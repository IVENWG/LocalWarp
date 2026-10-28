"""连接器内置的 DNS 劫持定位通道（软件模拟定位，零手机侧安装）。

真机实测结论（2026-10-25，iPhone 14 Pro Max / iOS 26.6.1，详见
docs/research/enhanced-location-acceptance-2026-10-25.md 第四轮）：

- iOS 的系统定位进程 locationd 不查阅 Wi-Fi 手动/PAC 代理设置，但使用系统
  解析器；把手机 Wi-Fi 的 DNS 指向连接器后，两个 Apple 定位域名的查询会被
  本模块应答为连接器自身，定位流量因此在 443 端口被现有 wloc CA 终结。
- 首次生效存在 2–6 分钟“一致应答学习窗口”，之后 locationd 缓存命中即即时
  生效；开关一次定位服务可加速。不需要飞行模式。
- 苹果真实服务器对转发的手机请求一律返回 400（存在请求指纹校验），因此本
  通道只回合成应答，不做上游转发。

TLS 采用 MemoryBIO 手动握手 + ClientHello SNI 解析：不依赖各解释器
sni_callback 行为差异（部分构建不支持回调返回上下文），Mac/Windows 表现一致。

安全边界：只劫持 HIJACK_HOSTS 中的两个精确域名，其余查询原样转发上游，
不解析、不记录；443 仅接受 SNI 为劫持域名的 TLS，仅响应 POST /clls/wloc。
端口 53/443 在 Unix 上为特权端口，产品化由安装期的特权助手持有；
测试可用构造参数改用高位端口。
"""
import asyncio
import ipaddress
import math
import os
import socket
import ssl
import struct
from pathlib import Path

try:
    from wloc_proxy import (HOSTS, CertificateStore, build_response,  # noqa: F401
                            field as pb_field, fields as pb_fields)
except ImportError:
    from src.backend.wloc_proxy import (HOSTS, CertificateStore,
                                        build_response,
                                        field as pb_field,
                                        fields as pb_fields)

HIJACK_HOSTS = HOSTS
STEPS = ['download_ca', 'trust_ca', 'configure_dns', 'verify_maps']
SUPPRESS_STEPS = ['configure_dns', 'toggle_location', 'verify_maps']
MAX_BODY = 256 * 1024
FALLBACK_UPSTREAMS = ('223.5.5.5', '119.29.29.29')


def constraint_text(mode='rewrite'):
    if mode == 'suppress':
        return ('Start the USB accessory session, set Wi-Fi DNS to this computer, '
                'enable Airplane Mode (keep Wi-Fi on), then toggle Location Services once. '
                'Verified on iOS 27.2: far-distance fixes are adopted reliably. '
                'Restore DNS to Automatic and disable Airplane Mode when finished.')
    return ('Set the phone Wi-Fi DNS to this computer, trust the LocalWarp CA, '
            'then toggle Location Services once. Verified on iOS 26.6.1: the '
            'blue dot adopts the target after a 2-6 minute learning window of '
            'consistent answers and stays (cached, zero further queries); '
            'no airplane mode needed. Restore DNS to Automatic to revert. '
            'Ports 53/443 need elevation on macOS; not on Windows.')


def system_nameservers():
    """读取系统解析器（去除自指/回环），失败时用公共上游。"""
    servers = []
    try:
        for line in Path('/etc/resolv.conf').read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'nameserver':
                address = parts[1]
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if parsed.version == 4 and not parsed.is_loopback:
                    servers.append(address)
    except OSError:
        pass
    unique = list(dict.fromkeys(servers))
    return tuple(unique) or FALLBACK_UPSTREAMS


# ---------------------------------------------------------------------------
# DNS：报文构造与解析（纯函数，便于测试）
# ---------------------------------------------------------------------------

def parse_question(data):
    """解析单问题查询；返回 (name, qtype, qclass, question_end) 或 None。"""
    if len(data) < 12:
        return None
    if struct.unpack('>H', data[4:6])[0] != 1:
        return None
    pos, labels = 12, []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 or pos + 1 + length > len(data):
            return None
        labels.append(data[pos + 1:pos + 1 + length])
        pos += 1 + length
    if pos + 4 > len(data):
        return None
    qtype, qclass = struct.unpack('>HH', data[pos:pos + 4])
    name = '.'.join(part.decode('ascii', 'ignore').lower() for part in labels)
    return name, qtype, qclass, pos + 4


def dns_answer(query, question_end, rcode=0, answers=()):
    question = query[12:question_end]
    header = query[:2] + struct.pack('>HHHHH', 0x8580 | rcode, 1,
                                     len(answers), 0, 0)
    return header + question + b''.join(answers)


def hijack_answer(query, question_end, qtype, ip):
    """劫持应答：A 记录指向连接器；AAAA/HTTPS(65) 等返回 NODATA。"""
    if qtype == 1:
        record = (b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 30, 4)
                  + socket.inet_aton(ip))
        return dns_answer(query, question_end, answers=[record])
    return dns_answer(query, question_end)


def servfail(query, question_end):
    return dns_answer(query, question_end, rcode=2)


async def forward_udp(query, upstreams, timeout=2.0):
    """原样转发查询；upstream 可为 'ip' 或 ('ip', port)（测试用高位端口）。"""
    loop = asyncio.get_running_loop()
    for upstream in upstreams:
        remote = upstream if isinstance(upstream, tuple) else (upstream, 53)
        done = loop.create_future()

        class Relay(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not done.done():
                    done.set_result(data)

            def error_received(self, error):
                if not done.done():
                    done.set_exception(error)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: Relay(), remote_addr=remote)
        except OSError:
            continue
        try:
            transport.sendto(query)
            return await asyncio.wait_for(done, timeout)
        except (asyncio.TimeoutError, OSError):
            continue
        finally:
            transport.close()
    return None


def build_query(name, qtype=1, qclass=1, query_id=0x1234):
    """构造单问题查询报文（测试与自检用）。"""
    question = b''.join(
        bytes([len(label)]) + label.encode('ascii')
        for label in name.split('.')) + b'\x00'
    question += struct.pack('>HH', qtype, qclass)
    header = struct.pack('>HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
    return header + question


# ---------------------------------------------------------------------------
# 伪造应答：严格 ARPC -> 宽松 ARPC -> 空结果（模拟“服务端不认识这些基站”）
# ---------------------------------------------------------------------------

def coordinate(value):
    scaled = value * 100_000_000
    return math.floor(scaled + .5) if scaled >= 0 else math.ceil(scaled - .5)


def forged_location(latitude, longitude):
    # 精度字段与真机采信通过的参数一致：39m 水平精度 / 1000m 垂直精度
    return b''.join(pb_field(n, v) for n, v in (
        (1, coordinate(latitude)), (2, coordinate(longitude)), (3, 39),
        (4, 3), (5, 100), (6, 1000), (11, 63), (12, 467)))


EMPTY_RESPONSE = b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'


def _walk_strings(body):
    offset = 2
    for _ in range(3):
        if offset + 2 > len(body):
            raise ValueError('truncated envelope')
        length = int.from_bytes(body[offset:offset + 2], 'big')
        offset += 2 + length
    return offset


def tolerant_response(body, latitude, longitude):
    """返回 (response, mode)；mode ∈ strict / tolerant / empty。"""
    try:
        return build_response(body, latitude=latitude, longitude=longitude), 'strict'
    except ValueError:
        pass
    try:
        offset = _walk_strings(body)
        if offset + 8 > len(body):
            raise ValueError('truncated header')
        plen = int.from_bytes(body[offset + 4:offset + 8], 'big')
        proto = body[offset + 8:offset + 8 + plen] if plen else body[offset + 8:]
        location = forged_location(latitude, longitude)
        results = []
        for number, wire, value in pb_fields(proto):
            if number == 2 and wire == 2:
                bssid = next((v for n, w, v in pb_fields(value)
                              if n == 1 and w == 2), None)
                if bssid:
                    results.append(pb_field(2, pb_field(1, bssid)
                                            + pb_field(2, location)))
        if not results:
            raise ValueError('no usable entries')
        protobuf = b''.join(results)
        return (b'\x00\x01\x00\x00\x00\x01\x00\x00'
                + struct.pack('>H', len(protobuf)) + protobuf), 'tolerant'
    except (ValueError, IndexError):
        return EMPTY_RESPONSE, 'empty'


# ---------------------------------------------------------------------------
# TLS：ClientHello SNI 解析 + MemoryBIO 手动握手（跨解释器一致）
# ---------------------------------------------------------------------------

async def read_client_hello(reader, timeout=10):
    """读取并跨记录重组 ClientHello。

    返回 (handshake_msg, wire)。handshake_msg 为去掉 TLS 记录头的完整
    ClientHello 握手消息（供 parse_sni）；wire 为已消费的原始线缆字节含
    记录头与其后已读到的字节（供 MemoryBIO 原样喂入，不能去头）。
    """
    raw = bytearray()
    wire = bytearray()
    handshake = bytearray()

    async def fill():
        chunk = await asyncio.wait_for(reader.read(4096), timeout)
        if not chunk:
            raise ConnectionResetError('client closed before ClientHello')
        raw.extend(chunk)
        wire.extend(chunk)

    while True:
        while len(raw) < 5:
            await fill()
        if raw[0] != 0x16:  # 非 handshake 记录
            raise ValueError('not a TLS handshake record')
        record_length = int.from_bytes(raw[3:5], 'big')
        while len(raw) < 5 + record_length:
            await fill()
        handshake.extend(raw[5:5 + record_length])
        del raw[:5 + record_length]
        if len(handshake) >= 4:
            total = 4 + int.from_bytes(handshake[1:4], 'big')
            if len(handshake) >= total:
                return (bytes(handshake[:total]), bytes(wire))


def parse_sni(client_hello):
    """从 ClientHello 握手消息（不含 TLS 记录头，含 4 字节握手头）解析
    server_name；无则 None。"""
    body = client_hello
    try:
        if body[0] != 0x01:  # 不是 ClientHello
            return None
        pos = 4 + 2 + 32                      # 头 + client_version + random
        pos += 1 + body[pos]                  # session_id
        pos += 2 + int.from_bytes(body[pos:pos + 2], 'big')   # cipher suites
        pos += 1 + body[pos]                  # compression methods
        extensions_end = min(pos + 2
                             + int.from_bytes(body[pos:pos + 2], 'big'),
                             len(body))
        pos += 2
        while pos + 4 <= extensions_end:
            etype = int.from_bytes(body[pos:pos + 2], 'big')
            elen = int.from_bytes(body[pos + 2:pos + 4], 'big')
            data = body[pos + 4:pos + 4 + elen]
            pos += 4 + elen
            if etype != 0:  # server_name
                continue
            list_end = min(2 + int.from_bytes(data[:2], 'big'), len(data))
            cursor = 2
            while cursor + 3 <= list_end:
                name_type = data[cursor]
                name_len = int.from_bytes(data[cursor + 1:cursor + 3], 'big')
                if name_type == 0:
                    return data[cursor + 3:cursor + 3 + name_len].decode(
                        'ascii', 'ignore').lower()
                cursor += 3 + name_len
        return None
    except (IndexError, ValueError):
        return None


class ManualTls:
    """基于 MemoryBIO 的服务端 TLS：明文侧提供行读取/定长读取/写。

    wire 为已读到的原始线缆字节（含 TLS 记录头），需原样进入 inbio。
    """

    def __init__(self, reader, writer, context, wire):
        self.reader, self.writer = reader, writer
        self.inbio = ssl.MemoryBIO()
        self.outbio = ssl.MemoryBIO()
        self.inbio.write(wire)
        self.sslobj = context.wrap_bio(self.inbio, self.outbio,
                                       server_side=True)
        self.plain = bytearray()

    async def _flush(self):
        if self.outbio.pending:
            self.writer.write(self.outbio.read())
            await self.writer.drain()

    async def handshake(self, timeout=10):
        while True:
            try:
                self.sslobj.do_handshake()
                await self._flush()
                return
            except ssl.SSLWantReadError:
                await self._flush()
                chunk = await asyncio.wait_for(self.reader.read(16384), timeout)
                if not chunk:
                    raise ConnectionResetError('client closed mid-handshake')
                self.inbio.write(chunk)

    async def _read_plaintext(self, timeout):
        while True:
            chunk = self.sslobj.read(16384)
            if chunk:
                self.plain.extend(chunk)
                return
            await self._flush()
            data = await asyncio.wait_for(self.reader.read(16384), timeout)
            if not data:
                raise ConnectionResetError('client closed')
            self.inbio.write(data)

    async def readline(self, timeout=15):
        while b'\n' not in self.plain:
            await self._read_plaintext(timeout)
        index = self.plain.index(b'\n')
        line = bytes(self.plain[:index + 1])
        del self.plain[:index + 1]
        return line

    async def readexactly(self, count, timeout=15):
        while len(self.plain) < count:
            await self._read_plaintext(timeout)
        data = bytes(self.plain[:count])
        del self.plain[:count]
        return data

    async def write(self, data, timeout=15):
        self.sslobj.write(data)
        await self._flush()


# ---------------------------------------------------------------------------
# 管理器
# ---------------------------------------------------------------------------

class DnsLocationError(Exception):
    pass


class DnsLocationManager:
    def __init__(self, store_root=None, dns_port=53, tls_port=443,
                 upstreams=None):
        self.store = CertificateStore(store_root)
        self.dns_port = dns_port
        self.tls_port = tls_port
        self.upstreams = tuple(upstreams) if upstreams else FALLBACK_UPSTREAMS
        self.lock = asyncio.Lock()
        self.server = None
        self.target = None
        self.lan_ip = None
        self.contexts = {}
        self.clients = set()
        self.mode = 'rewrite'
        self.sinkhole = None
        self.diagnostics = self._fresh_diagnostics()

    @staticmethod
    def _fresh_diagnostics():
        return dict(dns_queries=0, dns_hijacked=0, dns_suppressed=0, dns_forwarded=0,
                    dns_failed=0, tls_conn=0, sni_refused=0,
                    wloc_requests=0, strict=0, tolerant=0, empty=0,
                    errors=0, last_error_code=None)

    @property
    def running(self):
        return getattr(self, 'dns_tcp', None) is not None

    @staticmethod
    def detect_lan_ip():
        """返回一个非 link-local 的本机 IPv4（探测 UDP 路由，不实际发包）。"""
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(('223.5.5.5', 53))
            return probe.getsockname()[0]
        except OSError:
            return None
        finally:
            probe.close()

    def status(self):
        cert = getattr(self.store, 'cert', None) if self.mode == 'rewrite' else None
        return dict(running=self.running, mode=self.mode, sinkhole_ip=self.sinkhole,
                    tls_listening=self.server is not None, requires_ca=self.mode == 'rewrite',
                    ios27_hint='iOS >=27: use accessory + DNS suppress (device-verified); rewrite mode is blocked by cert pinning.',
                    listen_dns_port=self.dns_port,
                    listen_tls_port=self.tls_port, lan_ip=self.lan_ip,
                    hijack_hosts=sorted(HIJACK_HOSTS),
                    upstreams=list(self.upstreams),
                    target=self.target, phone_location_verified=False,
                    phone_steps=SUPPRESS_STEPS if self.mode == 'suppress' else STEPS,
                    constraint=constraint_text(self.mode),
                    ca_fingerprint_sha256=(cert.fingerprint(
                        __import__('cryptography.hazmat.primitives.hashes',
                                   fromlist=['SHA256']).SHA256()).hex().upper()
                        if cert else None),
                    diagnostics=dict(self.diagnostics))

    async def prepare(self):
        async with self.lock:
            await asyncio.to_thread(self.store.ensure)
            return self.status()

    async def start(self, latitude, longitude, mode='rewrite'):
        if mode not in ('rewrite', 'suppress'):
            raise ValueError('mode must be rewrite or suppress')
        if not (math.isfinite(latitude) and math.isfinite(longitude)
                and -90 <= latitude <= 90 and -180 <= longitude <= 180):
            raise ValueError('invalid coordinates')
        sinkhole = str(ipaddress.IPv4Address(os.getenv('LOCALWARP_DNS_SINKHOLE', '0.0.0.0'))) if mode == 'suppress' else None
        async with self.lock:
            if self.running:
                raise DnsLocationError('dns location session already running')
            lan_ip = self.detect_lan_ip()
            if not lan_ip:
                raise DnsLocationError('no LAN IPv4 address found')
            self.lan_ip = lan_ip
            self.mode = mode
            self.sinkhole = sinkhole
            self.target = dict(latitude=latitude, longitude=longitude)
            self.diagnostics = self._fresh_diagnostics()
            self.contexts = {}
            if mode == 'rewrite':
                await asyncio.to_thread(self.store.ensure)
                self.contexts = {host: await asyncio.to_thread(
                    self.store.tls_context, host) for host in HIJACK_HOSTS}
            try:
                loop = asyncio.get_running_loop()
                self.udp_transport, _ = await loop.create_datagram_endpoint(
                    self._udp_factory, local_addr=('0.0.0.0', self.dns_port))
                self.dns_tcp = await asyncio.start_server(
                    self._accept_tcp_dns, '0.0.0.0', self.dns_port)
                if mode == 'rewrite':
                    self.server = await asyncio.start_server(
                        self._accept_tls, '0.0.0.0', self.tls_port)
            except OSError as error:
                await self._close_listeners()
                raise DnsLocationError(
                    f'cannot bind required ports for {mode} (DNS {self.dns_port}, TLS {self.tls_port}): '
                    f'{error}') from error
            return self.status()

    async def stop(self):
        async with self.lock:
            await self._close_listeners()
            return self.status()

    async def shutdown(self):
        await self.stop()

    async def _close_listeners(self):
        servers = []
        for name in ('dns_tcp', 'server'):
            entry = getattr(self, name, None)
            if entry:
                entry.close()
                servers.append(entry)
                setattr(self, name, None)
        transport = getattr(self, 'udp_transport', None)
        if transport:
            transport.close()
            self.udp_transport = None
        # Close accepted streams before waiting for the servers to drain.
        for writer in list(self.clients):
            writer.close()
        for entry in servers:
            await entry.wait_closed()

    # -- DNS ---------------------------------------------------------------
    def _udp_factory(self):
        manager = self

        class UdpDns(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                asyncio.get_running_loop().create_task(
                    manager._answer_dns(data, lambda reply: (
                        self.transport.sendto(reply, addr))))

        return UdpDns()

    def _accept_stream(self, handler, reader, writer):
        # Register synchronously: stop may run before an async handler is scheduled.
        if not self.running:
            writer.close()
            return
        self.clients.add(writer)
        asyncio.get_running_loop().create_task(handler(reader, writer))

    def _accept_tcp_dns(self, reader, writer):
        self._accept_stream(self._handle_tcp_dns, reader, writer)

    def _accept_tls(self, reader, writer):
        self._accept_stream(self._handle_tls, reader, writer)

    async def _handle_tcp_dns(self, reader, writer):
        self.clients.add(writer)
        try:
            while True:
                prefix = await asyncio.wait_for(reader.readexactly(2), 20)
                (length,) = struct.unpack('>H', prefix)
                query = await asyncio.wait_for(reader.readexactly(length), 10)
                await self._answer_dns(
                    query,
                    lambda reply: writer.write(
                        struct.pack('>H', len(reply)) + reply))
                await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError,
                ValueError):
            pass
        finally:
            self.clients.discard(writer)
            writer.close()

    async def _answer_dns(self, query, send):
        try:
            parsed = parse_question(query)
            if not parsed:
                return
            name, qtype, qclass, qend = parsed
            self.diagnostics['dns_queries'] += 1
            if qclass == 1 and name in HIJACK_HOSTS:
                self.diagnostics['dns_hijacked'] += 1
                if self.mode == 'suppress':
                    self.diagnostics['dns_suppressed'] += 1
                answer_ip = self.sinkhole if self.mode == 'suppress' else self.lan_ip
                send(hijack_answer(query, qend, qtype, answer_ip))
                return
            upstream = await forward_udp(query, self.upstreams)
            if upstream is not None:
                self.diagnostics['dns_forwarded'] += 1
                send(upstream)
            else:
                self.diagnostics['dns_failed'] += 1
                send(servfail(query, qend))
        except (ValueError, OSError) as error:
            self.diagnostics['errors'] += 1
            self.diagnostics['last_error_code'] = type(error).__name__

    # -- TLS ----------------------------------------------------------------
    async def _handle_tls(self, reader, writer):
        self.clients.add(writer)
        try:
            handshake, wire = await read_client_hello(reader)
            sni = parse_sni(handshake)
            context = self.contexts.get(sni) if sni else None
            if context is None:
                self.diagnostics['sni_refused'] += 1
                writer.close()
                return
            tls = ManualTls(reader, writer, context, wire)
            await tls.handshake()
            self.diagnostics['tls_conn'] += 1
            request = await tls.readline(20)
            parts = request.decode('latin1').split()
            headers = {}
            while True:
                line = await tls.readline(10)
                if line in (b'\r\n', b'\n', b''):
                    break
                key, _, value = line.decode('latin1').partition(':')
                headers[key.strip().lower()] = value.strip()
            method = parts[0] if parts else ''
            path = parts[1] if len(parts) > 1 else ''
            length = int(headers.get('content-length', '0') or 0)
            if (method != 'POST' or path.split('?')[0] != '/clls/wloc'
                    or headers.get('host', '').split(':')[0] != sni
                    or not 0 < length <= MAX_BODY):
                await tls.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0'
                                b'\r\nConnection: close\r\n\r\n')
                return
            body = await tls.readexactly(length, 15)
            self.diagnostics['wloc_requests'] += 1
            response, mode = tolerant_response(
                body, self.target['latitude'], self.target['longitude'])
            self.diagnostics[mode] += 1
            await tls.write(b'HTTP/1.1 200 OK\r\nContent-Type: '
                            b'application/octet-stream\r\nContent-Length: '
                            + str(len(response)).encode()
                            + b'\r\nConnection: close\r\n\r\n' + response)
        except (ValueError, OSError, asyncio.TimeoutError,
                asyncio.IncompleteReadError, ConnectionResetError,
                ssl.SSLError) as error:
            self.diagnostics['errors'] += 1
            self.diagnostics['last_error_code'] = (
                f'tls:{type(error).__name__}')
        finally:
            self.clients.discard(writer)
            try:
                writer.close()
            except Exception:
                pass
