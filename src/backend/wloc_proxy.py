"""Restricted Apple Wi-Fi location responder. No upstream connections are made.

ARPC/protobuf port of OpenHRTT/wloc AppWLocARPC/AppWLocMutator/BSSIDApp.pb.swift.
Reference revision: 6c597b1926a1288ba72d2955e513910c85d8c495.
MIT, Copyright (c) 2026 WLoc8.com contributors. Full license: licenses/wloc-MIT.txt.
"""
import asyncio
import datetime as dt
import ipaddress
import math
import os
from pathlib import Path
import socket
import ssl
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOSTS = frozenset(('gs-loc.apple.com', 'gs-loc-cn.apple.com'))
STEPS = ['download_ca', 'trust_ca', 'configure_proxy', 'verify_maps']
CA_PATH = '/api/location/wloc/ca.pem'
PAC_PATH = '/api/location/wloc/proxy.pac'
SHADOWROCKET_PATH = '/api/location/wloc/shadowrocket.conf'
MAX_BODY = 256 * 1024


def lan_ips():
    """IPv4 interfaces, plus default-route address (UDP connect sends no data)."""
    addresses = set()
    try:
        addresses.update(item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    except OSError:
        pass
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(('192.0.2.1', 9))
            addresses.add(sock.getsockname()[0])
        except OSError:
            pass
    # ifaddr is a transitive zeroconf dependency; enumerate all real interfaces.
    try:
        from ifaddr import get_adapters
        addresses.update(ip.ip for adapter in get_adapters() for ip in adapter.ips if isinstance(ip.ip, str))
    except (ImportError, OSError):
        pass
    return sorted(a for a in addresses if ipaddress.ip_address(a).version == 4
                  and ipaddress.ip_address(a).is_private
                  and not ipaddress.ip_address(a).is_loopback
                  and not ipaddress.ip_address(a).is_unspecified)


def validate_target(latitude, longitude):
    if not (math.isfinite(latitude) and math.isfinite(longitude)
            and -90 <= latitude <= 90 and -180 <= longitude <= 180):
        raise ValueError('invalid coordinates')


def connect_host(authority):
    # No suffix matching, IP literals, credentials, alternate ports, or DNS lookup.
    parts = authority.lower().split(':')
    if len(parts) != 2 or parts[0] not in HOSTS or parts[1] != '443':
        raise ValueError('forbidden destination')
    return parts[0]


def build_pac(host, port):
    """Only the two exact Apple HTTPS hosts use the restricted proxy.

    All ordinary requests stay DIRECT on the phone. The destination is a local
    socket address, never the untrusted HTTP Host header. No general MITM or
    upstream forwarding is enabled by this configuration.
    """
    address = ipaddress.ip_address(host)
    if address.version != 4 or not address.is_private or address.is_unspecified:
        raise ValueError('PAC requires a local IPv4 address')
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('invalid PAC port')
    return (f'function FindProxyForURL(url, host) {{\n'
            f'  host = host.toLowerCase();\n'
            f'  if (url.substring(0, 6).toLowerCase() === "https:" &&\n'
            f'      (host === "gs-loc.apple.com" || host === "gs-loc-cn.apple.com")) {{\n'
            f'    return "PROXY {address}:{port}";\n'
            f'  }}\n'
            f'  return "DIRECT";\n'
            f'}}\n').encode('ascii')


def build_shadowrocket_config(host, port):
    """Validation profile for proxy-capable VPN apps (Shadowrocket et al.).

    The HTTP node is embedded so the phone needs no manual server entry: import
    the file, make it the active config, select Config routing. Only the two
    exact Apple location domains reach the connector; everything else stays
    direct. Surge-2 style syntax; no MITM, certificates or keys inside. Same
    address validation as PAC.
    """
    build_pac(host, port)
    return (f'# LocalWarp WLoc validation profile. Keep your other configs;\n'
            f'# switch back to them after testing. No certificates inside.\n'
            f'# Embedded node: http://{host}:{port} (no authentication).\n'
            f'[General]\n'
            f'dns-server = system\n'
            f'\n[Proxy]\n'
            f'LocalWarp = http, {host}, {port}\n'
            f'\n[Rule]\n'
            f'DOMAIN,gs-loc.apple.com,LocalWarp\n'
            f'DOMAIN,gs-loc-cn.apple.com,LocalWarp\n'
            f'FINAL,DIRECT\n').encode('ascii')


def varint(value):
    value &= (1 << 64) - 1
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def read_varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError('truncated protobuf')
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ValueError('oversized varint')
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError('invalid varint')


def fields(data):
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not number:
            raise ValueError('invalid field')
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, offset = read_varint(data, offset)
            else:
                length = 8 if wire == 1 else 4
            if offset + length > len(data):
                raise ValueError('truncated field')
            value = data[offset:offset + length]
            offset += length
        else:
            raise ValueError('unsupported wire type')
        yield number, wire, value


def field(number, value):
    if isinstance(value, bytes):
        return varint(number << 3 | 2) + varint(len(value)) + value
    return varint(number << 3) + varint(value)


def build_response(request, latitude, longitude):
    """ARPC: BE u16 version, three u16-length strings, u32 function, u32 body.

    WLoc location uses int64 (NOT zigzag), degrees * 1e8. Wi-Fi field 2,
    BSSID string field 1, location field 2. Response has 8-byte prefix + BE u16.
    """
    validate_target(latitude, longitude)
    offset = 2
    for _ in range(3):
        if offset + 2 > len(request):
            raise ValueError('truncated ARPC')
        length = int.from_bytes(request[offset:offset + 2], 'big')
        offset += 2 + length
    if offset + 8 > len(request):
        raise ValueError('truncated ARPC')
    length = int.from_bytes(request[offset + 4:offset + 8], 'big')
    offset += 8
    if offset + length != len(request):
        raise ValueError('invalid ARPC length')
    def coordinate(value):
        scaled = value * 100_000_000
        return math.floor(scaled + .5) if scaled >= 0 else math.ceil(scaled - .5)
    location = b''.join(field(n, v) for n, v in (
        (1, coordinate(latitude)), (2, coordinate(longitude)), (3, 4),
        (4, 3), (5, 480), (6, 10), (11, 63), (12, 467)))
    results = []
    for number, wire, value in fields(request[offset:]):
        if number == 2 and wire == 2:
            bssid = next((v for n, w, v in fields(value) if n == 1 and w == 2), None)
            if bssid is None:
                raise ValueError('missing BSSID')
            results.append(field(2, field(1, bssid) + field(2, location)))
    protobuf = b''.join(results)
    if not results or len(protobuf) > 65535:
        raise ValueError('invalid Wi-Fi results')
    return b'\x00\x01\x00\x00\x00\x01\x00\x00' + struct.pack('>H', len(protobuf)) + protobuf


class CertificateStore:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else Path.home() / '.localwarp' / 'wloc'
        self.cert = None
        self.key = None

    def write(self, name, data):
        path = self.directory / name
        # O_EXCL prevents following pre-existing symlinks and accidental key replacement.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
        return path

    def ensure(self):
        if self.cert is not None:
            return
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        cert_path, key_path = self.directory / 'ca.pem', self.directory / 'ca.key'
        if cert_path.exists() or key_path.exists():
            if cert_path.is_symlink() or key_path.is_symlink():
                raise ValueError('CA files must not be symlinks')
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            key = serialization.load_pem_private_key(key_path.read_bytes(), None)
            if cert.public_key().public_numbers() != key.public_key().public_numbers():
                raise ValueError('CA key mismatch')
            for path in (cert_path, key_path):
                os.chmod(path, 0o600)
            self.cert, self.key = cert, key
            return
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'LocalWarp WLoc Root CA')])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                .sign(key, hashes.SHA256()))
        self.write('ca.key', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.write('ca.pem', cert.public_bytes(serialization.Encoding.PEM))
        self.cert, self.key = cert, key

    def pem(self):
        self.ensure()
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def tls_context(self, host):
        if host not in HOSTS:
            raise ValueError('forbidden certificate hostname')
        self.ensure()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                .issuer_name(self.cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .sign(self.key, hashes.SHA256()))
        # Ephemeral leaf files are only needed by SSLContext.load_cert_chain.
        token = str(x509.random_serial_number())
        cert_path = self.write(token + '.pem', cert.public_bytes(serialization.Encoding.PEM) + self.pem())
        key_path = self.write(token + '.key', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert_path, key_path)
            def check_sni(sock, name, ctx):
                if name is not None and name != host:
                    return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            context.set_servername_callback(check_sni)
            return context
        finally:
            cert_path.unlink()
            key_path.unlink()


async def read_header(reader):
    raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
    lines = raw.decode('ascii').split('\r\n')
    method, path, version = lines[0].split(' ')
    if version != 'HTTP/1.1':
        raise ValueError('unsupported HTTP version')
    headers = {}
    for line in lines[1:-2]:
        key, value = line.split(':', 1)
        key = key.lower()
        if key in headers:
            raise ValueError('duplicate header')
        headers[key] = value.strip()
    return method, path, headers


async def reply(writer, code, body=b'', content_type='text/plain'):
    writer.write((f'HTTP/1.1 {code}\r\nContent-Length: {len(body)}\r\n'
                  f'Content-Type: {content_type}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n').encode() + body)
    await writer.drain()


class WlocProxy:
    def __init__(self, directory=None, port=None, ca_port=28888, auth_guard=None):
        self.store = CertificateStore(directory)
        self.port = int(port if port is not None else os.getenv('LOCALWARP_WLOC_PORT', '28889'))
        if not 0 <= self.port <= 65535:
            raise ValueError('invalid proxy port')
        self.ca_port = ca_port
        self.auth_guard = auth_guard
        self.server = None
        self.ca_servers = []
        self.target = None
        self.contexts = {}
        self.clients = set()
        self.lock = asyncio.Lock()
        self.download_errors = []
        self.diagnostics = self._new_diagnostics()

    @staticmethod
    def _new_diagnostics():
        return dict(connections=0, rejected_destinations=0, allowed_connects=0,
                    tls_completed=0, location_requests=0, responses_sent=0,
                    errors=0, last_error_code=None)

    def status(self):
        cert = self.store.cert
        return dict(running=self.server is not None, ca_generated=cert is not None,
                    ca_fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex().upper() if cert else None,
                    listen_port=self.port, target=self.target, phone_location_verified=False,
                    phone_steps=STEPS, lan_ips=lan_ips(), ca_download_port=self.ca_port,
                    ca_download_errors=self.download_errors, diagnostics=dict(self.diagnostics))

    async def prepare(self):
        async with self.lock:
            await asyncio.to_thread(self.store.ensure)
            if not self.ca_servers:
                self.download_errors = []
                for address in lan_ips():
                    try:
                        server = await asyncio.start_server(self.download, address, self.ca_port, limit=16384)
                        self.ca_servers.append(server)
                    except OSError as error:
                        self.download_errors.append(f'{address}: {error}')
        return self.status()

    async def download(self, reader, writer):
        try:
            method, path, _ = await read_header(reader)
            if method == 'GET' and path == CA_PATH:
                await reply(writer, '200 OK', self.store.pem(), 'application/x-x509-ca-cert')
            elif method == 'GET' and path == PAC_PATH:
                address = writer.get_extra_info('sockname')[0]
                await reply(writer, '200 OK', build_pac(address, self.port), 'application/x-ns-proxy-autoconfig')
            elif method == 'GET' and path == SHADOWROCKET_PATH:
                address = writer.get_extra_info('sockname')[0]
                await reply(writer, '200 OK', build_shadowrocket_config(address, self.port), 'text/plain; charset=utf-8')
            else:
                await reply(writer, '403 Forbidden')
        except (ValueError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self, latitude, longitude):
        validate_target(latitude, longitude)
        await self.prepare()
        if self.server:
            raise ValueError('wloc session already running')
        self.contexts = {host: await asyncio.to_thread(self.store.tls_context, host) for host in HOSTS}
        self.target = dict(latitude=latitude, longitude=longitude)
        self.diagnostics = self._new_diagnostics()
        self.server = await asyncio.start_server(self.handle, '0.0.0.0', self.port, limit=16384)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.status()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        for writer in list(self.clients):
            writer.close()
        self.target = None
        return self.status()

    async def shutdown(self):
        await self.stop()
        for server in self.ca_servers:
            server.close()
            await server.wait_closed()
        self.ca_servers = []

    async def handle(self, reader, writer):
        if len(self.clients) >= 32:
            writer.close()
            return
        self.clients.add(writer)
        self.diagnostics['connections'] += 1
        stage = 'connect'
        try:
            method, authority, _ = await read_header(reader)
            try:
                if method != 'CONNECT':
                    raise ValueError('CONNECT required')
                host = connect_host(authority)
            except ValueError:
                self.diagnostics['rejected_destinations'] += 1
                await reply(writer, '403 Forbidden')
                return
            self.diagnostics['allowed_connects'] += 1
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            stage = 'tls'
            await writer.start_tls(self.contexts[host], ssl_handshake_timeout=10)
            self.diagnostics['tls_completed'] += 1
            stage = 'request'
            method, path, headers = await read_header(reader)
            if (method != 'POST' or path != '/clls/wloc'
                    or headers.get('host', '').lower() not in (host, host + ':443')
                    or 'transfer-encoding' in headers
                    or headers.get('content-encoding', 'identity') != 'identity'):
                await reply(writer, '403 Forbidden')
                return
            self.diagnostics['location_requests'] += 1
            length = int(headers.get('content-length', '0'))
            if not 0 < length <= MAX_BODY:
                raise ValueError('invalid content length')
            body = await asyncio.wait_for(reader.readexactly(length), 10)
            if self.auth_guard is not None and not self.auth_guard():
                self.target = None
                await reply(writer, '403 Forbidden')
                return
            if not self.server or not self.target:
                return
            stage = 'response'
            body = build_response(body, **self.target)
            await reply(writer, '200 OK', body, 'application/x-www-form-urlencoded')
            self.diagnostics['responses_sent'] += 1
        except (ValueError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
            # Fixed stage/type codes only: never persist hostnames, BSSIDs or payloads.
            self.diagnostics['errors'] += 1
            self.diagnostics['last_error_code'] = f'{stage}:{type(error).__name__}'
            # Invalid traffic never falls through to a general proxy.
        finally:
            self.clients.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass
