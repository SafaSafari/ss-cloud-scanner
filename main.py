import os
import sys
import ssl
import time
import json
import hmac
import base64
import socket
import struct
import random
import asyncio
import logging
import requests
import binascii
import ipaddress
import stream_pb2
from uuid import UUID
from urllib import parse
from hashlib import md5, sha256
from Crypto.Cipher import AES as AS
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from grpclib.client import Channel, ServiceMethod, _SendType, _RecvType, Cardinality, Sequence, Optional, _MetadataLike, List, H2Protocol

THREADS = 4
TIMEOUT = 5
NUM_IPS = 2
SIZE = 1024 * 128


def ss_input(prompt, default='', t=int):
    result = input('{}{}: '.format(
        prompt, (" [" + str(default) + "] (Enter for default)") if str(default) != '' else ''))
    if result == '':
        return default
    else:
        return t(result)


async def create_data(size=SIZE):
    created_size = 0
    while size > created_size:
        created_size += 512
        yield b"S" * 512


async def get_working_worker(speed_urls):  # function name 😂😂😂
    async with ClientSession() as session:
        for i in speed_urls:
            i = i.strip()
            async with session.get("https://" + i) as r:
                if r.status != 429:
                    return i

class StreamStreamMethod(ServiceMethod[_SendType, _RecvType]):
    """
    Represents STREAM-STREAM gRPC method type.

    .. automethod:: __call__
    .. automethod:: open
    """
    _cardinality = Cardinality.STREAM_STREAM

    async def __call__(
        self,
        messages: Sequence[_SendType],
        *,
        timeout: Optional[float] = None,
        metadata: Optional[_MetadataLike] = None,
    ) -> List[_RecvType]:
        """Coroutine to perform defined call.

        :param messages: sequence of messages
        :param float timeout: request timeout (seconds)
        :param metadata: custom request metadata, dict or list of pairs
        :return: sequence of messages
        """
        async with self.open(timeout=timeout, metadata=metadata) as stream:
            async for message in messages:
                await stream.send_message(message)
            async for message in stream:
                yield message

class SSChannel(Channel):

    def __init__(self, host, port, server_hostname, **kwargs):
        self.server_hostname = server_hostname
        super().__init__(host, port, **kwargs)

    async def _create_connection(self) -> H2Protocol:
        if self._path is not None:
            _, protocol = await self._loop.create_unix_connection(
                self._protocol_factory, self._path, ssl=self._ssl, server_hostname=self.server_hostname
            )
        else:
            _, protocol = await self._loop.create_connection(
                self._protocol_factory, self._host, self._port,
                ssl=self._ssl, server_hostname=self.server_hostname
            )
        return protocol

class VlessSS:

    def __init__(self, uuid: str):
        self.uuid = UUID(uuid)

    async def send_packets(self, addr, port, data):
        yield await self.send_headers(addr, port)
        async for d in data:
            yield d

    async def send_packets_grpc(self, addr, port, data):
        yield stream_pb2.Hunk(data=await self.send_headers(addr, port))
        async for d in data:
            yield stream_pb2.Hunk(data=d)

    async def read_packets(self, recv):
        yield (await self.get_headers(await recv()))[2]
        while d := await recv():
            yield d
    
    async def read_packets_grpc(self, recv):
        yield (await self.get_headers(await recv.asend(None)))[2]
        async for p in recv:
            yield p

    async def send_headers(self, addr, port) -> bytes:
        addr_type = 2
        addr_bytes = addr.encode()
        alen = len(addr_bytes)
        info_p = b''
        info_p_len = len(info_p)
        req = struct.pack(
            f'!B16sB{info_p_len}sBHBB{alen}s',
            0,  # version
            self.uuid.bytes,  # uuid
            info_p_len,  # protobuf length
            info_p,  # protobuf
            1,  # command (tcp)
            port,  # port
            addr_type,  # address type (domain)
            alen,
            addr_bytes
        )
        return req

    async def get_headers(self, header):
        version, info_p_len, data = struct.unpack(
            f'!BB{len(header) - 2}s', header)
        info_p, data = struct.unpack(
            f'!{info_p_len}s{len(header) - 2 - info_p_len}s', data)

        async def read():
            return data
        self.read = read
        return version, info_p, data

    def parse_link(link: str):
        if not link.startswith('vless://'):
            return None
        link_parse = parse.urlparse(link)
        params = {k: v[0] for k, v in parse.parse_qs(link_parse.query).items()}
        return link_parse.username, params['host'], link_parse.port, params['path'], ['s', params.get('sni', params['host'])] if params.get('security') and params['security'] == 'tls' else ['', params['host']], params['type']


class VmessSS:
    KDFSaltConstAuthIDEncryptionKey = b"AES Auth ID Encryption"
    KDFSaltConstAEADRespHeaderLenKey = b"AEAD Resp Header Len Key"
    KDFSaltConstAEADRespHeaderLenIV = b"AEAD Resp Header Len IV"
    KDFSaltConstAEADRespHeaderPayloadKey = b"AEAD Resp Header Key"
    KDFSaltConstAEADRespHeaderPayloadIV = b"AEAD Resp Header IV"
    KDFSaltConstVMessAEADKDF = b"VMess AEAD KDF"
    KDFSaltConstVMessHeaderPayloadAEADKey = b"VMess Header AEAD Key"
    KDFSaltConstVMessHeaderPayloadAEADIV = b"VMess Header AEAD Nonce"
    KDFSaltConstVMessHeaderPayloadLengthAEADKey = b"VMess Header AEAD Key_Length"
    KDFSaltConstVMessHeaderPayloadLengthAEADIV = b"VMess Header AEAD Nonce_Length"

    addr: str
    port: int
    key: bytes
    iv: bytes

    def fnv32a(self, buf: bytes) -> bytes:
        hval = 0x811c9dc5
        fnv_32_prime = 0x01000193
        for ch in buf:
            hval = ((hval ^ ch) * fnv_32_prime) & 0xffffffff
        return hval.to_bytes(4, 'big')

    def kdf(self, *args):
        if len(args) == 0:
            return lambda x = b'': hmac.new(self.KDFSaltConstVMessAEADKDF, x, 'sha256')
        else:
            return lambda x = b'': hmac.new(args[-1], x, self.kdf(*args[:-1]))

    def Key(self):
        return md5(self.uuid.bytes +
                   b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()

    def __init__(self, uuid: str):
        self.uuid = UUID(uuid)
        self.key = random.randbytes(16)
        self.iv = random.randbytes(16)

    async def send_packets(self, addr, port, data):
        yield await self.send_headers(addr, port)
        async for d in data:
            yield d

    async def send_packets_grpc(self, addr, port, data):
        yield stream_pb2.Hunk(data=await self.send_headers(addr, port))
        async for d in data:
            yield stream_pb2.Hunk(data=d)

    async def read_packets(self, recv):
        await self.get_headers(await recv())
        while d := await recv():
            yield d
    
    async def read_packets_grpc(self, recv):
        await self.get_headers((await recv.asend(None)).data)
        async for p in recv:
            yield p.data

    async def send_headers(self, addr, port) -> bytes:
        rv = random.getrandbits(4)
        plen = random.getrandbits(4)
        ts = int(time.time())
        auth_bytes = ts.to_bytes(8, 'big')
        auth_bytes += random.randbytes(4)
        auth_bytes += bytes.fromhex(hex(binascii.crc32(auth_bytes))
                                    [2:].rjust(8, '0'))
        auth = AS.new(self.kdf(self.KDFSaltConstAuthIDEncryptionKey)(
            self.Key()).digest()[:16], AS.MODE_ECB).encrypt(auth_bytes)
        nonce = random.randbytes(8)
        addr_bytes = addr.encode()
        alen = len(addr_bytes)
        req = struct.pack(
            f'!B16s16sBBBBBHBB{alen}s{plen}s',
            1,  # version
            self.iv,  # iv
            self.key,  # key
            rv,  # Response authentication
            0,  # option
            (plen << 4) + 5,  # Margin P
            0,  # reserved
            1,  # command
            port,  # port
            2,  # address type
            alen,  # address len
            addr_bytes,  # address
            b"\x00" * plen,  # random p
        )
        req += self.fnv32a(req)
        headerLen = struct.pack('>h', len(req))
        lengthkey = self.kdf(self.KDFSaltConstVMessHeaderPayloadLengthAEADKey, auth, nonce)(
            self.Key()).digest()[:16]
        lengthnonce = self.kdf(self.KDFSaltConstVMessHeaderPayloadLengthAEADIV, auth, nonce)(
            self.Key()).digest()[:12]
        headerLen = AESGCM(lengthkey).encrypt(lengthnonce, headerLen, auth)
        headerkey = self.kdf(self.KDFSaltConstVMessHeaderPayloadAEADKey, auth, nonce)(
            self.Key()).digest()[:16]
        headernonce = self.kdf(self.KDFSaltConstVMessHeaderPayloadAEADIV, auth, nonce)(
            self.Key()).digest()[:12]
        req = AESGCM(headerkey).encrypt(headernonce, req, auth)
        return auth + headerLen + nonce + req

    async def get_headers(self, header):
        key, iv = sha256(self.key).digest()[
            :16], sha256(self.iv).digest()[:16]
        headerlenkey = self.kdf(
            self.KDFSaltConstAEADRespHeaderLenKey)(key).digest()[:16]
        headerlennonce = self.kdf(
            self.KDFSaltConstAEADRespHeaderLenIV)(iv).digest()[:12]
        headerlen = struct.unpack(">h", AESGCM(
            headerlenkey).decrypt(headerlennonce, header[:18], None))
        headerkey = self.kdf(self.KDFSaltConstAEADRespHeaderPayloadKey)(
            key).digest()[:16]
        headernonce = self.kdf(
            self.KDFSaltConstAEADRespHeaderPayloadIV)(iv).digest()[:12]
        rv, opt, p = struct.unpack("BB2s", AESGCM(
            headerkey).decrypt(headernonce, header[18:], None))
        return rv

    def parse_link(link):
        if not link.startswith('vmess://'):
            return None
        link = link[len('vmess://'):]
        link = json.loads(base64.b64decode(link))
        return link['id'], link['host'], link['port'], link['path'], ['s', link.get('sni', link['host'])] if link['tls'] == 'tls' else ['', link['host']], link['net']


class fronting:
    def __init__(self, ip):
        self.ip = ip

    async def resolve(self, hostname: str, port: int = 0, family: int = socket.AF_INET):
        result = [
            {
                "hostname": hostname,
                "host": self.ip,
                "port": port,
                "family": family,
                "proto": 6,
                "flags": socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
            }
        ]
        return result


ssl_context = ssl.create_default_context()
ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2

if not os.path.exists('ips.txt'):
    print('Please download ips.txt file')
    exit()

COUNT = ss_input('Enter count of ip you need', 5)
TYPE = ['speed', 'vmess', 'vless', 'server'][ss_input(
    'Enter type (1.speed, 2.vmess, 3.vless, 4.personal server)', 4) - 1]

if TYPE in ['vmess', 'vless']:
    LINK = ss_input('Enter {} share link, {}://'.format(TYPE, TYPE), t=str)
    ID, HOST, PORT, PATH, SECURE, NETWORK = VmessSS.parse_link(
        LINK) if TYPE == 'vmess' else VlessSS.parse_link(LINK)
    if NETWORK not in ['ws', 'grpc']:
        print('just websocket and grpc transport implemented :))')
        exit()
    SECURE, DOMAIN = SECURE        
    if NETWORK == 'grpc':
        HOST = DOMAIN
        DOMAIN = ss_input('You have grpc config, on this config you can select a sni to use domain fronting', DOMAIN, str)
else:
    if TYPE == 'server':
        SPEED_DOMAIN = ss_input(
            'Enter domain of your persoanl server behind cloudflare', 'speedtest.safasafari.ir', str)
    SECURE = {'y': 's', 'n': ''}[
        ss_input('Secure (y. https, n.http) ?', 'y', str)]
f = open("good.txt", "w")
cloud_ips = open('ips.txt', 'r').read().strip().split(
    "\n")[::-1] if len(sys.argv) < 2 else sys.argv[1:]

ch = {}

async def create_data_v2ray():
    CHUNKS = 4 * 1024
    next = b''
    headers = b'POST / HTTP/1.1\r\nHost: cp.cloudflare.com\r\nTransfer-Encoding: chunked\r\n\r\n'
    append = [headers]
    async for data in create_data():
        data = next + \
            '{:x}'.format(len(data)).encode() + \
            b'\r\n' + data + b'\r\n'
        current_bytes = b''.join(append)
        current_len = len(current_bytes)
        if current_len == CHUNKS:
            yield current_bytes
            append = []
            current_len = 0
        if current_len < CHUNKS:
            append.append(data[:CHUNKS - current_len])
            next = data[CHUNKS - current_len:]
    yield b''.join(append) + b'0\r\n\r\n'

async def websocket(ip, timeout, secure, domain, port, path, host, vess):
    async with ClientSession(connector=TCPConnector(resolver=fronting(ip)), timeout=ClientTimeout(total=timeout)) as sess:
        async with sess.ws_connect("ws{}://{}:{}{}".format(secure, domain, port, path), timeout=timeout, headers={"Host": host}) as websocket:
            async for send in vess.send_packets('cp.cloudflare.com', 80, create_data_v2ray()):
                await websocket.send_bytes(send)
            data = []
            async for d in vess.read_packets(websocket.receive_bytes):
                data.append(d)
                break
            data = b''.join(data)
            if data.split(b"\r\n")[0] != b"HTTP/1.1 204 NO CONTENT":
                return
    return True

async def grpc_v2ray(ip, timeout, secure, domain, port, service_name, host, vess):
    if secure == '':
        channel = Channel(ip, port)
    elif secure == 's':
        channel = SSChannel(ip, port, server_hostname=domain, ssl=True)
        channel._authority = host
    Tun = StreamStreamMethod(channel, f'/{service_name}/Tun', stream_pb2.Hunk, stream_pb2.Hunk)
    async for d in vess.read_packets_grpc(Tun(vess.send_packets_grpc('cp.cloudflare.com', 80, create_data_v2ray()), timeout=timeout)):
        if d.split(b"\r\n")[0] == b"HTTP/1.1 204 NO CONTENT":
            channel.close()
            return True
    channel.close()
    return False

async def check(ip):
    global COUNT, ch
    if COUNT <= 0:
        f.close()
        os._exit(1)
    if TYPE in ['vmess', 'vless']:
        try:
            vess = VmessSS(ID) if TYPE == 'vmess' else VlessSS(ID)
            if NETWORK == 'ws':
                if not await websocket(ip, TIMEOUT, SECURE, DOMAIN, PORT, PATH, HOST, vess):
                    return
            elif NETWORK == 'grpc':
                if not await grpc_v2ray(ip, TIMEOUT, SECURE, DOMAIN, PORT, PATH, HOST, vess):
                    return
        except:
            return

    elif TYPE in ['speed', 'server']:
        async with ClientSession(connector=TCPConnector(resolver=fronting(ip)), timeout=ClientTimeout(total=TIMEOUT)) as sess:
            try:
                async with sess.post('http{}://{}/{}up'.format(SECURE, SPEED_DOMAIN, '__' if SPEED_DOMAIN == 'speed.cloudflare.com' else ''), data=create_data()) as r:
                    if r.status != 200:
                        return
            except:
                return

    COUNT -= 1
    f.write(ip + "\n")
    logging.critical("find good ip: {}".format(ip))

async def select(ips):
    ipas = ipaddress.ip_network(ips)
    print("Progress: {:.2f}%".format(
        cloud_ips.index(ips) / len(cloud_ips) * 100), end='\r')
    collect = []
    for ip in ipas:
        collect.append(str(ip))
        if len(collect) % NUM_IPS == 0:
            await asyncio.gather(*[check(range) for range in collect])
            collect = []
            return
    await asyncio.gather(*[check(range) for range in collect])

async def main():
    if TYPE == 'speed':
        global SPEED_DOMAIN
        print('Finding worker', end='\r')
        for speed_urls in [open('speedtest_urls.txt', 'r') if os.path.exists('speedtest_urls.txt') else [], requests.get('https://raw.githubusercontent.com/SafaSafari/ss-cloud-scanner/main/speedtest_urls.txt').content.decode().split('\n')]:
            SPEED_DOMAIN = await get_working_worker(speed_urls)
            if SPEED_DOMAIN != None:
                break
        if SPEED_DOMAIN == None:
            print("Worker not found")
            exit()
        print("Selected Worker: " + SPEED_DOMAIN)
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(
        format=format, level=logging.CRITICAL, datefmt="%H:%M:%S")
    for i in range(-(-len(cloud_ips) // THREADS)):
        await asyncio.gather(*[select(range) for range in cloud_ips[i * THREADS:][:THREADS]])
    # logging.critical('Nice :)))') دیگه گیر ندین بهش :))))

asyncio.run(main())
