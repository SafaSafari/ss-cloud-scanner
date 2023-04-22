import os
import sys
import ssl
import time
import hmac
import socket
import struct
import random
import asyncio
import logging
import binascii
import ipaddress
from uuid import UUID
from hashlib import md5, sha256
from Crypto.Cipher import AES as AS
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def ss_input(prompt, default = '', t=int):
    result = input('{} {}:'.format(prompt, ("[" + str(default) + "] (Enter for default)") if str(default) != '' else ''))
    if result == '':
        return default
    else:
        return t(result)


async def create_data(size=512 * 1024):
    created_size = 0
    while size > created_size:
        created_size += 512
        yield b"S" * 512


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

    def __init__(self, uuid: str, writer, reader):
        self.uuid = UUID(uuid)
        self.key = random.randbytes(16)
        self.iv = random.randbytes(16)
        self.writer = writer
        self.reader = reader

    async def send(self, buf):
        await self.writer(buf)

    async def read(self):
        return await self.reader()

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
        await self.writer(auth + headerLen + nonce + req)
        return rv

    async def get_headers(self):
        header = await self.read()
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

# ////////////////////////////////////// config
CONFIG = []
input_config = input('Enter your config (supported: vless, trojan):')
if 'vless' in input_config or 'trojan' in input_config:
    parts = input_config.split('@')
    CONFIG += [parts[0] + '@', ':' + parts[1].split(':')[1]]
# /////////////////////////////////////// values
THREADS = 4
TIMEOUT = 7
COUNT = ss_input('Enter count of ip you need', 5)
TYPE = ['speed', 'vmess'][ss_input('Enter type (1.speed, 2.vmess)', 1) - 1]
SECURE = {'y': 's', 'n': ''}[ss_input('Secure?', 'y', str)]
# //////////////////////////////////////
f = open("good.txt", "w")
cloud_ips = open('ips.txt', 'r').read().strip().split("\n")[::-1] if len(sys.argv) < 2 else sys.argv[1:]

if TYPE == 'vmess':
    ID = ss_input('Enter uuid of proxy behind cloudflare', t=str)
    DOMAIN = ss_input('Enter domain (with subdoamin)', t=str)
    PORT = ss_input('Enter port', t=int)
    PATH = ss_input('And path', t=str)

ch = {}

async def check(ip):
    global COUNT, ch
    if COUNT <= 0:
        f.close()
        os._exit(1)
    if TYPE == 'vmess':
        try:
            CHUNKS = 4 * 1024
            async with ClientSession(connector=TCPConnector(resolver=fronting(ip)), timeout=ClientTimeout(total=TIMEOUT)) as sess:
                async with sess.ws_connect("ws{}://{}:{}/{}".format(SECURE, DOMAIN, PORT, PATH), timeout=TIMEOUT) as websocket:
                    vmess = VmessSS(ID,
                                    websocket.send_bytes, websocket.receive_bytes)
                    await vmess.send_headers('cp.cloudflare.com', 80)
                    headers = b'POST / HTTP/1.1\r\nHost: cp.cloudflare.com\r\nTransfer-Encoding: chunked\r\n\r\n'
                    append = [headers]
                    next = b''
                    async for data in create_data():
                        data = next + '{:x}'.format(len(data)).encode() + b'\r\n' + data + b'\r\n'
                        current_bytes = b''.join(append)
                        current_len = len(current_bytes)
                        if current_len == CHUNKS:
                            await vmess.send(current_bytes)
                            append = []
                            current_len = 0
                        if current_len < CHUNKS:
                            append.append(data[:CHUNKS - current_len])
                            next = data[CHUNKS - current_len:]
                    await vmess.send(b''.join(append) + b'0\r\n\r\n')
                    await vmess.get_headers()
                    data = []
                    while d := await vmess.read():
                        if (type(d) == bytes):
                            data.append(d)
                            break
                    data = b''.join(data)
                    if data.split(b"\r\n")[0] != b"HTTP/1.1 204 NO CONTENT":
                        return
        except:
            return

    elif TYPE == 'speed':
        async with ClientSession(connector=TCPConnector(resolver=fronting(ip)), timeout=ClientTimeout(total=TIMEOUT)) as sess:
            try:
                async with sess.post('http{}://speedtest.safasafari.workers.dev/up'.format(SECURE), data=create_data()) as r:
                    if await r.read() != b'ok':
                        return
            except:
                return
    COUNT -= 1
    if len(CONFIG) == 0:
        f.write(ip + "\n")
    else:
        f.write(CONFIG[0] + ip + CONFIG[1] + "[%s]" % ip + "\n")
    logging.critical("find good ip: {}".format(ip))

async def ping(ips):
    ipas = ipaddress.ip_network(ips)
    print("{:.2f}%".format(cloud_ips.index(ips) / len(cloud_ips) * 100), end='\r')
    collect = []
    for ip in ipas:
        collect.append(str(ip))
        if len(collect) % THREADS == 0:
            await asyncio.gather(*[check(range) for range in collect])
            collect = []
            return
    await asyncio.gather(*[check(range) for range in collect])

async def main():
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(
        format=format, level=logging.CRITICAL, datefmt="%H:%M:%S")
    for i in range(-(-len(cloud_ips) // THREADS)):
        await asyncio.gather(*[ping(range) for range in cloud_ips[i * THREADS:][:THREADS]])
    logging.critical('Nice :)))')

asyncio.run(main())
