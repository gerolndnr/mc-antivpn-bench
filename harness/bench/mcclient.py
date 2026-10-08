"""Minimal Minecraft Java client for admission measurements (protocol 774 / 1.21.11).

The client connects to an owned loopback server, presents the subject address in a
PROXY protocol v2 header (the server software, not the product, parses it), and
plays the login, configuration and play phases far enough to observe *every*
place a product can refuse a player:

* DENY_LOGIN   disconnect before Login Success (PreLogin/Login events)
* DENY_CONFIG  disconnect during the configuration phase
* DENY_PLAY    joined, then kicked inside the observation window (e.g. async checks)
* ALLOW        still in the world when the observation window ends
* TIMEOUT      no decision before the hard deadline (a hung login)
* CLOSED       the connection was closed before Login Success without a disconnect message: no product decision
               (Velocity closes a login after its 30 s read timeout this way)
* ERROR        protocol or socket failure not attributable to the product

Timestamps are monotonic nanoseconds relative to the TCP connect.
"""
import asyncio
import hashlib
import ipaddress
import json
import re
import struct
import time
import uuid
import zlib

PROTOCOL = 774
CONFIG_KEEP_ALIVE, CONFIG_PING, CONFIG_DISCONNECT, CONFIG_FINISH = 0x04, 0x05, 0x02, 0x03
CONFIG_KNOWN_PACKS, CONFIG_COOKIE_REQUEST, CONFIG_ADD_PACK, CONFIG_CODE_OF_CONDUCT = 0x0E, 0x00, 0x09, 0x13
PLAY_DISCONNECT, PLAY_KEEP_ALIVE, PLAY_LOGIN, PLAY_PING, PLAY_POSITION, PLAY_START_CONFIG = \
    0x20, 0x2B, 0x30, 0x3B, 0x46, 0x74
SB_PLAY_TELEPORT, SB_PLAY_KEEP_ALIVE, SB_PLAY_PONG, SB_PLAY_CONFIG_ACK, SB_PLAY_LOADED = 0x00, 0x1B, 0x2C, 0x0F, 0x2B


def varint(number):
    number &= 0xFFFFFFFF
    out = bytearray()
    while True:
        part = number & 0x7F
        number >>= 7
        out.append(part | (0x80 if number else 0))
        if not number:
            return bytes(out)


def read_varint_bytes(data, offset=0):
    result = 0
    for shift in range(0, 35, 7):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
    raise ValueError('VarInt too long')


def string(value):
    encoded = value.encode('utf-8')
    return varint(len(encoded)) + encoded


def read_string(data, offset=0):
    length, offset = read_varint_bytes(data, offset)
    return data[offset:offset + length].decode('utf-8', 'replace'), offset + length


def proxy_v2_header(subject_ip, subject_port, destination_port):
    address = ipaddress.ip_address(subject_ip)
    if address.version == 4:
        destination = ipaddress.ip_address('127.0.0.1')
        family = 0x11
    else:
        destination = ipaddress.ip_address('::1')
        family = 0x21
    body = address.packed + destination.packed + struct.pack('>HH', subject_port, destination_port)
    return b'\r\n\r\n\x00\r\nQUIT\n' + bytes([0x21, family]) + struct.pack('>H', len(body)) + body


def offline_uuid(name):
    digest = bytearray(hashlib.md5(('OfflinePlayer:' + name).encode()).digest())
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(digest))


def text_of(raw):
    """Best-effort plain text from a JSON or NBT text component (for logs only)."""
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        printable = ''.join(chr(b) if 32 <= b < 127 else ' ' for b in raw) if isinstance(raw, bytes) else str(raw)
        return ' '.join(printable.split())[:300]
    out = []

    def walk(node):
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, dict):
            out.append(str(node.get('text', '')))
            out.append(str(node.get('translate', '')) if 'translate' in node and not node.get('text') else '')
            for child in node.get('extra', []) + node.get('with', []):
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(value)
    return ' '.join(''.join(out).split())[:300]


class Connection:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.threshold = -1

    async def read_packet(self):
        length = 0
        for shift in range(0, 35, 7):
            byte = (await self.reader.readexactly(1))[0]
            length |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
        if not 0 < length <= 8 * 1024 * 1024:
            raise ValueError(f'bad frame length {length}')
        frame = await self.reader.readexactly(length)
        if self.threshold >= 0:
            data_length, offset = read_varint_bytes(frame)
            frame = zlib.decompress(frame[offset:]) if data_length else frame[offset:]
        packet_id, offset = read_varint_bytes(frame)
        return packet_id, frame[offset:]

    def send(self, packet_id, payload=b''):
        body = varint(packet_id) + payload
        if self.threshold >= 0:
            if len(body) >= self.threshold:
                compressed = zlib.compress(body)
                body = varint(len(body)) + compressed
            else:
                body = varint(0) + body
        self.writer.write(varint(len(body)) + body)


async def admit(port, subject_ip, name, *, observe_s=8.0, deadline_s=30.0, host='127.0.0.1', proxy=True,
                protocol=PROTOCOL):
    """Attempt one join and classify the outcome. Never raises."""
    started = time.perf_counter_ns()
    marks = {}
    result = dict(subject_ip=subject_ip, name=name)

    def mark(label):
        marks[label] = (time.perf_counter_ns() - started) / 1e6

    async def run():
        reader, writer = await asyncio.open_connection(host, port)
        mark('connected')
        connection = Connection(reader, writer)
        try:
            if proxy:
                local_port = writer.get_extra_info('sockname')[1]
                writer.write(proxy_v2_header(subject_ip, 40000 + (local_port % 20000), port))
            connection.send(0x00, varint(protocol) + string('localhost') + struct.pack('>H', port) + varint(2))
            connection.send(0x00, string(name) + offline_uuid(name).bytes)
            await writer.drain()
            # ---- login
            while True:
                packet_id, data = await connection.read_packet()
                if packet_id == 0x00:
                    mark('decided')
                    reason = text_of(read_string(data)[0])
                    # The proxy's own timeout message is not a product's refusal.
                    if re.fullmatch(r'\s*(read )?timed out\.?\s*', reason, re.IGNORECASE):
                        return 'CLOSED', f'proxy: {reason}'
                    return 'DENY_LOGIN', reason
                if packet_id == 0x03:
                    connection.threshold = read_varint_bytes(data)[0]
                elif packet_id == 0x04:
                    message_id, _ = read_varint_bytes(data)
                    connection.send(0x02, varint(message_id) + b'\x00')
                elif packet_id == 0x05:
                    key, _ = read_string(data)
                    connection.send(0x04, string(key) + b'\x00')
                elif packet_id == 0x02:
                    mark('login_success')
                    connection.send(0x03)
                    break
                elif packet_id == 0x01:
                    return 'ERROR', 'server requested encryption (online-mode); fixture misconfigured'
                await writer.drain()
            # ---- configuration
            connection.send(0x00, string('en_us') + bytes([8]) + varint(0) + b'\x01' + bytes([0x7F]) + varint(1) +
                            b'\x00\x01' + varint(0))
            await writer.drain()
            while True:
                packet_id, data = await connection.read_packet()
                if packet_id == CONFIG_DISCONNECT:
                    mark('decided')
                    return 'DENY_CONFIG', text_of(data)
                if packet_id == CONFIG_KNOWN_PACKS:
                    connection.send(0x07, data)
                elif packet_id == CONFIG_KEEP_ALIVE:
                    connection.send(0x04, data)
                elif packet_id == CONFIG_PING:
                    connection.send(0x05, data)
                elif packet_id == CONFIG_COOKIE_REQUEST:
                    key, _ = read_string(data)
                    connection.send(0x01, string(key) + b'\x00')
                elif packet_id == CONFIG_ADD_PACK:
                    connection.send(0x06, data[:16] + varint(1))  # declined
                elif packet_id == CONFIG_CODE_OF_CONDUCT:
                    connection.send(0x09)
                elif packet_id == CONFIG_FINISH:
                    connection.send(0x03)
                    await writer.drain()
                    mark('configured')
                    break
                await writer.drain()
            # ---- play: stay for the observation window, answer liveness packets
            loop = asyncio.get_running_loop()
            window_end = None
            while True:
                timeout = None if window_end is None else window_end - loop.time()
                if timeout is not None and timeout <= 0:
                    mark('decided')
                    return 'ALLOW', None
                try:
                    packet_id, data = await asyncio.wait_for(connection.read_packet(), timeout)
                except asyncio.TimeoutError:
                    mark('decided')
                    return 'ALLOW', None
                if packet_id == PLAY_DISCONNECT:
                    mark('decided')
                    return 'DENY_PLAY', text_of(data)
                if packet_id == PLAY_LOGIN and window_end is None:
                    mark('joined')
                    window_end = loop.time() + observe_s
                    connection.send(SB_PLAY_LOADED)
                elif packet_id == PLAY_KEEP_ALIVE:
                    connection.send(SB_PLAY_KEEP_ALIVE, data)
                elif packet_id == PLAY_PING:
                    connection.send(SB_PLAY_PONG, data)
                elif packet_id == PLAY_POSITION:
                    teleport_id, _ = read_varint_bytes(data)
                    connection.send(SB_PLAY_TELEPORT, varint(teleport_id))
                elif packet_id == PLAY_START_CONFIG:
                    return 'ERROR', 'server re-entered configuration (transfer/reconfigure) - not modelled'
                await writer.drain()
        finally:
            writer.close()

    try:
        outcome, reason = await asyncio.wait_for(run(), deadline_s)
    except asyncio.TimeoutError:
        outcome, reason = 'TIMEOUT', f'no decision within {deadline_s}s'
    except asyncio.IncompleteReadError:
        # The server closed without a disconnect packet; classify by phase reached. Before Login Success that is no
        # refusal message at all (a proxy timeout, a crash): CLOSED, undecided rather than blocked.
        outcome = 'DENY_PLAY' if 'joined' in marks else 'DENY_CONFIG' if 'login_success' in marks else 'CLOSED'
        reason = 'connection closed without disconnect packet'
        mark('decided')
    except (OSError, ValueError, zlib.error, struct.error) as error:
        outcome, reason = 'ERROR', f'{type(error).__name__}: {str(error)[:200]}'
    result.update(outcome=outcome, reason=reason, marks=marks,
                  total_ms=(time.perf_counter_ns() - started) / 1e6)
    return result


async def status_protocol(port, host='127.0.0.1', proxy_ip='192.0.2.1'):
    """Server List Ping; returns (protocol, version name). Used to assert the fixture version."""
    reader, writer = await asyncio.open_connection(host, port)
    connection = Connection(reader, writer)
    writer.write(proxy_v2_header(proxy_ip, 41000, port))
    connection.send(0x00, varint(PROTOCOL) + string('localhost') + struct.pack('>H', port) + varint(1))
    connection.send(0x00)
    await writer.drain()
    _, data = await asyncio.wait_for(connection.read_packet(), 10)
    writer.close()
    payload = json.loads(read_string(data)[0])
    return payload['version']['protocol'], payload['version']['name']
