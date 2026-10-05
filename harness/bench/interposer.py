"""Transparent egress interposer for product JVMs.

Every outbound TCP connection of the unprivileged `mc` user is redirected here by
iptables (see netguard.py). The interposer

* terminates TLS with a per-host certificate from the throwaway CA,
* logs every request (secrets redacted) and counts requests per host,
* scans every request for canary secrets and reports where they went,
* serves the request according to the active rule set:
  passthrough, record (forward once, then serve the recorded answer to every
  product), replay, template (re-use a recorded answer for another IP), fault
  injection (timeout, 429, 5xx, malformed, incomplete, reset) or deny,
* replaces canary API keys by the operator's real keys only when the request goes
  to the provider host that key belongs to. Product configurations therefore
  never contain a real key.

Rules are replaced atomically through the control API on 127.0.0.1:15000, which the
`mc` user cannot reach.
"""
import asyncio
import fnmatch
import hashlib
import ipaddress
import json
import math
import os
import random
import re
import socket
import sqlite3
import ssl
import struct
import threading
import time
import urllib.parse

from .ca import Authority

CATCH_ALL_PORT = 15001
CONTROL_PORT = 15000
SO_ORIGINAL_DST = 80
METHODS = (b'GET ', b'POST', b'PUT ', b'HEAD', b'DELE', b'PATC', b'OPTI')
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
IPV6_CANDIDATE = re.compile(r'(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])')
MAX_BODY = 4 * 1024 * 1024


def ip_literals(text):
    found = []
    for match in IPV4.findall(text):
        try:
            found.append(str(ipaddress.ip_address(match)))
        except ValueError:
            pass
    for match in IPV6_CANDIDATE.findall(text):
        try:
            address = ipaddress.ip_address(match)
            if address.version == 6:
                found.append(match)
        except ValueError:
            pass
    return found


class Request:
    def __init__(self, method, target, version, headers, body):
        self.method, self.target, self.version, self.headers, self.body = method, target, version, headers, body

    def header(self, name):
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    @property
    def keep_alive(self):
        connection = (self.header('connection') or '').lower()
        if self.version == 'HTTP/1.0':
            return connection == 'keep-alive'
        return connection != 'close'


async def read_request(reader):
    try:
        head = await reader.readuntil(b'\r\n\r\n')
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        return None
    lines = head.decode('iso-8859-1').split('\r\n')
    try:
        method, target, version = lines[0].split(' ', 2)
    except ValueError:
        return None
    headers = []
    for line in lines[1:]:
        if line and ':' in line:
            key, value = line.split(':', 1)
            headers.append((key.strip(), value.strip()))
    request = Request(method, target, version, headers, b'')
    if (request.header('transfer-encoding') or '').lower() == 'chunked':
        body = bytearray()
        while True:
            size_line = await reader.readuntil(b'\r\n')
            size = int(size_line.split(b';')[0].strip(), 16)
            if size == 0:
                await reader.readuntil(b'\r\n')
                break
            body.extend(await reader.readexactly(size))
            await reader.readexactly(2)
            if len(body) > MAX_BODY:
                return None
        request.body = bytes(body)
        request.headers = [(k, v) for k, v in headers if k.lower() != 'transfer-encoding']
    elif request.header('content-length'):
        length = int(request.header('content-length'))
        if length > MAX_BODY:
            return None
        request.body = await reader.readexactly(length)
    return request


async def read_response(reader):
    head = await reader.readuntil(b'\r\n\r\n')
    lines = head.decode('iso-8859-1').split('\r\n')
    parts = lines[0].split(' ', 2)
    status = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ''
    headers = []
    for line in lines[1:]:
        if line and ':' in line:
            key, value = line.split(':', 1)
            headers.append((key.strip(), value.strip()))
    lookup = {k.lower(): v for k, v in headers}
    if (lookup.get('transfer-encoding') or '').lower() == 'chunked':
        body = bytearray()
        while True:
            size = int((await reader.readuntil(b'\r\n')).split(b';')[0].strip(), 16)
            if size == 0:
                try:
                    await reader.readuntil(b'\r\n')
                except asyncio.IncompleteReadError:
                    pass
                break
            body.extend(await reader.readexactly(size))
            await reader.readexactly(2)
    elif 'content-length' in lookup:
        body = await reader.readexactly(int(lookup['content-length']))
    elif status in (204, 304) or 100 <= status < 200:
        body = b''
    else:
        body = await reader.read(MAX_BODY)
    keep = [(k, v) for k, v in headers if k.lower() not in
            ('transfer-encoding', 'content-length', 'connection', 'keep-alive')]
    return status, reason, keep, bytes(body)


class Store:
    """Recorded upstream answers, keyed by redacted canonical request."""

    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('create table if not exists answer (key text primary key, template_key text, host text,'
                        ' status integer, reason text, headers text, body blob, upstream_ms real, recorded_at real,'
                        ' subject_ip text)')
        self.db.execute('create index if not exists answer_template on answer(template_key)')
        self.db.commit()

    def get(self, key):
        with self.lock:
            row = self.db.execute('select status, reason, headers, body, upstream_ms, recorded_at from answer'
                                  ' where key=?', (key,)).fetchone()
        if not row:
            return None
        return dict(status=row[0], reason=row[1], headers=json.loads(row[2]), body=row[3], upstream_ms=row[4],
                    recorded_at=row[5])

    def template(self, template_key, reference_ip):
        with self.lock:
            row = self.db.execute('select status, reason, headers, body, upstream_ms, subject_ip from answer'
                                  ' where template_key=? and subject_ip=?', (template_key, reference_ip)).fetchone()
        if not row:
            return None
        return dict(status=row[0], reason=row[1], headers=json.loads(row[2]), body=row[3], upstream_ms=row[4],
                    subject_ip=row[5])

    def put(self, key, template_key, host, answer, subject_ip):
        with self.lock:
            self.db.execute('insert or ignore into answer values (?,?,?,?,?,?,?,?,?,?)',
                            (key, template_key, host, answer['status'], answer['reason'],
                             json.dumps(answer['headers']), answer['body'], answer['upstream_ms'], time.time(),
                             subject_ip))
            self.db.commit()


class Interposer:
    def __init__(self, state_dir, secrets=None):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.authority = Authority(os.path.join(state_dir, 'ca'))
        self.store = Store(os.path.join(state_dir, 'answers.sqlite'))
        # One log per interposer lifetime; sequence numbers are only unique within it.
        self.events_path = os.path.join(state_dir, 'egress.jsonl')
        if os.path.exists(self.events_path):
            os.replace(self.events_path, os.path.join(state_dir, f'egress-{int(time.time())}.jsonl'))
        self.events = open(self.events_path, 'w', buffering=1)
        # {name: {"canary": str, "value": str|None, "hosts": [glob]}}; real values come from the environment.
        self.secrets = secrets or {}
        self.rules = dict(default='deny', rules=[], replay_latency='recorded', seed=1)
        self.counters = {}
        self.sequence = 0
        self.random = random.Random(1)
        self.sni = {}
        self.key_locks = {}
        self.upstream_tls = ssl.create_default_context()
        self.lock = threading.Lock()

    # ----------------------------------------------------------------- rules
    def configure(self, rules):
        rules.setdefault('default', 'deny')
        rules.setdefault('rules', [])
        rules.setdefault('replay_latency', 'recorded')
        self.rules = rules
        self.random = random.Random(rules.get('seed', 1))

    def rule_for(self, host):
        for rule in self.rules['rules']:
            if any(fnmatch.fnmatch(host, pattern) for pattern in rule.get('hosts', ['*'])):
                return rule
        return dict(action=self.rules['default'])

    # ---------------------------------------------------------------- secrets
    def redact(self, text):
        for name, secret in self.secrets.items():
            for value in (secret.get('value'), secret.get('canary')):
                if value:
                    text = text.replace(value, f'<SECRET:{name}>')
                    text = text.replace(urllib.parse.quote(value, safe=''), f'<SECRET:{name}>')
        return text

    def canaries_in(self, raw):
        hits = []
        for name, secret in self.secrets.items():
            canary = secret.get('canary')
            if canary and (canary in raw or urllib.parse.quote(canary, safe='') in raw):
                hits.append(name)
        return hits

    def inject(self, host, raw):
        """Replace canaries by real values for the hosts each secret belongs to."""
        for secret in self.secrets.values():
            if secret.get('value') and secret.get('canary') and \
                    any(fnmatch.fnmatch(host, pattern) for pattern in secret.get('hosts', [])):
                raw = raw.replace(secret['canary'], secret['value'])
        return raw

    def secret_allowed(self, name, host):
        return any(fnmatch.fnmatch(host, pattern) for pattern in self.secrets[name].get('hosts', []))

    # ------------------------------------------------------------- canonical
    def canonical(self, scheme, host, request):
        parsed = urllib.parse.urlsplit(request.target)
        query = sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        path = self.redact(urllib.parse.unquote(parsed.path))
        query_text = self.redact(urllib.parse.urlencode(query))
        body = self.redact(request.body.decode('utf-8', 'replace'))
        headers = sorted((k.lower(), self.redact(v)) for k, v in request.headers
                         if k.lower() in ('x-key', 'key', 'authorization', 'x-api-key'))
        key = f'{request.method} {scheme}://{host}{path}?{query_text}|{json.dumps(headers)}|' \
              f'{hashlib.sha256(body.encode()).hexdigest()}'
        subjects = ip_literals(urllib.parse.unquote(request.target) + ' ' + body)
        subject = subjects[0] if subjects else None
        template_key = key
        if subject:
            template_key = f'{request.method} {scheme}://{host}{path.replace(subject, "{IP}")}?' \
                           f'{query_text.replace(subject, "{IP}").replace(urllib.parse.quote(subject), "{IP}")}|' \
                           f'{json.dumps(headers)}|{hashlib.sha256(body.replace(subject, "{IP}").encode()).hexdigest()}'
        return key, template_key, subject

    # ------------------------------------------------------------- handling
    def log(self, **event):
        with self.lock:
            self.sequence += 1
            event['seq'] = self.sequence
            event['ts'] = time.time()
            self.events.write(json.dumps(event, sort_keys=True) + '\n')
            counter = self.counters.setdefault(event.get('host', '?'), {})
            counter[event.get('action', '?')] = counter.get(event.get('action', '?'), 0) + 1

    def latency(self, rule, recorded_ms):
        spec = rule.get('latency_ms')
        if spec is None:
            if self.rules.get('replay_latency') == 'recorded' and recorded_ms is not None:
                return min(recorded_ms, 5000) / 1000
            return 0
        if isinstance(spec, (int, float)):
            return spec / 1000
        # Log-normal with the given median and p95, seeded per rule set.
        median, p95 = spec['median'], spec['p95']
        sigma = max(0.01, (math.log(p95) - math.log(median)) / 1.645)
        return self.random.lognormvariate(math.log(median), sigma) / 1000

    async def open_upstream(self, scheme, host, port):
        port = port or (443 if scheme == 'https' else 80)  # direct (non-redirected) clients
        return await asyncio.wait_for(asyncio.open_connection(
            host, port, ssl=self.upstream_tls if scheme == 'https' else None,
            server_hostname=host if scheme == 'https' else None), 10)

    def upstream_request(self, host, request, rule=None):
        target = request.target
        for param, secret_name in ((rule or {}).get('add_query_if_missing') or {}).items():
            value = (self.secrets.get(secret_name) or {}).get('value')
            query = urllib.parse.urlsplit(target).query
            if value and param not in dict(urllib.parse.parse_qsl(query, keep_blank_values=True)):
                target += ('&' if '?' in target else '?') + urllib.parse.urlencode({param: value})
        raw_target = self.inject(host, target)
        headers = [(k, self.inject(host, v)) for k, v in request.headers
                   if k.lower() not in ('accept-encoding', 'connection', 'keep-alive', 'proxy-connection', 'host',
                                        'content-length', 'transfer-encoding', 'upgrade', 'http2-settings', 'te')]
        body = self.inject(host, request.body.decode('latin-1')).encode('latin-1')
        lines = [f'{request.method} {raw_target} HTTP/1.1', f'Host: {request.header("host") or host}']
        lines += [f'{k}: {v}' for k, v in headers]
        if body or request.method in ('POST', 'PUT', 'PATCH'):
            lines.append(f'Content-Length: {len(body)}')
        lines += ['Accept-Encoding: identity', 'Connection: close', '', '']
        return '\r\n'.join(lines).encode('latin-1') + body

    async def forward(self, scheme, host, port, request, timeout=20, rule=None):
        started = time.perf_counter()
        reader, writer = await self.open_upstream(scheme, host, port)
        try:
            writer.write(self.upstream_request(host, request, rule))
            await writer.drain()
            status, reason, response_headers, response_body = await asyncio.wait_for(read_response(reader), timeout)
        finally:
            writer.close()
        return dict(status=status, reason=reason, headers=response_headers, body=response_body,
                    upstream_ms=(time.perf_counter() - started) * 1000)

    async def stream_passthrough(self, scheme, host, port, request, writer):
        """HTTP/1.1 passthrough without buffering (library and list downloads can be large)."""
        upstream_reader, upstream_writer = await self.open_upstream(scheme, host, port)
        status, total = None, 0
        try:
            upstream_writer.write(self.upstream_request(host, request))
            await upstream_writer.drain()
            while True:
                chunk = await asyncio.wait_for(upstream_reader.read(65536), 120)
                if not chunk:
                    break
                if status is None:
                    try:
                        status = int(chunk.split(b' ', 2)[1])
                    except (IndexError, ValueError):
                        status = -1
                total += len(chunk)
                writer.write(chunk)
                await writer.drain()
        finally:
            upstream_writer.close()
        return status, total

    def prepare(self, request, scheme, conn_host, port, conn_id):
        host = (request.header('host') or conn_host or '').split(':')[0].lower().strip('[]')
        raw = request.target + '\n' + '\n'.join(f'{k}: {v}' for k, v in request.headers) + '\n' + \
            request.body.decode('utf-8', 'replace')
        leaks = [dict(secret=name, allowed_host=self.secret_allowed(name, host), tls=scheme == 'https')
                 for name in self.canaries_in(raw)]
        rule = self.rule_for(host)
        key, template_key, subject = self.canonical(scheme, host, request)
        event = dict(conn=conn_id, scheme=scheme, host=host, port=port, method=request.method,
                     version=request.version, target=self.redact(request.target)[:400], subject_ip=subject,
                     action=rule.get('action', 'deny'), rule=rule.get('name'), leaks=leaks)
        return dict(host=host, rule=rule, action=event['action'], key=key, template_key=template_key,
                    subject=subject, event=event, started=time.perf_counter())

    async def decide(self, ctx, request, scheme, port):
        """Resolve a non-fault, non-deny request to (answer, source); answer None means 504."""
        rule, action = ctx['rule'], ctx['action']
        if action == 'record':
            # Single flight: concurrent identical requests (several products asking about the same
            # subject at once) share one upstream call and therefore one answer.
            lock = self.key_locks.setdefault(ctx['key'], asyncio.Lock())
            async with lock:
                return await self._decide(ctx, request, scheme, port)
        return await self._decide(ctx, request, scheme, port)

    async def _decide(self, ctx, request, scheme, port):
        rule, action = ctx['rule'], ctx['action']
        answer, source = None, None
        if action in ('record', 'replay'):
            answer = self.store.get(ctx['key'])
            source = 'store' if answer else None
        if answer is None and action == 'template' and ctx['subject']:
            reference = rule.get('reference_ip')
            found = self.store.template(ctx['template_key'], reference) if reference else None
            if found:
                answer = dict(found, body=found['body'].replace(reference.encode(), ctx['subject'].encode()))
                source = 'template'
        if answer is None and action in ('record', 'passthrough'):
            answer = await self.forward(scheme, ctx['host'], port, request,
                                        timeout=120 if action == 'passthrough' else 20, rule=rule)
            source = 'upstream'
            if action == 'record' and answer['status'] < 500 and answer['status'] != 429:
                self.store.put(ctx['key'], ctx['template_key'], ctx['host'], answer, ctx['subject'])
        if answer is not None and source != 'upstream':
            delay = self.latency(rule, answer.get('upstream_ms'))
            if delay:
                await asyncio.sleep(delay)
        return answer, source

    FAULT_BODIES = {
        'http_429': (429, 'Too Many Requests', b'{"status":"denied","message":"rate limit exceeded"}',
                     [('Retry-After', '60')]),
        'http_500': (500, 'Internal Server Error', b'{"status":"error","message":"internal error"}', []),
        'http_503': (503, 'Service Unavailable', b'<html><body>503 Service Unavailable</body></html>', []),
        'malformed': (200, 'OK', b'{"status":"ok",,"proxy":<<nope>>', []),
        'empty': (200, 'OK', b'', []),
        'html': (200, 'OK', b'<!doctype html><html><body>Please verify you are human</body></html>', []),
    }
    INCOMPLETE_BODY = b'{"status":"ok","proxy":"no","type":"Residential","risk":'

    def fault_answer(self, kind):
        status, reason, body, extra = self.FAULT_BODIES[kind]
        content_type = 'text/html' if body.startswith(b'<') else 'application/json'
        return dict(status=status, reason=reason, headers=[('Content-Type', content_type)] + extra, body=body)

    # ----------------------------------------------------------- HTTP/1.1
    async def respond(self, writer, answer, keep_alive):
        headers = [(k, v) for k, v in answer['headers'] if k.lower() not in ('content-encoding',)]
        lines = [f'HTTP/1.1 {answer["status"]} {answer.get("reason") or "OK"}']
        lines += [f'{k}: {v}' for k, v in headers]
        lines += [f'Content-Length: {len(answer["body"])}', 'Connection: ' + ('keep-alive' if keep_alive else 'close'),
                  '', '']
        writer.write('\r\n'.join(lines).encode('latin-1') + answer['body'])
        await writer.drain()

    async def fault_http1(self, kind, rule, writer, reader):
        if kind == 'timeout':
            # Accept the request and never answer; the product's own deadline must fire.
            try:
                await asyncio.wait_for(reader.read(1), rule.get('hold_s', 120))
            except asyncio.TimeoutError:
                pass
            return False
        if kind == 'reset':
            sock = writer.get_extra_info('socket')
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            writer.close()
            return False
        if kind == 'incomplete':
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n'
                         b'Connection: close\r\n\r\n' + self.INCOMPLETE_BODY)
            await writer.drain()
            writer.close()
            return False
        await self.respond(writer, self.fault_answer(kind), True)
        return True

    async def serve_http(self, reader, writer, scheme, conn_host, port, conn_id):
        while True:
            request = await read_request(reader)
            if request is None:
                return
            if request.method == 'PRI' and request.version == 'HTTP/2.0':
                # HTTP/2 with prior knowledge: hand the rest of the preface to the h2 handler.
                await self.serve_h2(reader, writer, scheme, conn_host, port, conn_id,
                                    initial=b'PRI * HTTP/2.0\r\n\r\n')
                return
            ctx = self.prepare(request, scheme, conn_host, port, conn_id)
            event, rule, action = ctx['event'], ctx['rule'], ctx['action']
            try:
                if action == 'deny':
                    self.log(**event, status=None)
                    writer.close()
                    return
                if action == 'passthrough':
                    status, total = await self.stream_passthrough(scheme, ctx['host'], port, request, writer)
                    self.log(**event, status=status, source='upstream-stream', bytes=total,
                             served_ms=(time.perf_counter() - ctx['started']) * 1000)
                    return
                if action == 'fault':
                    delay = self.latency(rule, None)
                    if delay:
                        await asyncio.sleep(delay)
                    keep = await self.fault_http1(rule['fault'], rule, writer, reader)
                    self.log(**event, fault=rule['fault'], status=None,
                             served_ms=(time.perf_counter() - ctx['started']) * 1000)
                    if not keep or not request.keep_alive:
                        return
                    continue
                answer, source = await self.decide(ctx, request, scheme, port)
                if answer is None:
                    answer, source = dict(status=504, reason='Gateway Timeout', headers=[('Content-Type', 'text/plain')],
                                          body=b'mc-antivpn-bench: no recorded answer'), 'missing'
                await self.respond(writer, answer, request.keep_alive)
                self.log(**event, status=answer['status'], source=source,
                         served_ms=(time.perf_counter() - ctx['started']) * 1000, upstream_ms=answer.get('upstream_ms'))
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError, ssl.SSLError) as error:
                self.log(**event, status=None, error=f'{type(error).__name__}: {str(error)[:200]}')
                writer.close()
                return
            if not request.keep_alive:
                return

    # ------------------------------------------------------------- HTTP/2
    async def serve_h2(self, reader, writer, scheme, conn_host, port, conn_id, initial=b''):
        import h2.config
        import h2.connection
        import h2.events
        import h2.exceptions
        connection = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding='utf-8'))
        connection.initiate_connection()
        writer.write(connection.data_to_send())
        streams, tasks = {}, set()
        window = asyncio.Event()

        def flush():
            data = connection.data_to_send()
            if data:
                writer.write(data)

        async def send(stream_id, answer, partial=False):
            headers = [(':status', str(answer['status']))]
            headers += [(k.lower(), v) for k, v in answer['headers'] if k.lower() not in
                        ('connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'proxy-connection',
                         'content-encoding', 'content-length')]
            body = answer['body']
            headers.append(('content-length', str(400 if partial else len(body))))
            connection.send_headers(stream_id, headers, end_stream=not body and not partial)
            flush()
            offset = 0
            while offset < len(body):
                allowed = min(connection.local_flow_control_window(stream_id), connection.max_outbound_frame_size,
                              len(body) - offset)
                if allowed <= 0:
                    window.clear()
                    flush()
                    await writer.drain()
                    await window.wait()
                    continue
                connection.send_data(stream_id, body[offset:offset + allowed])
                offset += allowed
                flush()
                await writer.drain()
            if partial:
                connection.reset_stream(stream_id)
            elif body:
                connection.end_stream(stream_id)
            flush()
            await writer.drain()

        async def process(stream_id, raw_headers, body):
            pseudo = {k: v for k, v in raw_headers if k.startswith(':')}
            headers = [(k, v) for k, v in raw_headers if not k.startswith(':')]
            if pseudo.get(':authority'):
                headers.append(('host', pseudo[':authority']))
            request = Request(pseudo.get(':method', 'GET'), pseudo.get(':path', '/'), 'HTTP/2', headers, body)
            ctx = self.prepare(request, scheme, conn_host, port, conn_id)
            event, rule, action = ctx['event'], ctx['rule'], ctx['action']
            try:
                if action == 'deny':
                    self.log(**event, status=None)
                    connection.reset_stream(stream_id)
                    flush()
                    return
                if action == 'fault':
                    kind = rule['fault']
                    delay = self.latency(rule, None)
                    if delay:
                        await asyncio.sleep(delay)
                    self.log(**event, fault=kind, status=None)
                    if kind == 'timeout':
                        return  # stream stays open, unanswered
                    if kind == 'reset':
                        connection.reset_stream(stream_id)
                        flush()
                        return
                    if kind == 'incomplete':
                        await send(stream_id, dict(status=200, headers=[('content-type', 'application/json')],
                                                   body=self.INCOMPLETE_BODY), partial=True)
                        return
                    await send(stream_id, self.fault_answer(kind))
                    return
                answer, source = await self.decide(ctx, request, scheme, port)
                if answer is None:
                    answer, source = dict(status=504, headers=[('content-type', 'text/plain')],
                                          body=b'mc-antivpn-bench: no recorded answer'), 'missing'
                await send(stream_id, answer)
                self.log(**event, status=answer['status'], source=source,
                         served_ms=(time.perf_counter() - ctx['started']) * 1000, upstream_ms=answer.get('upstream_ms'))
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError, ssl.SSLError,
                    h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError) as error:
                self.log(**event, status=None, error=f'{type(error).__name__}: {str(error)[:200]}')

        pending = initial
        try:
            while True:
                data = pending or await reader.read(65536)
                pending = b''
                if not data:
                    break
                try:
                    events = connection.receive_data(data)
                except h2.exceptions.ProtocolError as error:
                    self.log(conn=conn_id, host=conn_host, port=port, action='h2_error', error=str(error)[:200])
                    flush()
                    break
                for item in events:
                    # h2 reports END_STREAM as a separate StreamEnded event (also for header-only requests).
                    if isinstance(item, h2.events.RequestReceived):
                        streams[item.stream_id] = [item.headers, bytearray()]
                    elif isinstance(item, h2.events.DataReceived):
                        if item.stream_id in streams:
                            streams[item.stream_id][1].extend(item.data)
                        connection.acknowledge_received_data(item.flow_controlled_length, item.stream_id)
                    elif isinstance(item, h2.events.WindowUpdated):
                        window.set()
                    elif isinstance(item, h2.events.StreamEnded) and item.stream_id in streams:
                        raw_headers, body = streams.pop(item.stream_id)
                        task = asyncio.create_task(process(item.stream_id, raw_headers, bytes(body)))
                        tasks.add(task)
                        task.add_done_callback(tasks.discard)
                    elif isinstance(item, h2.events.ConnectionTerminated):
                        flush()
                        return
                flush()
                await writer.drain()
        finally:
            for task in tasks:
                task.cancel()

    # ----------------------------------------------------------- dispatch
    async def handle(self, conn):
        loop = asyncio.get_running_loop()
        conn_id = f'{time.time_ns():x}'
        try:
            packed = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port = struct.unpack('>H', packed[2:4])[0]
            original = socket.inet_ntoa(packed[4:8])
        except OSError:
            try:
                packed = conn.getsockopt(socket.SOL_IPV6, SO_ORIGINAL_DST, 28)
                port = struct.unpack('>H', packed[2:4])[0]
                original = socket.inet_ntop(socket.AF_INET6, packed[8:24])
            except OSError:
                original, port = None, None
        conn.setblocking(False)
        readable = loop.create_future()
        loop.add_reader(conn.fileno(), lambda: readable.done() or readable.set_result(True))
        try:
            await asyncio.wait_for(readable, 30)
        except asyncio.TimeoutError:
            conn.close()
            return
        finally:
            loop.remove_reader(conn.fileno())
        try:
            first = conn.recv(8, socket.MSG_PEEK)
        except OSError:
            conn.close()
            return
        reader = asyncio.StreamReader(limit=MAX_BODY)
        protocol = asyncio.StreamReaderProtocol(reader)
        alpn = None
        if first[:1] == b'\x16':
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.set_alpn_protocols(['h2', 'http/1.1'])
            names = {}

            def choose(ssl_object, server_name, _context):
                names['sni'] = server_name
                ssl_object.context = self.authority.context_for(server_name or original)
            context.sni_callback = choose
            self.authority.context_for(original)
            context.load_cert_chain(*self._default_chain(None, original))
            try:
                transport, _ = await loop.connect_accepted_socket(lambda: protocol, sock=conn, ssl=context,
                                                                  ssl_handshake_timeout=10)
            except (OSError, ssl.SSLError, asyncio.TimeoutError) as error:
                self.log(conn=conn_id, host=original, port=port, action='tls_failed',
                         error=f'{type(error).__name__}: {str(error)[:200]}')
                return
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            ssl_object = writer.get_extra_info('ssl_object')
            alpn = ssl_object.selected_alpn_protocol() if ssl_object else None
            scheme, host = 'https', names.get('sni') or original
        elif first and (any(first.startswith(m[:len(first)]) for m in METHODS) or first.startswith(b'PRI ')):
            transport, _ = await loop.connect_accepted_socket(lambda: protocol, sock=conn)
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            scheme, host = 'http', original
        else:
            # Non-HTTP egress (database, raw socket, telemetry protocol): never forwarded.
            self.log(conn=conn_id, host=original, port=port, action='raw_denied', first=first.hex())
            conn.close()
            return
        try:
            if alpn == 'h2':
                await self.serve_h2(reader, writer, scheme, host, port, conn_id)
            else:
                await self.serve_http(reader, writer, scheme, host, port, conn_id)
        except (OSError, ssl.SSLError, asyncio.IncompleteReadError) as error:
            self.log(conn=conn_id, host=host, port=port, action='connection_error',
                     error=f'{type(error).__name__}: {str(error)[:200]}')
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _default_chain(self, _context, original):
        safe = ''.join(c if c.isalnum() or c in '.-' else '_' for c in (original or 'unknown.invalid'))
        directory = self.authority.directory
        return os.path.join(directory, f'leaf-{safe}.pem'), os.path.join(directory, f'leaf-{safe}.key')

    # ------------------------------------------------------------- control
    async def control(self, reader, writer):
        request = await read_request(reader)
        if request is None:
            writer.close()
            return
        path = request.target
        status, payload = 200, {}
        if request.method == 'PUT' and path == '/rules':
            self.configure(json.loads(request.body or b'{}'))
            payload = dict(ok=True)
        elif request.method == 'GET' and path == '/rules':
            payload = self.rules
        elif request.method == 'GET' and path == '/stats':
            payload = dict(sequence=self.sequence, counters=self.counters)
        elif request.method == 'POST' and path == '/reset':
            self.counters = {}
            payload = dict(ok=True, sequence=self.sequence)
        elif request.method == 'GET' and path == '/health':
            payload = dict(ok=True)
        else:
            status, payload = 404, dict(error='unknown')
        body = json.dumps(payload).encode()
        writer.write(f'HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n'
                     f'Connection: close\r\n\r\n'.encode() + body)
        await writer.drain()
        writer.close()

    async def run(self):
        loop = asyncio.get_running_loop()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('0.0.0.0', CATCH_ALL_PORT))
        listener.listen(4096)
        listener.setblocking(False)
        listener6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listener6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener6.bind(('::', CATCH_ALL_PORT))
        listener6.listen(4096)
        listener6.setblocking(False)
        await asyncio.start_server(self.control, '127.0.0.1', CONTROL_PORT)

        async def accept(sock):
            while True:
                conn, _ = await loop.sock_accept(sock)
                loop.create_task(self.handle(conn))
        await asyncio.gather(accept(listener), accept(listener6))


def secrets_from_environment(spec):
    """spec: {name: {"env": "PROXYCHECK_KEY", "canary": "...", "hosts": [...]}}"""
    resolved = {}
    for name, entry in spec.items():
        resolved[name] = dict(canary=entry['canary'], hosts=entry['hosts'],
                              value=os.environ.get(entry.get('env', ''), '') or None)
    return resolved


def main(state_dir, secrets_path=None):
    secrets = {}
    if secrets_path and os.path.exists(secrets_path):
        with open(secrets_path) as handle:
            secrets = secrets_from_environment(json.load(handle))
    asyncio.run(Interposer(state_dir, secrets).run())
