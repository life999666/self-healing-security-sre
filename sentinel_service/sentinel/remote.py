"""Windows-side authenticated executor client; no model-generated commands."""
import base64
import hashlib
import hmac
import ipaddress
import json
import shlex
import socket
import threading
import time
import uuid
import paramiko
from .sql_patterns import candidate_source


class RemoteFailure(RuntimeError):
    pass


class KaliRepair:
    def __init__(self, host, fingerprint, lab_path, user='kali', port=9002, ssh_port=22):
        ip = ipaddress.ip_address(host)
        if ip.version != 4 or not ip.is_private or ip.is_unspecified:
            raise ValueError('Use a specific private Kali IPv4 address')
        self.host, self.fingerprint, self.lab_path = host, fingerprint.strip(), lab_path
        self.user, self.port, self.ssh_port = user, port, ssh_port
        self.transport = self.channel = None
        self.buffer = b''
        self.lock = threading.Lock()

    def connect(self, password_provider):
        try:
            self.transport = paramiko.Transport(socket.create_connection((self.host, self.ssh_port), timeout=10))
            self.transport.get_security_options().key_types = ('ssh-ed25519',)
            self.transport.start_client(timeout=10)
            key = self.transport.get_remote_server_key()
            actual = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            if not hmac.compare_digest(actual, self.fingerprint):
                raise RuntimeError('SSH fingerprint mismatch. Verify the Kali host key locally.')
            # Ask for the password only AFTER host identity was verified.
            password = password_provider()
            self.transport.auth_password(self.user, password)
            del password
            self.transport.set_keepalive(15)
            self.channel = self.transport.open_session(timeout=10)
            self.channel.settimeout(10)
            self.channel.exec_command('cd ' + shlex.quote(self.lab_path)
                + ' && exec .venv/bin/python -u executor.py --host ' + shlex.quote(self.host)
                + ' --port ' + str(self.port))
            ready = self.receive(30)
            if ready.get('type') != 'ready':
                raise RuntimeError('Kali executor not ready')
        except Exception:
            self.close()
            raise

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                return json.loads(line)
            if self.channel.recv_stderr_ready():
                print(self.channel.recv_stderr(4096).decode(errors='replace'), end='', flush=True)
            if self.channel.recv_ready():
                data = self.channel.recv(4096)
                if not data:
                    raise ConnectionError('Executor disconnected')
                self.buffer += data
                if len(self.buffer) > 131072:
                    raise ValueError('Oversized executor response')
                continue
            if self.channel.closed or self.channel.exit_status_ready():
                raise ConnectionError('Executor stopped; check Kali diagnostics')
            time.sleep(.02)
        raise TimeoutError('Executor outcome unknown; inspect Kali repair-runs')

    def rpc(self, op, data=None):
        request_id = str(uuid.uuid4())
        self.channel.sendall((json.dumps({'id': request_id, 'op': op, 'data': data or {}})+'\n').encode())
        reply = self.receive(90)
        if reply.get('id') != request_id:
            raise ConnectionError('Unexpected executor reply')
        if not reply.get('ok'):
            raise RemoteFailure(reply.get('error', 'Remote operation failed'))
        return reply['data']

    def repair(self, incident):
        with self.lock:
            event = {k: incident[k] for k in ('id', 'label', 'path')}
            trace = ['investigate']
            # If begin fails before a transaction exists, do not touch old reports.
            try:
                reply = self.rpc('begin', event)
            except RemoteFailure as exc:
                try:
                    self.rpc('rollback', {'error': str(exc)})
                    return self.rpc('finish', {'trace': trace + ['rollback']})
                except RemoteFailure:
                    return {'status': 'refused', 'error': str(exc)}
            try:
                original = base64.b64decode(reply['source'], validate=True)
                trace.append('plan_on_windows')
                candidate = candidate_source(original)
                self.rpc('stage', {'source': base64.b64encode(candidate).decode()})
                for step in ('test', 'apply', 'verify'):
                    trace.append(step)
                    self.rpc(step)
            except (RemoteFailure, ValueError, SyntaxError) as exc:
                trace.append('rollback')
                self.rpc('rollback', {'error': str(exc)})
            return self.rpc('finish', {'trace': trace})

    def close(self):
        if self.channel is not None:
            try:
                self.channel.shutdown_write()
                deadline = time.monotonic() + 15
                while not self.channel.exit_status_ready() and time.monotonic() < deadline:
                    if self.channel.recv_ready():
                        self.channel.recv(4096)
                    time.sleep(.05)
            except Exception:
                pass
            finally:
                self.channel.close()
                self.channel = None
        if self.transport is not None:
            self.transport.close()
            self.transport = None
