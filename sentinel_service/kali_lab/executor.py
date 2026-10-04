"""SSH stdin/stdout execution service for the Windows Repair Agent."""
import argparse
import base64
import difflib
import fcntl
import ipaddress
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid
from worker_support import Worker, digest


class Executor(Worker):
    def __init__(self, root, host, port):
        self.root, self.host, self.port = root.resolve(), host, port
        self.target = self.root / 'unsafe_demo.py'
        self.runs = self.root / 'repair-runs'
        self.runs.mkdir(exist_ok=True)
        self.journal = self.runs / 'pending.json'
        self.child = self.log = None
        self.trace, self.report = [], {}
        self.phase = 'idle'

    def check_port(self):
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            check.bind((self.host, self.port))

    def start_app(self):
        self.check_port()
        self.log = open(self.runs / 'app.log', 'ab', buffering=0)
        self.child = subprocess.Popen([sys.executable, str(self.root/'worker_support.py'),
            '--app-child', '--host', self.host, '--port', str(self.port)],
            cwd=self.root, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)

    def command(self, op, data):
        if op == 'health':
            return {'healthy': self.healthy(), 'phase': self.phase}
        if op == 'begin':
            if self.phase != 'idle':
                raise ValueError('Repair already active')
            incident = str(uuid.UUID(data['id']))
            if data.get('label') != 'sql_injection' or data.get('path') != '/products':
                raise ValueError('Only onboarded /products source repairs allowed')
            self.run = self.runs / incident
            if self.run.exists():
                raise ValueError('Incident already exists; inspect its report')
            self.run.mkdir()
            self.phase = 'begun'
            self.report = {'incident_id': incident, 'started': time.time(),
                           'status': 'investigating', 'controller': 'windows'}
            self.investigate()
            if len(self.original) > 60000:
                raise ValueError('Lab source exceeds protocol limit')
            return {'source': base64.b64encode(self.original).decode()}
        if op == 'stage' and self.phase == 'begun':
            candidate = base64.b64decode(data['source'], validate=True)
            if len(candidate) > 60000:
                raise ValueError('Candidate too large')
            compile(candidate, 'candidate.py', 'exec')
            self.candidate = candidate
            (self.run/'candidate.py').write_bytes(candidate)
            (self.run/'patch.diff').write_text(''.join(difflib.unified_diff(
                self.original.decode().splitlines(True), candidate.decode().splitlines(True),
                fromfile='unsafe_demo.py.before', tofile='unsafe_demo.py.after')), encoding='utf-8')
            self.report['candidate_hash'] = digest(candidate)
            self.phase = 'staged'
        elif op == 'test' and self.phase == 'staged':
            self.test()
            self.phase = 'tested'
        elif op == 'apply' and self.phase == 'tested':
            self.apply()
            self.phase = 'applied'
        elif op == 'verify' and self.phase == 'applied':
            self.verify()
            self.phase = 'verified'
        elif op == 'rollback' and self.phase != 'idle':
            self.report['error'] = str(data['error'])[:2000]
            try:
                if self.journal.exists():
                    self.stop_app()
                    self.recover()
                    self.start_app()
                    self.wait_ready()
                    self.report['status'] = 'rolled_back'
                else:
                    self.report['status'] = 'refused'
            except Exception as exc:
                self.report.update(status='manual_intervention_required', rollback_error=str(exc))
            self.phase = 'failed'
        elif op == 'finish' and self.phase in ('verified', 'failed'):
            self.trace = data['trace']
            self.record({})
            self.phase = 'idle'
        else:
            raise ValueError('Operation not allowed in phase ' + self.phase)
        return self.report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=9002)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.host)
    if address.version != 4 or not address.is_private or address.is_unspecified:
        parser.error('Use the specific private IPv4 address of Kali')
    root = Path(__file__).resolve().parent
    with open(root/'.repair-agent.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker = Executor(root, args.host, args.port)
        for sig in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, lambda *_: sys.exit(0))
        try:
            worker.check_port()
            worker.recover()
            worker.start_app()
            worker.wait_ready()
            print(json.dumps({'type': 'ready'}), flush=True)
            while True:
                line = sys.stdin.buffer.readline(131073)
                if not line:
                    break
                if len(line) > 131072 or not line.endswith(b'\n'):
                    raise ValueError('Invalid message size')
                request = json.loads(line)
                try:
                    result = worker.command(request['op'], request.get('data', {}))
                    reply = {'id': request['id'], 'ok': True, 'data': result}
                except Exception as exc:
                    reply = {'id': request['id'], 'ok': False, 'error': str(exc)}
                print(json.dumps(reply), flush=True)
        finally:
            try:
                if worker.journal.exists():
                    worker.stop_app()
                    worker.recover()
            finally:
                worker.stop_app()


if __name__ == '__main__':
    main()
