"""Kali execution primitives. No graph or patch generator lives here."""
import argparse
import ast
import difflib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time
import types
import uuid
from typing import TypedDict

SQL = 'SELECT id, name, price FROM products WHERE name = ?'
ATTACK = "' OR 1=1--"
MOUSE = {'products': [{'id': 3, 'name': 'Mouse', 'price': 500}]}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data):
    tmp = path.with_name(path.name + '.repair-tmp')
    with open(tmp, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if path.exists():
        os.chmod(tmp, path.stat().st_mode & 0o777)
    os.replace(tmp, path)


def save_json(path, data):
    atomic(path, (json.dumps(data, indent=2) + '\n').encode())




def load_app(path):
    module = types.ModuleType('unsafe_demo')
    module.__file__ = str(path)
    sys.modules['unsafe_demo'] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def regression_check(path):
    module = load_app(path)
    checks = [('normal', 'Mouse', MOUSE), ('injection', ATTACK, {'products': []}),
              ('apostrophe', "O'Reilly", {'products': []})]
    results = {}
    for name, query, expected in checks:
        try:
            results[name] = module.search_product(query) == expected
        except Exception:
            results[name] = False
    print('REPAIR_TEST_RESULT=' + json.dumps(results))
    return 0 if all(results.values()) else 1




class Worker:


    def recover(self):
        if not self.journal.exists():
            return
        pending = json.loads(self.journal.read_text())
        backup_path = (self.runs / pending['backup']).resolve()
        if not backup_path.is_relative_to(self.runs.resolve()):
            raise RuntimeError('Invalid backup location')
        backup = backup_path.read_bytes()
        if digest(backup) != pending['original_hash']:
            raise RuntimeError('Backup hash mismatch')
        current = digest(self.target.read_bytes())
        if current == pending['candidate_hash']:
            atomic(self.target, backup)
        elif current != pending['original_hash']:
            raise RuntimeError('Concurrent edit detected; backup retained for manual review')
        self.journal.unlink()

    def start_app(self):
        with socket.socket() as check:
            check.bind((self.host, self.port))
        self.log = open(self.runs / 'app.log', 'ab', buffering=0)
        self.child = subprocess.Popen(
            [sys.executable, str(self.root / 'worker_support.py'), '--app-child',
             '--host', self.host, '--port', str(self.port)],
            cwd=self.root, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)

    def stop_app(self):
        if self.child is not None:
            if self.child.poll() is None:
                os.killpg(self.child.pid, signal.SIGTERM)
                try:
                    self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(self.child.pid, signal.SIGKILL)
                    self.child.wait(timeout=5)
            self.child = None
        if self.log:
            self.log.close()
            self.log = None

    def healthy(self):
        import httpx
        if self.child is None or self.child.poll() is not None:
            return False
        try:
            with httpx.Client(trust_env=False, timeout=2) as client:
                response = client.get(f'http://{self.host}:{self.port}/health')
                return response.status_code == 200 and response.json() == {'status': 'ok'}
        except Exception:
            return False

    def wait_ready(self):
        for _ in range(30):
            if self.healthy():
                return
            if self.child is not None and self.child.poll() is not None:
                break
            time.sleep(0.2)
        raise RuntimeError('App did not become healthy; see repair-runs/app.log')

    def run_tests(self, source, log_name):
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--check', str(source)],
                                 cwd=self.root, capture_output=True, timeout=20)
        (self.run / log_name).write_bytes(process.stdout + process.stderr)
        prefix = b'REPAIR_TEST_RESULT='
        results = [line[len(prefix):] for line in process.stdout.splitlines() if line.startswith(prefix)]
        if len(results) != 1 or process.returncode not in (0, 1):
            raise RuntimeError('Regression process failed; inspect test logs')
        return json.loads(results[0])

    def investigate(self):
        self.original = self.target.read_bytes()
        self.report['original_hash'] = digest(self.original)
        baseline_path = self.run / 'baseline.py'
        baseline_path.write_bytes(self.original)
        self.report['baseline'] = self.run_tests(baseline_path, 'baseline-tests.log')
        if not self.report['baseline'].get('normal'):
            raise RuntimeError('Normal search is already broken; refusing automatic repair')


    def test(self):
        self.report['candidate_tests'] = self.run_tests(self.run / 'candidate.py', 'candidate-tests.log')
        if not all(self.report['candidate_tests'].values()):
            raise RuntimeError('Candidate failed regression tests; source left unchanged')

    def apply(self):
        if self.target.read_bytes() != self.original:
            raise RuntimeError('Source changed during repair; refusing overwrite')
        if self.candidate == self.original:
            self.report['status'] = 'already_safe'
            return
        backup = self.run / 'unsafe_demo.py.bak'
        backup.write_bytes(self.original)
        save_json(self.journal, {'backup': str(backup.relative_to(self.runs)),
                                'original_hash': digest(self.original),
                                'candidate_hash': digest(self.candidate)})
        self.stop_app()
        if self.target.read_bytes() != self.original:
            raise RuntimeError('Concurrent source edit; refusing overwrite')
        atomic(self.target, self.candidate)
        self.start_app()
        self.wait_ready()
        self.report['status'] = 'applied_pending_verification'

    def verify(self):
        import httpx
        self.wait_ready()
        with httpx.Client(trust_env=False, timeout=3) as client:
            for query, expected in [('Mouse', MOUSE), (ATTACK, {'products': []}),
                                    ("O'Reilly", {'products': []})]:
                response = client.get(f'http://{self.host}:{self.port}/products', params={'q': query})
                if response.status_code != 200 or response.json() != expected:
                    raise RuntimeError('Live HTTP regression check failed')
            for password, status in [('sentinel-lab-only', 200), ('wrong-demo-password', 401)]:
                response = client.post(f'http://{self.host}:{self.port}/login',
                    json={'username': 'student', 'password': password})
                if response.status_code != status:
                    raise RuntimeError('Login regression failed after SQL patch')
        if self.target.read_bytes() != self.candidate:
            raise RuntimeError('Source changed during verification')
        self.report['live_http_tests'] = 'passed'
        if self.report['status'] != 'already_safe':
            self.report['status'] = 'repaired'
        self.journal.unlink(missing_ok=True)

    def record(self, state):
        self.report.update(trace=self.trace, completed=time.time())
        save_json(self.run / 'report.json', self.report)
        save_json(self.runs / 'latest-report.json', self.report)
        return {'phase': 'record'}



def emit(data):
    print(json.dumps(data), flush=True)





if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', type=Path)
    parser.add_argument('--app-child', action='store_true')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9002)
    args = parser.parse_args()
    if args.check:
        raise SystemExit(regression_check(args.check))
    if not args.app_child:
        parser.error('Use executor.py; this file only runs checks or the app child')
    import uvicorn
    uvicorn.run(load_app(Path(__file__).resolve().parent / 'unsafe_demo.py').app,
                host=args.host, port=args.port, proxy_headers=False, access_log=False)
