"""Loopback SSH integration: real executor, HTTP backend and five-agent graph."""
import asyncio
import base64
import hashlib
import io
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid

import httpx
import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sentinel.core import Engine, Store, Settings
from sentinel.remote import KaliRepair
from sentinel.sql_patterns import candidate_source
from sentinel.web import create_apps

ROOT=Path(__file__).resolve().parents[1]

class Server(paramiko.ServerInterface):
    def __init__(self):self.exec_requested=threading.Event()
    def check_auth_password(self,user,password):
        return paramiko.AUTH_SUCCESSFUL if (user,password)==('kali','test-only') else paramiko.AUTH_FAILED
    def get_allowed_auths(self,user):return 'password'
    def check_channel_request(self,kind,channel_id):
        return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self,channel,command):
        self.exec_requested.set();return True

class SSHLab:
    def __init__(self,path):
        self.path=path
        shutil.copytree(ROOT/'kali_lab',path,ignore=shutil.ignore_patterns('__pycache__'))
        self.original=(path/'unsafe_demo.py').read_bytes()
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));self.app_port=sock.getsockname()[1]
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen()
        self.ssh_port=self.listener.getsockname()[1]
        raw=Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.OpenSSH,serialization.NoEncryption()).decode()
        self.key=paramiko.Ed25519Key(file_obj=io.StringIO(raw))
        self.pin='SHA256:'+base64.b64encode(hashlib.sha256(self.key.asbytes()).digest()).decode().rstrip('=')
        self.proc=None;self.transport=None;self.error=None
        self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
    def serve(self):
        try:
            sock,_=self.listener.accept();self.transport=paramiko.Transport(sock)
            self.transport.add_server_key(self.key)
            server=Server();self.transport.start_server(server=server)
            channel=self.transport.accept(10)
            if channel is None or not server.exec_requested.wait(5):return
            self.proc=subprocess.Popen([sys.executable,str(self.path/'executor.py'),'--host','127.0.0.1','--port',str(self.app_port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            def input_pump():
                try:
                    while True:
                        data=channel.recv(4096)
                        if not data:break
                        self.proc.stdin.write(data);self.proc.stdin.flush()
                finally:self.proc.stdin.close()
            def output_pump(stream,send):
                try:
                    while True:
                        data=stream.read(4096)
                        if not data:break
                        send(data)
                except (OSError,EOFError):pass
            threading.Thread(target=input_pump,daemon=True).start()
            outputs=[threading.Thread(target=output_pump,args=(self.proc.stdout,channel.sendall),daemon=True),threading.Thread(target=output_pump,args=(self.proc.stderr,channel.sendall_stderr),daemon=True)]
            for task in outputs:task.start()
            self.proc.wait(timeout=90)
            for task in outputs:task.join(2)
            channel.send_exit_status(self.proc.returncode);channel.close()
        except Exception as exc:self.error=exc
        finally:
            if self.transport:self.transport.close()
    def close(self):
        if self.transport:self.transport.close()
        self.listener.close();self.thread.join(15)
        if self.proc and self.proc.poll() is None:
            self.proc.terminate();self.proc.wait(10)

@pytest.fixture
def ssh_lab(tmp_path):
    if sys.platform=='win32':pytest.skip('Linux executor integration')
    lab=SSHLab(tmp_path/'lab')
    try:yield lab
    finally:lab.close()

def client(lab,pin=None):
    return KaliRepair('127.0.0.1',pin or lab.pin,str(lab.path),port=lab.app_port,ssh_port=lab.ssh_port)

def test_fingerprint_checked_before_password(ssh_lab):
    called=[];remote=client(ssh_lab,'SHA256:wrong')
    with pytest.raises(RuntimeError,match='fingerprint mismatch'):
        remote.connect(lambda:called.append(True) or 'test-only')
    assert not called

def test_five_agents_sql_and_brute_over_ssh(ssh_lab):
    remote=client(ssh_lab);remote.connect(lambda:'test-only')
    try:
        async def run():
            engine=Engine(Store(':memory:'),Settings(),repairer=remote)
            management,gateway=create_apps(engine,f'http://127.0.0.1:{ssh_lab.app_port}','a'*32,'b'*32,ROOT/'website')
            async with management.router.lifespan_context(management):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway,client=('192.0.2.1',1)),base_url='http://gateway') as browser:
                    assert (await browser.get('/products',params={'q':'Mouse'})).status_code==200
                    assert (await browser.get('/products',params={'q':"' OR 1=1--"})).status_code==403
                    await asyncio.wait_for(engine.queue.join(),40)
                    incident=engine.snapshot()['incidents'][0]
                    assert incident['status']=='repaired',incident
                    assert incident['source_repair']['controller']=='windows'
                    assert {step['node'] for step in incident['trace']}==set(engine.agent_activity)
                    for _ in range(5):
                        assert (await browser.post('/login',json={'username':'student','password':'wrong-demo'})).status_code==401
                    await asyncio.wait_for(engine.queue.join(),5)
                    assert (await browser.post('/login',json={'username':'student','password':'sentinel-lab-only'})).status_code==429
                    assert (await browser.get('/products',params={'q':'Mouse'})).status_code==200
                    brute=engine.snapshot()['incidents'][0]
                    assert brute['label']=='brute_force' and brute['status']=='mitigated'
                    assert brute['source_repair']['status']=='not_applicable'
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway,client=('192.0.2.2',2)),base_url='http://gateway') as other:
                    assert (await other.post('/login',json={'username':'student','password':'sentinel-lab-only'})).status_code==200
                assert 'wrong-demo' not in str(engine.snapshot())
        asyncio.run(run())
    finally:remote.close()
    assert (ssh_lab.path/'unsafe_demo.py').read_bytes()!=ssh_lab.original

def test_disconnect_restores_unverified_source(ssh_lab):
    remote=client(ssh_lab);remote.connect(lambda:'test-only')
    event={'id':str(uuid.uuid4()),'label':'sql_injection','path':'/products'}
    raw=base64.b64decode(remote.rpc('begin',event)['source'])
    remote.rpc('stage',{'source':base64.b64encode(candidate_source(raw)).decode()})
    remote.rpc('test');remote.rpc('apply')
    remote.close()
    assert (ssh_lab.path/'unsafe_demo.py').read_bytes()==ssh_lab.original
