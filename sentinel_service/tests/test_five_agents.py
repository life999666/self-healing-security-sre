import asyncio
import importlib.util
from pathlib import Path
import shutil
import socket
import sqlite3
import sys
import time
import uuid
import pytest
from sentinel.core import Engine, Store, Settings, Event
from sentinel.remote import KaliRepair, RemoteFailure
from sentinel.sql_patterns import candidate_source
ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT/'kali_lab'
PATTERNS = [
    '''"SELECT id FROM products WHERE name = '" + q + "'"''',
    '''f"SELECT id FROM products WHERE name = '{q}'"''',
    '''"SELECT id FROM products WHERE name = '%s'" % q''',
    '''"SELECT id FROM products WHERE name = '{}'".format(q)''',
]

@pytest.mark.parametrize('pattern',PATTERNS)
@pytest.mark.parametrize('assigned',[False,True])
def test_multiple_patterns(pattern,assigned):
    body=('    query = '+pattern+'\n    return db.execute(query).fetchall()') if assigned else ('    return db.execute('+pattern+').fetchall()')
    fixed=candidate_source(('def search(db,q):\n'+body+'\n').encode())
    assert candidate_source(fixed)==fixed
    namespace={};exec(fixed,namespace)
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE products(id INTEGER,name TEXT)')
        db.execute('INSERT INTO products VALUES(1,?)',('Mouse',))
        for q,expected in [('Mouse',[(1,)]),("O'Reilly",[]),("' OR 1=1--",[])]:
            assert namespace['search'](db,q)==expected

@pytest.mark.parametrize('expression',[
    '''f"SELECT id FROM {q} WHERE name = 'x'"''',
    '''f"SELECT id FROM products WHERE name LIKE '%{q}%'"''',
    '''f"SELECT id FROM products WHERE name = '{q!r}'"'''])
def test_unsupported_refused(expression):
    with pytest.raises(ValueError):
        candidate_source(('def search(db,q):\n    return db.execute('+expression+')\n').encode())

def test_exact_five_nodes_and_boss_dispatch():
    async def run():
        async def healthy():return True
        e=Engine(Store(':memory:'),Settings(),healthy)
        assert set(e.graph.get_graph().nodes)-{'__start__','__end__'}=={'boss','detection','soc_analyst','repair','monitor'}
        e.observe(Event(source_ip='192.0.2.1',path='/products',query="q=' OR 1=1--"))
        d=(await e.graph.ainvoke({'incident':e.queue.get_nowait()}))['incident']
        assert {t['node'] for t in d['trace']}==set(e.agent_activity)
        assert [t['outcome'] for t in d['trace'] if t['node']=='Boss Agent' and t['outcome'].startswith('Dispatch')]==['Dispatch detection','Dispatch soc_analyst','Dispatch repair','Dispatch monitor']
        assert d['status']=='mitigated' and d['source_repair']['status']=='not_configured'
        assert e.snapshot()['enabled_attacks']==['sql_injection','brute_force']
        for _ in range(70):assert e.observe(Event(source_ip='192.0.2.2',path='/normal')) is None
    asyncio.run(run())

def test_brute_scope_expiry():
    async def run():
        async def healthy():return True
        e=Engine(Store(':memory:'),Settings(),healthy)
        for _ in range(5):e.observe(Event(source_ip='192.0.2.1',path='/login',status=401,auth_failed=True))
        d=(await e.graph.ainvoke({'incident':e.queue.get_nowait()}))['incident']
        assert d['source_repair']['status']=='not_applicable'
        assert e.blocked_by_rule(Event(source_ip='192.0.2.1',path='/login'))
        assert not e.blocked_by_rule(Event(source_ip='192.0.2.2',path='/login'))
        assert not e.blocked_by_rule(Event(source_ip='192.0.2.1',path='/products'))
        e.store.db.execute('UPDATE rules SET expires=?',(time.time()-1,));e.store.db.commit()
        assert not e.blocked_by_rule(Event(source_ip='192.0.2.1',path='/login'))
        assert e.snapshot()['incidents'][0]['status']=='expired'
    asyncio.run(run())

def test_monitor_without_incident():
    async def run():
        async def healthy():return True
        e=Engine(Store(':memory:'),Settings(),healthy)
        task=asyncio.create_task(e.monitor_loop());await asyncio.sleep(.02);task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        assert e.snapshot()['monitor']['healthy'] is True
    asyncio.run(run())

@pytest.fixture
def executor(tmp_path):
    if sys.platform=='win32':pytest.skip('Kali lifecycle test requires Linux')
    shutil.copytree(LAB,tmp_path/'lab',ignore=shutil.ignore_patterns('__pycache__'))
    sys.path.insert(0,str(tmp_path/'lab'))
    spec=importlib.util.spec_from_file_location('test_executor',tmp_path/'lab'/'executor.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    worker=mod.Executor(tmp_path/'lab','127.0.0.1',port)
    worker.start_app();worker.wait_ready()
    try:yield worker
    finally:worker.stop_app();sys.path.pop(0)

def direct_client(worker):
    client=KaliRepair('127.0.0.1','unused','unused')
    def rpc(op,data=None):
        try:return worker.command(op,data or {})
        except Exception as exc:raise RemoteFailure(str(exc)) from exc
    client.rpc=rpc
    return client

def event():return {'id':str(uuid.uuid4()),'label':'sql_injection','path':'/products'}

def test_real_source_repair(executor):
    client=direct_client(executor)
    report=client.repair(event())
    assert report['status']=='repaired'
    assert all(report['candidate_tests'].values())
    assert report['live_http_tests']=='passed' and report['controller']=='windows'
    assert client.repair(event())['status']=='already_safe'
    assert not executor.journal.exists()

def test_failed_verification_rolls_back(executor,monkeypatch):
    original=executor.target.read_bytes()
    def fail():raise RuntimeError('Forced verification failure')
    monkeypatch.setattr(executor,'verify',fail)
    assert direct_client(executor).repair(event())['status']=='rolled_back'
    assert executor.target.read_bytes()==original and executor.healthy()

def test_concurrent_edit_preserved(executor,monkeypatch):
    original_test=executor.test
    def changed():
        original_test()
        executor.target.write_bytes(executor.target.read_bytes()+b'\n# concurrent edit\n')
    monkeypatch.setattr(executor,'test',changed)
    assert direct_client(executor).repair(event())['status']=='refused'
    assert executor.target.read_bytes().endswith(b'# concurrent edit\n')
