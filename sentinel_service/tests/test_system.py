import asyncio
import time
from pathlib import Path
import httpx
import pytest
from sentinel.core import Engine, Store, Settings, Event, sql_signal
from sentinel.web import create_apps
from lab_app import app as lab

async def healthy(): return True

def make(**kwargs):
    return Engine(Store(':memory:'), Settings(http_flood_enabled=True, **kwargs), healthy)

@pytest.mark.parametrize('query', ["q=' OR 1=1--", 'q=UNION%20SELECT%20name', 'q=%2527%2520OR%25201%253D1--', 'q=union/**/select name', 'q=pg_sleep(3)'])
def test_sql_encodings(query):
    assert sql_signal(Event(source_ip='192.0.2.1',query=query))

@pytest.mark.parametrize('query',["q=O'Reilly",'q=union of students','q=select a book','q=hello'])
def test_benign_inputs(query):
    assert sql_signal(Event(source_ip='192.0.2.1',query=query)) is None

def test_threshold_windows_and_dedup():
    e=make(ip_limit=3);v=Event(source_ip='192.0.2.1')
    assert e.observe(v) is None
    assert e.observe(v) is None
    assert e.metrics['requests']==1
    assert e.observe(Event(source_ip=v.source_ip)) is None
    assert e.observe(Event(source_ip=v.source_ip))=='http_flood'
    assert e.queue.qsize()==1
    e.sources[v.source_ip]['requests'].clear()
    assert e.observe(Event(source_ip=v.source_ip)) is None

def test_bounded_queue_and_memory():
    e=make(queue_size=1,max_sources=2)
    for i in range(1,5):e.observe(Event(source_ip=f'192.0.2.{i}',query="q=' OR 1=1--"))
    assert e.queue.qsize()==1 and len(e.sources)==2
    assert e.metrics['dropped_incidents']==3

def test_graph_applies_scoped_sql_and_rolls_back():
    async def run():
        e=make();e.observe(Event(source_ip='192.0.2.1',path='/products',query="q=' OR 1=1--"))
        out=await e.graph.ainvoke({'incident':e.queue.get_nowait()})
        assert out['incident']['status']=='mitigated'
        assert e.blocked_by_rule(Event(source_ip='192.0.2.8',path='/products',query="q=' OR 1=1--"))
        assert not e.blocked_by_rule(Event(source_ip='192.0.2.1',path='/products',query="q=O'Reilly"))
        assert e.store.rollback(out['rule']['id']) and not e.store.rules()
    asyncio.run(run())

def test_failed_post_health_causes_automatic_rollback():
    async def run():
        answers=iter([True,False])
        async def health():return next(answers)
        e=make();e.health=health;e.observe(Event(source_ip='192.0.2.1',query="q=' OR 1=1--"))
        result=await e.graph.ainvoke({'incident':e.queue.get_nowait()})
        assert result['incident']['status']=='rolled_back' and not e.store.rules()
    asyncio.run(run())

def test_unhealthy_precheck_escalates():
    async def run():
        e=make()
        async def bad():return False
        e.health=bad;e.observe(Event(source_ip='192.0.2.1',query="q=' OR 1=1--"))
        result=await e.graph.ainvoke({'incident':e.queue.get_nowait()})
        assert result['incident']['status']=='escalated' and not e.store.rules()
    asyncio.run(run())

def test_aggregate_flood_does_not_block_arbitrary_ip():
    async def run():
        e=make(global_limit=5,min_sources=5,ip_limit=100)
        for i in range(5):e.observe(Event(source_ip=f'192.0.2.{i+1}'))
        result=await e.graph.ainvoke({'incident':e.queue.get_nowait()})
        assert result['incident']['evidence']['scope']=='aggregate'
        assert result['incident']['status']=='escalated' and not e.store.rules()
    asyncio.run(run())

def test_expiry_and_persistence(tmp_path):
    p=str(tmp_path/'state.db');s=Store(p)
    r=dict(id='rule1',incident_id='i1',kind='source_block',source_ip='192.0.2.1',path='/',expires=time.time()+60)
    s.add_rule(r);s.db.close();reopened=Store(p)
    assert len(reopened.rules())==1
    reopened.db.execute('UPDATE rules SET expires=?',(time.time()-1,));reopened.db.commit()
    assert reopened.rules()==[]

def test_live_gateway_and_management():
    async def run():
        e=make(ip_limit=100)
        management,gateway=create_apps(e,'http://lab','a'*32,'b'*32,Path('website'),transport=httpx.ASGITransport(app=lab))
        async with management.router.lifespan_context(management):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway,client=('192.0.2.10',123)),base_url='http://gateway') as c, httpx.AsyncClient(transport=httpx.ASGITransport(app=management),base_url='http://management') as m:
                assert (await m.get('/api/state')).status_code==401
                assert (await m.get('/api/state',headers={'Authorization':'Bearer '+'b'*32})).status_code==401
                good=await c.get('/products',params={'q':'book'})
                assert good.status_code==200 and good.json()['products'][0]['name']=='book'
                bad=await c.get('/products',params={'q':"' OR 1=1--"},headers={'X-Forwarded-For':'1.1.1.1'})
                assert bad.status_code==403
                await asyncio.wait_for(e.queue.join(),3)
                d=e.snapshot()['incidents'][0]
                assert d['source_ip']=='192.0.2.10' and d['status']=='mitigated'
                assert (await c.get('/products',params={'q':'book'})).status_code==200
                for _ in range(5):assert (await c.post('/login',json={'username':'student','password':'incorrect'})).status_code==401
                await asyncio.wait_for(e.queue.join(),3)
                assert (await c.post('/login',json={'username':'student','password':'sentinel-lab-only'})).status_code==429
                assert (await c.get('/products',params={'q':'book'})).status_code==200
                state=(await m.get('/api/state',headers={'Authorization':'Bearer '+'a'*32})).json()
                assert len(state['incidents'])==2 and state['metrics']['requests']==10
                assert 'incorrect' not in str(state) and 'sentinel-lab-only' not in str(state)
                assert (await c.post('/login',content='a'*20000)).status_code==413
                rid=next(x['id'] for x in state['rules'] if x['kind']=='login_cooldown')
                assert (await m.post('/api/rules/'+rid+'/rollback',headers={'Authorization':'Bearer '+'a'*32})).status_code==200
                assert (await c.post('/login',json={})).status_code==429
                assert (await m.post('/api/events',json={},headers={'Authorization':'Bearer '+'b'*32})).status_code==422
                assert (await m.get('/')).status_code==200
    asyncio.run(run())

def test_source_flood_enforcement_and_other_source():
    async def run():
        e=make(ip_limit=4)
        m,g=create_apps(e,'http://lab','a'*32,'b'*32,Path('website'),transport=httpx.ASGITransport(app=lab))
        async with m.router.lifespan_context(m):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=g,client=('192.0.2.1',1)),base_url='http://gw') as c:
                for _ in range(3):assert (await c.get('/products')).status_code==200
                assert (await c.get('/products')).status_code==429
                await asyncio.wait_for(e.queue.join(),3)
                assert e.store.rules()[0]['kind']=='source_block'
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=g,client=('192.0.2.2',1)),base_url='http://gw') as c:
                assert (await c.get('/products')).status_code==200
    asyncio.run(run())

def test_login_success_is_not_failure():
    async def run():
        e=make(ip_limit=100)
        m,g=create_apps(e,'http://lab','a'*32,'b'*32,Path('website'),transport=httpx.ASGITransport(app=lab))
        async with m.router.lifespan_context(m):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=g,client=('192.0.2.1',1)),base_url='http://gw') as c:
                for _ in range(6):assert (await c.post('/login',json={'username':'student','password':'sentinel-lab-only'})).status_code==200
                assert e.queue.empty() and not e.snapshot()['incidents']
    asyncio.run(run())

def test_no_cross_client_cookie_leak():
    async def run():
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        upstream=FastAPI()
        @upstream.get('/health')
        def health():return {'ok':True}
        @upstream.get('/set')
        def set_cookie():
            r=JSONResponse({'ok':True});r.set_cookie('session','alice');return r
        @upstream.get('/read')
        def read(request:Request):return {'cookie':request.headers.get('cookie','')}
        e=make();m,g=create_apps(e,'http://lab','a'*32,'b'*32,Path('website'),transport=httpx.ASGITransport(app=upstream))
        async with m.router.lifespan_context(m):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=g,client=('192.0.2.1',1)),base_url='http://gw') as c:
                r=await c.get('/set');assert 'session=alice' in r.headers['set-cookie']
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=g,client=('192.0.2.2',1)),base_url='http://gw') as c:
                assert (await c.get('/read')).json()['cookie']==''
    asyncio.run(run())

def test_json_escape_sql_signature():
    e=Event(source_ip='192.0.2.1',body_text=r'{"q":"\u0027 OR 1=1--"}')
    assert sql_signal(e)
