"""Separate management plane and HTTP gateway; no packet-capture claim."""
import asyncio
import json
import secrets
from http.cookiejar import CookieJar, DefaultCookiePolicy
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from .core import Engine, Event

class RejectCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False

MAX_BODY = 16384
MAX_RESPONSE = 2 * 1024 * 1024
HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
       'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length'}

async def bounded_body(request):
    result = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                result.extend(chunk)
                if len(result) > MAX_BODY:
                    raise HTTPException(413, 'Request body exceeds 16 KiB prototype limit')
    except TimeoutError:
        raise HTTPException(408, 'Request body timeout')
    return bytes(result)


def create_apps(engine: Engine, upstream: str, admin_token: str, collector_token: str,
                web_dir: Path, allowed_origins=None, transport=None):
    parsed = urlsplit(upstream)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('UPSTREAM_URL must be a fixed HTTP(S) origin, without credentials, path, query or fragment')
    if len(admin_token) < 32 or len(collector_token) < 32 or admin_token == collector_token:
        raise ValueError('Use distinct ADMIN_TOKEN and COLLECTOR_TOKEN values, each at least 32 characters')
    client = httpx.AsyncClient(trust_env=False, base_url=upstream.rstrip('/'), timeout=5, follow_redirects=False,
                              cookies=CookieJar(policy=RejectCookies()),
                              limits=httpx.Limits(max_connections=engine.cfg.max_inflight), transport=transport)

    async def health():
        response = await client.get('/health')
        return response.status_code == 200
    engine.health = health

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(engine.worker())
        monitor = asyncio.create_task(engine.monitor_loop())
        yield
        monitor.cancel()
        try:
            await monitor
        except asyncio.CancelledError:
            pass
        # Let an in-flight source repair finish before closing its SSH executor.
        try:
            await asyncio.wait_for(engine.queue.join(), timeout=120)
        except TimeoutError:
            pass
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await client.aclose()

    management = FastAPI(title='Sentinel Team B Management', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    gateway = FastAPI(title='Sentinel Gateway', docs_url=None, redoc_url=None, openapi_url=None)
    if allowed_origins:
        management.add_middleware(CORSMiddleware, allow_origins=allowed_origins,
                                 allow_methods=['GET', 'POST'], allow_headers=['Authorization', 'Content-Type'])

    def token_check(expected):
        async def check(request: Request):
            value = request.headers.get('authorization', '')
            if not secrets.compare_digest(value, 'Bearer '+expected):
                raise HTTPException(401, 'Invalid token', headers={'WWW-Authenticate': 'Bearer'})
        return check
    admin, collector = token_check(admin_token), token_check(collector_token)

    @management.get('/api/health')
    async def management_health():
        return {'service': 'sentinel-team-b', 'status': 'running'}

    @management.get('/api/state', dependencies=[Depends(admin)])
    async def state():
        return engine.snapshot()

    @management.post('/api/rules/{rule_id}/rollback', dependencies=[Depends(admin)])
    async def rollback(rule_id: str):
        if not engine.store.rollback(rule_id):
            raise HTTPException(404, 'Active rule not found')
        return {'status': 'rolled_back', 'rule_id': rule_id}

    @management.post('/api/events', dependencies=[Depends(collector)])
    async def events(request: Request):
        body = await bounded_body(request)
        try:
            raw = json.loads(body)
            event = Event.model_validate(raw)
        except Exception:
            raise HTTPException(422, 'Invalid event; check the event schema in the guide')
        event.origin = 'collector'
        label = engine.observe(event)
        return {'accepted': True, 'label': label, 'queue_depth': engine.queue.qsize(),
                'note': 'Log ingestion is after the request. Enforcement applies only to traffic through this gateway.'}

    if web_dir.exists():
        management.mount('/', StaticFiles(directory=web_dir, html=True), name='dashboard')

    inflight = 0

    @gateway.api_route('/{path:path}', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
    async def proxy(request: Request, path: str):
        nonlocal inflight
        if inflight >= engine.cfg.max_inflight:
            engine.metrics['blocked'] += 1
            return JSONResponse({'detail': 'Gateway concurrency limit'}, 503, headers={'Retry-After':'2'})
        inflight += 1
        try:
            if len(request.url.query) > 8192 or len(request.url.path) > 2048:
                raise HTTPException(414, 'Request target too long')
            if request.headers.get('content-encoding', 'identity').lower() != 'identity':
                raise HTTPException(415, 'Compressed request bodies are unsupported')
            body = await bounded_body(request)
            # Uvicorn proxy_headers=False: ignore attacker-supplied forwarding headers.
            try:
                event = Event(source_ip=request.client.host, method=request.method,
                              path=request.url.path, query=request.url.query,
                              body_text=body.decode('utf-8', errors='replace'))
            except ValidationError:
                raise HTTPException(400, 'Invalid request path or client address')
            active = engine.blocked_by_rule(event)
            if active:
                engine.metrics['requests'] += 1; engine.metrics['blocked'] += 1
                return JSONResponse({'detail': 'Temporary security rule', 'rule_id': active['id']}, 429,
                                    headers={'Retry-After': str(max(1, int(active['expires']-__import__('time').time())))})
            # Detect before forwarding; login failures are attached after the upstream response.
            label = engine.observe(event)
            if label:
                engine.metrics['blocked'] += 1
                return JSONResponse({'detail': 'Security threshold matched', 'label': label},
                                    403 if label == 'sql_injection' else 429, headers={'Retry-After':'30'})
            if path.startswith('/') or '\\' in path:
                raise HTTPException(400, 'Invalid upstream path')
            connection_tokens = {x.strip().lower() for x in request.headers.get('connection', '').split(',')}
            headers = [(k, v) for k, v in request.headers.items()
                       if k.lower() not in HOP | connection_tokens
                       and not k.lower().startswith(('x-forwarded-', 'forwarded'))]
            # Fixed authority: never route to a client-supplied destination.
            target = httpx.URL(upstream).copy_with(path=request.url.path,
                                                  query=request.url.query.encode())
            try:
                async with client.stream(request.method, target, content=body, headers=headers) as response:
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > MAX_RESPONSE:
                            raise HTTPException(502, 'Upstream response exceeds 2 MiB prototype limit')
                    # 401 on the configured login route is the lab's trusted failure contract.
                    if event.path == engine.cfg.login_path and response.status_code == 401:
                        event.event_id += ':auth'
                        engine.observe(event, already_counted=True)
                    hop_response = HOP | {x.strip().lower() for x in response.headers.get('connection', '').split(',')}
                    # httpx decodes content; remove encoding and original content length.
                    out = Response(content=bytes(data), status_code=response.status_code)
                    for k, v in response.headers.multi_items():
                        if k.lower() not in hop_response | {'content-encoding'}:
                            out.headers.append(k, v)
                    return out
            except httpx.HTTPError:
                return JSONResponse({'detail': 'Upstream unavailable'}, 502)
        finally:
            inflight -= 1

    return management, gateway
