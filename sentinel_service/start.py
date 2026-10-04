"""Start the dashboard, gateway and optional lab in one Windows-friendly process."""
import asyncio
import os
import signal
import getpass
from contextlib import contextmanager
from pathlib import Path
from dotenv import load_dotenv
import uvicorn
from sentinel.core import Engine, Store, Settings
from sentinel.web import create_apps

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')

def integer(name, default):
    return int(os.getenv(name, str(default)))

class Server(uvicorn.Server):
    @contextmanager
    def capture_signals(self):
        yield

async def main():
    cfg = Settings(ip_limit=integer('IP_LIMIT',60), global_limit=integer('GLOBAL_LIMIT',300),
                   min_sources=integer('MIN_SOURCES',5), login_limit=integer('LOGIN_LIMIT',5),
                   flood_window=integer('FLOOD_WINDOW',10), login_window=integer('LOGIN_WINDOW',60),
                   rule_ttl=integer('RULE_TTL',120), login_path=os.getenv('LOGIN_PATH','/login'),
                   http_flood_enabled=os.getenv('ENABLE_HTTP_FLOOD','false').lower() == 'true',
                   llm_model=os.getenv('OLLAMA_MODEL',''), ollama_url=os.getenv('OLLAMA_URL','http://127.0.0.1:11434'))
    (ROOT/'data').mkdir(exist_ok=True)
    repairer = None
    if os.getenv('AUTO_SQL_REPAIR', 'false').lower() == 'true':
        from sentinel.remote import KaliRepair
        kali_ip = os.environ['KALI_IP']
        kali_port = integer('KALI_APP_PORT', 9002)
        if os.getenv('START_LAB', 'true').lower() == 'true':
            raise ValueError('Set START_LAB=false when using the Kali executor')
        if os.getenv('UPSTREAM_URL', '').rstrip('/') != f'http://{kali_ip}:{kali_port}':
            raise ValueError('UPSTREAM_URL must match the configured Kali app address')
        repairer = KaliRepair(kali_ip, os.environ['KALI_HOST_FINGERPRINT'],
            os.getenv('KALI_LAB_PATH', '/home/kali/sentinel-five-agent-lab'),
            user=os.getenv('KALI_USER', 'kali'), port=kali_port)
        await asyncio.to_thread(repairer.connect, lambda: getpass.getpass('Kali SSH password (hidden): '))
        print('Kali executor ready. All five LangGraph agents run in Windows.')
    incident_sink = None
    if os.getenv('SRE_BRIDGE_ENABLED', 'false').lower() == 'true':
        from sentinel.sre_bridge import SREBridge
        incident_sink = SREBridge(
            os.getenv('SRE_BRIDGE_URL', 'http://127.0.0.1:8101'),
            os.environ['SRE_BRIDGE_TOKEN'],
            timeout_seconds=float(os.getenv('SRE_BRIDGE_TIMEOUT', '180')),
        )
        print('SRE remediation bridge enabled.')

    engine = Engine(Store(str(ROOT/'data'/'sentinel.db')), cfg, repairer=repairer, incident_sink=incident_sink)
    origins = [x.strip() for x in os.getenv('ALLOWED_ORIGINS','').split(',') if x.strip()]
    management, gateway = create_apps(engine, os.getenv('UPSTREAM_URL','http://127.0.0.1:9000'),
        os.getenv('ADMIN_TOKEN',''), os.getenv('COLLECTOR_TOKEN',''), ROOT/'website', origins)
    servers = [Server(uvicorn.Config(management,host='127.0.0.1',port=8000,proxy_headers=False,access_log=False)),
               Server(uvicorn.Config(gateway,host=os.getenv('GATEWAY_HOST','127.0.0.1'),port=8080,
                                             proxy_headers=False,access_log=False,limit_concurrency=100))]
    if os.getenv('START_LAB','true').lower() == 'true':
        lab_mode = os.getenv('LOCAL_LAB_MODE', 'safe').lower()
        if lab_mode == 'unsafe':
            # Local-loopback learning mode only. The intentionally vulnerable app
            # is the same source file inspected by the SRE remediation service.
            import importlib.util
            lab_path = ROOT / 'kali_lab' / 'unsafe_demo.py'
            spec = importlib.util.spec_from_file_location('sentinel_local_unsafe_demo', lab_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            app = module.app
            print('Local lab mode: UNSAFE learning fixture behind Sentinel gateway.')
        elif lab_mode == 'safe':
            from lab_app import app
            print('Local lab mode: safe parameterized-SQL fixture.')
        else:
            raise ValueError("LOCAL_LAB_MODE must be 'safe' or 'unsafe'")
        servers.append(Server(uvicorn.Config(app,host='127.0.0.1',port=9000,proxy_headers=False,access_log=False)))
    def stop(signum, frame):
        for server in servers:
            server.should_exit = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print('Dashboard: http://127.0.0.1:8000 | Protected gateway: http://127.0.0.1:8080')
    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        for s in servers:
            s.should_exit = True
        if repairer is not None:
            await asyncio.to_thread(repairer.close)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
