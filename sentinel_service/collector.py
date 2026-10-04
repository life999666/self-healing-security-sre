"""Tail normalized JSONL produced by your own application; no packet capture."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import httpx
from dotenv import load_dotenv
from sentinel.core import Event

async def tail(path,from_start):
    load_dotenv(Path(__file__).resolve().parent/'.env')
    token=os.getenv('COLLECTOR_TOKEN','')
    if len(token)<32:raise SystemExit('Configure COLLECTOR_TOKEN first.')
    offset=0 if from_start else path.stat().st_size
    pending=b'';identity=None;discarding=False
    async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
        while True:
            try:
                st=path.stat();current=(st.st_dev,st.st_ino)
                if (identity is not None and identity!=current) or st.st_size<offset:
                    offset=0;pending=b'';discarding=False
                identity=current
                with path.open('rb') as f:
                    f.seek(offset);chunk=f.read(65536);offset=f.tell()
                for part in chunk.splitlines(keepends=True):
                    pending+=part
                    if len(pending)>32768:pending=b'';discarding=True
                    if not part.endswith(b'\n'):continue
                    if discarding:discarding=False;pending=b'';print('Skipped oversized line');continue
                    line=pending;pending=b''
                    try:
                        raw=json.loads(line);e=Event.model_validate(raw)
                        # Send normalized input once; no application tokens or headers included.
                        data=e.model_dump();data['body_text']=e.body_text;data['origin']='collector'
                        for attempt in range(3):
                            try:
                                r=await client.post('http://127.0.0.1:8000/api/events',json=data,
                                    headers={'Authorization':'Bearer '+token});r.raise_for_status();break
                            except httpx.HTTPError:
                                if attempt==2:raise
                                await asyncio.sleep(1)
                        print('Event accepted:',e.event_id)
                    except Exception as error:
                        print('Line not delivered:',type(error).__name__)
                await asyncio.sleep(.25)
            except FileNotFoundError:
                await asyncio.sleep(1)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('--from-start',action='store_true');a=p.parse_args()
    try:asyncio.run(tail(a.file,a.from_start))
    except KeyboardInterrupt:pass
