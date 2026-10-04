"""Small, bounded demonstrations against this project's local gateway only."""
import argparse
import time
import httpx

parser=argparse.ArgumentParser()
parser.add_argument('attack',choices=['sql','brute'])
args=parser.parse_args()
with httpx.Client(base_url='http://127.0.0.1:8080',trust_env=False,timeout=10) as client:
    if args.attack=='sql':
        response=client.get('/products',params={'q':"' OR 1=1--"})
        print('SQL lab request:',response.status_code,response.text)
        print('Watch the dashboard for all five agent decisions and the separate source repair result.')
    else:
        for attempt in range(1,7):
            response=client.post('/login',json={'username':'student','password':'wrong-demo-password'})
            print('Failed-login demonstration',attempt,': HTTP',response.status_code)
            time.sleep(1)
        print('Expected: initial 401 responses, then 429. Check the brute-force incident in the dashboard.')
    response=client.get('/products',params={'q':'Mouse'})
    print('Normal product search:',response.status_code)
