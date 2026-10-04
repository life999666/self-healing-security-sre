"""Set non-secret Kali connection settings, preserving generated API tokens."""
import argparse
import ipaddress
from pathlib import Path
import re
from dotenv import set_key

parser = argparse.ArgumentParser()
parser.add_argument('--host', required=True)
parser.add_argument('--fingerprint', required=True)
parser.add_argument('--user', default='kali')
parser.add_argument('--lab-path', default='/home/kali/sentinel-five-agent-lab')
args = parser.parse_args()
address = ipaddress.ip_address(args.host)
if address.version != 4 or not address.is_private or address.is_unspecified:
    parser.error('Use the private IPv4 address of Kali')
if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', args.fingerprint.strip()):
    parser.error('Paste only the SHA256 fingerprint from Kali')
p = Path(__file__).resolve().parent / '.env'
if not p.exists():
    parser.error('Run python setup_env.py first')
for key, value in {'START_LAB': 'false', 'AUTO_SQL_REPAIR': 'true',
    'UPSTREAM_URL': f'http://{args.host}:9002', 'KALI_IP': args.host,
    'KALI_APP_PORT': '9002', 'KALI_USER': args.user, 'KALI_LAB_PATH': args.lab_path,
    'KALI_HOST_FINGERPRINT': args.fingerprint.strip()}.items():
    set_key(str(p), key, value)
print('Configured Windows agents for the Kali lab. No SSH password was saved.')
