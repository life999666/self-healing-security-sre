from pathlib import Path
import secrets
root = Path(__file__).resolve().parent
p = root/'.env'
if p.exists():
    print('.env already exists; kept your settings.')
else:
    template=(root/'.env.example').read_text()
    template=template.replace('GENERATE_ADMIN_TOKEN',secrets.token_urlsafe(32)).replace('GENERATE_COLLECTOR_TOKEN',secrets.token_urlsafe(32))
    p.write_text(template)
    print('Created .env with unique tokens. Open .env locally to copy ADMIN_TOKEN into the dashboard.')
