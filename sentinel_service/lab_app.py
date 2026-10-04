"""Local-only protected application with safe parameterized SQL."""
import secrets
import sqlite3
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(docs_url=None, redoc_url=None)

@app.get('/health')
def health():
    return {'status': 'ok'}

@app.get('/')
def index():
    return {'application': 'Sentinel protected lab', 'endpoints': ['/products?q=book', '/login', '/health']}

@app.get('/products')
def products(q: str = 'book'):
    with sqlite3.connect(':memory:') as db:
        db.executescript("CREATE TABLE products(id INTEGER, name TEXT); INSERT INTO products VALUES(1,'book'),(2,'pen');")
        rows = db.execute('SELECT id,name FROM products WHERE name = ?', (q,)).fetchall()
    return {'products': [{'id': i, 'name': n} for i, n in rows]}

@app.post('/login')
async def login(request: Request):
    try:
        body = await request.json()
        user, password = str(body.get('username','')), str(body.get('password',''))
    except Exception:
        return JSONResponse({'detail':'Invalid JSON'}, 400)
    # Demonstration credentials only. This endpoint issues no session or access token.
    ok = secrets.compare_digest(user, 'student') and secrets.compare_digest(password, 'sentinel-lab-only')
    return JSONResponse({'authenticated': ok, 'note':'Local lab only; no production session'}, 200 if ok else 401)
