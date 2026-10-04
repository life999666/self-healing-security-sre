import sqlite3
from fastapi import FastAPI
from fastapi.responses import JSONResponse
app = FastAPI()
@app.get('/health')
def health():
    return {'status': 'ok'}
@app.get('/products')
def search_product(q: str = 'Laptop'):
    db = sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price INTEGER)')
        db.executemany('INSERT INTO products VALUES (?, ?, ?)', [(1, 'Laptop', 50000), (2, 'Keyboard', 1500), (3, 'Mouse', 500)])
        query = (
            "SELECT id, name, price FROM products "
            "WHERE name = '" + q + "'"
        )
        cursor = db.execute(query)
        rows = cursor.fetchall()
        return {'products': [{'id': r[0], 'name': r[1], 'price': r[2]} for r in rows]}
    except sqlite3.Error:
        return JSONResponse(status_code=400, content={'message': 'Invalid SQL query'})
    finally:
        db.close()

from fastapi import Request
import secrets

@app.get('/')
def home():
    return {'lab': 'Team B SQL and brute force learning lab', 'routes': ['/products?q=Mouse', '/login', '/health']}

@app.post('/login')
async def login(request: Request):
    try:
        body = await request.json()
        username, password = str(body.get('username', '')), str(body.get('password', ''))
    except Exception:
        return JSONResponse({'detail': 'Invalid JSON'}, status_code=400)
    # Public learning credentials. No session or real account is created.
    ok = secrets.compare_digest(username, 'student') and secrets.compare_digest(password, 'sentinel-lab-only')
    return JSONResponse({'authenticated': ok, 'lab_only': True}, status_code=200 if ok else 401)
