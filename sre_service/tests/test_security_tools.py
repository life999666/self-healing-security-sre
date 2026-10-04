from pathlib import Path

from security_tools import find_unsafe_sql, validate_security_fix


UNSAFE = '''
def search_product(q):
    db = object()
    query = "SELECT id FROM products WHERE name = '" + q + "'"
    return db.execute(query)
'''

SAFE = '''
def search_product(q):
    db = object()
    query = "SELECT id FROM products WHERE name = ?"
    return db.execute(query, (q,))
'''


def test_finds_dynamic_sql_variable():
    findings = find_unsafe_sql(UNSAFE)
    assert findings


def test_safe_parameterized_candidate_passes():
    result = validate_security_fix(UNSAFE, SAFE, "sql_injection")
    assert result["passed"] is True


def test_original_lab_fixture_is_detected():
    path = Path(__file__).resolve().parents[2] / "sentinel_service" / "kali_lab" / "unsafe_demo.py"
    findings = find_unsafe_sql(path.read_text(encoding="utf-8"))
    assert findings
