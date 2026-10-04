"""Deterministic source inspection and validation for security remediation.

The LLM may explain and propose a repair, but these checks decide whether a
SQL-injection repair is allowed to proceed to a Pull Request.
"""
from __future__ import annotations

import ast
from pathlib import Path


def read_source(path: str) -> str:
    target = Path(path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Target source file not found: {target}")
    if target.suffix.lower() != ".py":
        raise ValueError("Only Python source files are supported in this prototype")
    return target.read_text(encoding="utf-8")


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def find_unsafe_sql(code: str) -> list[str]:
    """Return conservative findings for dynamic SQL passed to ``*.execute``.

    This is intentionally narrow. It does not claim to find every SQL injection
    vulnerability. It catches the patterns used by the supplied Sentinel lab and
    similar direct string-interpolation cases.
    """
    tree = ast.parse(code)
    dynamic_vars: dict[str, int] = {}
    findings: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if _is_dynamic_string(node.value):
                dynamic_vars[node.targets[0].id] = getattr(node, "lineno", 0)

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany"}
            and node.args
        ):
            continue

        first = node.args[0]
        line = getattr(node, "lineno", 0)
        if _is_dynamic_string(first):
            findings.append(f"line {line}: dynamic SQL expression passed directly to {node.func.attr}()")
        elif isinstance(first, ast.Name) and first.id in dynamic_vars:
            findings.append(
                f"line {line}: {node.func.attr}() uses dynamic SQL variable '{first.id}' "
                f"created near line {dynamic_vars[first.id]}"
            )

    return findings


def _function_names(tree: ast.AST) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def validate_security_fix(original_code: str, fixed_code: str, attack_type: str) -> dict:
    errors: list[str] = []

    try:
        original_tree = ast.parse(original_code)
    except SyntaxError as exc:
        return {"passed": False, "errors": [f"Original source is invalid Python: {exc}"], "message": "Validation failed"}

    try:
        fixed_tree = ast.parse(fixed_code)
    except SyntaxError as exc:
        return {
            "passed": False,
            "errors": [f"Generated fix has syntax error at line {exc.lineno}: {exc.msg}"],
            "message": "Validation failed",
        }

    missing = _function_names(original_tree) - _function_names(fixed_tree)
    if missing:
        errors.append(f"Generated fix removed existing functions: {sorted(missing)}")

    for node in ast.walk(fixed_tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            errors.append("Generated fix contains a bare except: clause")

    if attack_type == "sql_injection":
        before = find_unsafe_sql(original_code)
        after = find_unsafe_sql(fixed_code)
        if not before:
            errors.append("No supported unsafe SQL construction was confirmed in the original source")
        if after:
            errors.extend(f"Unsafe SQL remains: {item}" for item in after)

        # If we are repairing a confirmed dynamic SQL use, require at least one
        # parameterized execute call in the candidate.
        parameterized = False
        for node in ast.walk(fixed_tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and len(node.args) >= 2
            ):
                parameterized = True
                break
        if before and not parameterized:
            errors.append("No parameterized execute(query, params) call was found in the generated fix")

    return {
        "passed": not errors,
        "errors": errors,
        "message": "Security validation passed" if not errors else f"Security validation failed with {len(errors)} issue(s)",
    }
