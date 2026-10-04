"""Conservative Python/SQLite candidate generator. It never deploys a patch."""
import ast
import re
import string

MARK = '__SQL_VALUE_'
IDENT = r'[A-Za-z_][A-Za-z0-9_]*'


def pieces(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if MARK in node.value:
            raise ValueError('Reserved marker in SQL')
        return [node.value]
    if isinstance(node, ast.Name):
        return [node]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return pieces(node.left) + pieces(node.right)
    if isinstance(node, ast.JoinedStr):
        result = []
        for item in node.values:
            if isinstance(item, ast.FormattedValue):
                if item.conversion != -1 or item.format_spec is not None or not isinstance(item.value, ast.Name):
                    raise ValueError('Only unformatted variable values are supported')
                result.append(item.value)
            else:
                result.extend(pieces(item))
        return result
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        template = ast.literal_eval(node.left)
        args = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        if not isinstance(template, str) or re.search(r'%(?!s)', template):
            raise ValueError('Only %s interpolation is supported')
        parts = template.split('%s')
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
          and node.func.attr == 'format' and not node.keywords):
        template = ast.literal_eval(node.func.value)
        if not isinstance(template, str):
            raise ValueError('Expected literal format string')
        args, parts = node.args, ['']
        for literal, field, spec, conversion in string.Formatter().parse(template):
            parts[-1] += literal
            if field is not None:
                if field != '' or spec or conversion:
                    raise ValueError('Only plain {} format fields are supported')
                parts.append('')
    else:
        raise ValueError('Unsupported SQL construction')
    if MARK in template or len(parts) != len(args) + 1 or not all(isinstance(a, ast.Name) for a in args):
        raise ValueError('Only simple variable interpolation is supported')
    result = [parts[0]]
    for arg, tail in zip(args, parts[1:]):
        result.extend([arg, tail])
    return result


def parameterize(expression):
    values, text = [], ''
    for part in pieces(expression):
        if isinstance(part, str):
            text += part
        else:
            text += f'{MARK}{len(values)}__'
            values.append(part.id)
    if not values:
        raise ValueError('No interpolated values')
    column = IDENT + r'(?:\.' + IDENT + r')?'
    columns = r'(?:\*|' + column + r'(?:\s*,\s*' + column + r')*)'
    predicate = column + r"\s*(?:=|!=|<>)\s*'__SQL_VALUE_[0-9]+__'"
    grammar = (r'\s*SELECT\s+' + columns + r'\s+FROM\s+' + IDENT + r'\s+WHERE\s+'
               + predicate + r'(?:\s+(?:AND|OR)\s+' + predicate + r')*\s*;?\s*')
    if not re.fullmatch(grammar, text, re.I):
        raise ValueError('SQL shape requires manual review')
    for index in range(len(values)):
        text = text.replace(f"'{MARK}{index}__'", '?')
    return repr(text), '(' + ', '.join(values) + ',)'


def candidate_source(raw):
    tree = ast.parse(raw)
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    lines, edits = raw.splitlines(keepends=True), []
    def replace(node, replacement):
        begin = sum(map(len, lines[:node.lineno-1])) + node.col_offset
        end = sum(map(len, lines[:node.end_lineno-1])) + node.end_col_offset
        edits.append((begin, end, replacement.encode()))
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name) and call.func.value.id == 'db'
                and call.func.attr == 'execute'):
            continue
        # Skipped statements are NOT certified secure by this generator.
        if len(call.args) != 1 or call.keywords or isinstance(call.args[0], ast.Constant):
            continue
        expression = call.args[0]
        if isinstance(expression, ast.Name):
            statement = call
            while statement in parents and not isinstance(statement, ast.stmt):
                statement = parents[statement]
            parent = parents.get(statement)
            siblings = next((v for _, v in ast.iter_fields(parent) if isinstance(v, list) and statement in v), []) if parent else []
            pos = siblings.index(statement) if statement in siblings else 0
            previous = siblings[pos-1] if pos else None
            if not (isinstance(previous, ast.Assign) and len(previous.targets) == 1
                    and isinstance(previous.targets[0], ast.Name) and previous.targets[0].id == expression.id):
                raise ValueError('Query assignment must immediately precede execute; remove query logging between them')
            scope = statement
            while scope in parents and not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = parents[scope]
            reads = [n for n in ast.walk(scope) if isinstance(n, ast.Name) and n.id == expression.id and isinstance(n.ctx, ast.Load)]
            if len(reads) != 1:
                raise ValueError('Query variable has other uses')
            if isinstance(previous.value, ast.Constant):
                continue
            sql, params = parameterize(previous.value)
            replace(previous.value, sql)
            replace(call, f'db.execute({expression.id}, {params})')
        else:
            sql, params = parameterize(expression)
            replace(call, f'db.execute({sql}, {params})')
    result, last = raw, len(raw)
    for begin, end, replacement in sorted(edits, reverse=True):
        if end > last:
            raise ValueError('Overlapping edits')
        result = result[:begin] + replacement + result[end:]
        last = begin
    ast.parse(result)
    return result
