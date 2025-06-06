## **⚔️ Practical Length-Extension Attack Demo (on SHA-256)**

### **🧠 Scenario**
1. Server signs a message using:

```
hash = SHA256(secret || message)
```

2. Attacker knows:
    - message
    - hash (digest of secret || message)
    - Not the secret
3. Attacker wants to forge:
    - message + malicious_data
    - And produce a valid hash that the server will accept — **without knowing the secret**.