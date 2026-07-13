# Friday Crucible Defense & Weekend VAPT Project Initiation

## 1. Friday Audit Prep & Validation
As we close Week 1, Day 5 of the 3-Month Bootcamp, this entry documents the forensic verification of my Week 1 vulnerability reports prior to the Live Teardown panel. All submitted artifacts have been audited against strict production reproduction criteria.

### Core Self-Audit Checklist
* **Day 1 (Stored XSS):** Verified context-aware output encoding logic (`&lt;`, `&gt;` replacements) and execution pathways.
* **Day 2 (SQL Injection Bypass):** Audited database payload bounds (`' OR 1=1 --`) and verified pre-compiled SQL parameter isolation.
* **Day 3 (JWT Signature Manipulation):** Validated byte-level Base64 structures and verified express-jwt signature verification wrapper rules.
* **Day 4 (Brute-Force & Rate Limiting):** Reviewed local loopback Intruder parameters and mathematically verified the express-rate-limit 5 attempts / 15-minute window threshold policy.

---

## 2. Theoretical Defense: Remediation & Algorithm Audits
In preparation for the Al Defense interrogation and Mentor review, the underlying mechanics of my remediation defenses are documented below:

### A. The Cryptographic Truth Behind JWT Verification
When a node server executes `jwt.verify(token, SECRET, { algorithms: ['HS256'] })`[cite: 3]:
1. **Header Parsing:** It extracts the algorithms block. By explicitly enforcing `['HS256']`[cite: 3], the library completely ignores and rejects any `"alg": "none"` manipulation attempts[cite: 2, 3].
2. **Signature Regeneration:** The server takes the incoming `Header` and `Payload` blocks, hashes them using the pre-configured `JWT_SECRET_KEY` on the backend, and compares this newly generated hash against the incoming `Signature` string[cite: 2, 3]. If they mismatch or the signature is missing, the request is rejected instantly[cite: 2, 3].

### B. Token-Bucket vs. Fixed-Window Rate Limiting Algorithms
* **Fixed-Window (Used in our Day 4 Express Middleware):** divides time into strict blocks (e.g., 15 minutes)[cite: 3, 4]. It increments a counter for every request from an IP[cite: 3, 4]. Once the counter hits 5, further requests are blocked until the window resets[cite: 3, 4]. 
* **Token-Bucket:** A bucket is filled with tokens at a constant, mathematically defined rate. Each incoming request consumes one token. If the bucket runs dry of tokens, incoming requests are dropped or queued. This prevents burst traffic spikes from exhausting server memory and processor cores.

---

## 3. Weekend VAPT Sprint Blueprint
* **VAPT Timeline:** Commencing Friday 12:00 PM – Due Monday 9:00 AM sharp.
* **Testing Scope:** Authorized Red Team access restricted strictly to the designated ProSensia vulnerable sandbox environment.
* **Minimum Mandated Deliverables:** 3 unique, documented security flaws (e.g., Session Hijacking, SQL Injection, Credential Stuffing) mapped directly into Jira-style tickets with working secure patch code blocks.

---
*Status: Pre-requisites validated. Local proxy environments mapped. Ready for immediate live-environment scanning.*
