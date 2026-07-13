# Forensic Vulnerability Report: JWT Authentication Bypass (None Algorithm Exploitation)

## 1. Executive Summary
During the Week 1, Day 3 tactical security assessment of the local sandbox environment, a critical stateless authentication bypass vulnerability was identified within the session management tier. The application utilizes JSON Web Tokens (JWT) for user tracking but fails to strictly validate cryptographic signatures on the backend. An attacker can exploit this architectural flaw to manually forge identity payloads, modify user access controls, and achieve full administrative privilege escalation.

---

## 2. Vulnerability Details
* **Vulnerability Type:** Cryptographic Failure / Authentication Bypass (JWT Manipulation)
* **CWE Identifier:** CWE-287 (Improper Authentication) / CWE-347 (Improper Verification of Cryptographic Signature)
* **Target Component:** Session Management Framework / API Authorization Headers
* **Severity:** Critical
* **CVSS v3.1 Score:** 9.8 (Critical)
* **Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

---

## 3. Exploit Mechanics (Byte-Level Manual Manipulation)
Per strict operational mandates, no automated token-forging extensions were utilized. Token manipulation was executed manually at the raw byte-level inside Burp Repeater to analyze the exact structural parsing of the back-end decoder.

A standard JSON Web Token consists of three Base64URL-encoded components separated by dots: `Header.Payload.Signature`.

### Intercepted HTTP Request (Standard User Profile)
Upon logging in as a standard user, the following JWT structure was intercepted inside the Authorization header:
```http
GET /api/Users/whoami HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MzIsImVtYWlsIjoianVzdC11c2VyQGp1aWNlLXNoLm9wIiwicm9sZSI6ImN1c3RvbWVyIn0.[SignatureBytes]
Manual Token Forgery Strategy
Header Manipulation: The algorithm parameter ("alg": "HS256") was altered to "alg": "none". This instructs the backend parser to bypass the cryptographic signature check phase completely.

Payload Modification: The identity parameter ("role": "customer") was modified to "role": "admin", and the context target email was pointed directly toward the primary administrator account profile.

Signature Removal: Because the algorithm was downgraded to none, the trailing signature block was entirely stripped, leaving the closing trailing dot (.) intact.
Forged HTTP Request

GET /api/Users/whoami HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9.
Observed Behavior
Expected Behavior: The backend API wrapper should recognize that the cryptographic validation mechanism has been stripped, instantly dropping the connection parameters with an HTTP 401 Unauthorized block.

Actual Behavior: The application server accepted the un-signed token layout verbatim, evaluated the raw JSON parameters under the none logic sequence, and returned an HTTP 200 state, effectively executing privilege escalation to the global database administrator tier.

4. Architectural Remediation
Simply validating parameters on the web framework surface is completely insecure. The server-tier session decoder pipeline must be hardened with proper defensive verification models:

Secure Remediation Directives
Banning the 'None' Primitive: The back-end JWT decoding libraries must explicitly block or disable acceptance of the "alg": "none" header parameter during runtime API calls.
Strict Signature Validation Enforcement: Every stateless API processing node must strictly validate incoming request signatures against a securely isolated asymmetric or symmetric Secret Key structure before evaluating any underlying JSON claims.

// Secured Node.js / Express Security Guard-Rail Architecture
const jwt = require('jsonwebtoken');

function verifySessionToken(request, response, next) {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return response.sendStatus(401);

    // Hardening Strategy: Enforcing explicit algorithm validation profiles
    jwt.verify(token, process.env.JWT_SECRET_KEY, { algorithms: ['HS256'] }, (err, authorizedProfile) => {
        if (err) return response.sendStatus(403); // Rejects altered or 'none' headers instantly
        request.user = authorizedProfile;
        next();
    });
}
