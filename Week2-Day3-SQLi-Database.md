# Forensic Vulnerability Report: SQL Injection (SQLi) Authentication Bypass

## 1. Executive Summary
During the Week 2, Day 3 tactical evaluation of the local sandbox infrastructure, a critical SQL Injection (SQLi) vulnerability was identified and successfully verified within the user authentication pipeline. The application's backend constructs dynamic SQL queries by concatenating unsanitized user inputs directly into query execution blocks. An attacker can exploit this structural flaw to inject arbitrary database payloads, completely bypassing password checks and gaining unauthorized access as any administrative user.

---

## 2. Vulnerability Details
* **Vulnerability Type:** SQL Injection (SQLi) - Authentication Bypass
* **CWE Identifier:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
* **Target Component:** Administrative Login Endpoint (`/rest/user/login`)
* **Severity:** Critical
* **CVSS v3.1 Score:** 9.8 (Critical)
* **Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

---

## 3. Exploit Mechanics (Manual Injection & Scouting)
Per strict operational mandates, no automated security scanners were used[cite: 7]. Manual testing was performed on the target authentication interface within the isolated sandbox environment[cite: 7].

### A. Vulnerability Discovery (Scouting Phase)
By injecting a single quote (`'`) character into the username field, the SQL interpreter broke out of its string literal context, causing the application to return database syntax errors[cite: 7]. This behavior confirmed that the backend dynamically generates database commands without parameter isolation[cite: 7].

### B. Payload Formulation & Execution
The backend was executing a raw, dynamically formatted query similar to:
```sql
SELECT * FROM Users WHERE email = 'USER_INPUT' AND password = 'USER_INPUT';

By injecting the classic SQLi tautology payload ' OR 1=1 -- into the email field[cite: 7], the database logic was altered
SELECT * FROM Users WHERE email = '' OR 1=1 --' AND password = '...';

Intercepted HTTP Request
Using Burp Suite Repeater, the raw login request was modified and forwarded to the backend
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Connection: close

{
  "email": "admin@juice-sh.op' OR 1=1 --",
  "password": "arbitrary_password_text"
}

Observed Behavior
Expected Behavior: The server should reject the request as an invalid username and password combination.

Actual Behavior: The database interpreter evaluated 1=1 as always true, while the comment sequence (--) instructed the parser to discard the password checking logic entirely[cite: 7]. The backend returned an HTTP 200 OK status, establishing an active administrative login session
4. Architectural Remediation
Relying on string sanitization or simple string escaping is completely insufficient to prevent SQL Injection. The backend must enforce the use of Prepared Statements (Parameterized Queries)
Secure Remediation Directives
Prepared statements pre-compile the SQL structure on the database engine. User input is then bound to specific query parameters (? placeholders) and treated strictly as literal data, entirely preventing it from being executed as SQL code
Vulnerable Code
// INSECURE: Dynamically executing concatenated inputs
const query = `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`;
db.all(query, (err, rows) => { ... });
Secure Code Implementation
// SECURE: Enforcing Prepared Statements with Parameterized Query Logic
const secureQuery = 'SELECT id, email, role FROM Users WHERE email = ? AND password = ?';
const parameters = [req.body.email, req.body.password];

// Database interpreter parses parameters strictly as text variables
db.get(secureQuery, parameters, (err, row) => {
    if (err) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
    if (!row) {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    // Proceed to generate session context securely
    return res.status(200).json({ success: true, user: row });
});
