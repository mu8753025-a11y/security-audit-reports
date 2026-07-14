# Forensic Vulnerability Report: Cross-Site Scripting (XSS) & Input Sanitization

## 1. Executive Summary
During the Week 2, Day 2 tactical audit of the local sandbox tier, critical Cross-Site Scripting (XSS) vulnerabilities (both Reflective and Stored) were identified and successfully verified. The web application renders user-supplied input directly in the client's browser context without performing contextual output encoding or strict sanitization. This allows an attacker to inject malicious JavaScript payloads that execute arbitrary commands within the user's session context.

---

## 2. Vulnerability Details
* **Vulnerability Type:** Cross-Site Scripting (Reflective & Stored XSS)
* **CWE Identifier:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
* **Target Component:** Main Search Bar (Reflective) and User Profile / Comment Section (Stored)
* **Severity:** High (Reflective) / Critical (Stored)
* **CVSS v3.1 Score:** 8.2 (High) / 8.7 (High-to-Critical)
* **Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N

---

## 3. Exploit Mechanics (Manual PoC Execution)
Per the "No Malware" rule of engagement, testing was strictly confined to harmless validation payloads using `alert()` and execution was conducted safely in the local loopback environment.

### A. Reflective XSS (Search Bar Parameter)
The search input parameter was found to dynamically echo values directly back into the search results page without sanitation[cite: 6].

* **Intercepted GET Request:**
  ```http
  GET /rest/products/search?q=%3Cscript%3Ealert('XSS-Reflected')%3C/script%3E HTTP/1.1
  Host: localhost:3000
  Connection: close
  Observed Behavior: The browser immediately processed the query string as executable code, triggering the script block and rendering the alert dialogue box
  B. Stored XSS (User Profile/Comments)
  An injection point was located in the persistent profile comment field, where payloads are saved directly to the database and executed on every subsequent page render
  Intercepted POST Payload:

  POST /api/Comments HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "message": "<img src=x onerror=alert('XSS-Stored')>",
  "author": "anonymous"
}
Observed Behavior: When any user visited the compromised comment page, the database served the unfiltered payload, and the browser executed the onerror JavaScript handler

4. Architectural Remediation
   Simply filtering or stripping <script> tags is highly fragile as attackers can bypass filters using alternative tags (e.g., <img> or <iframe>)[cite: 6]. Proper security requires Context-Aware Output Encoding and robust server-side sanitization libraries[cite: 6].

Secure Remediation Directives
Context-Aware Encoding: Ensure that all user inputs are encoded (e.g., converting < to &lt; and > to &gt;) before displaying them to prevent the browser from parsing them as HTML tags[cite: 6].

Sanitization Library: Implement backend validation using trusted, battle-tested libraries such as DOMPurify to safely strip malicious elements while preserving safe text.

Simply filtering or stripping <script> tags is highly fragile as attackers can bypass filters using alternative tags (e.g., <img> or <iframe>)[cite: 6]. Proper security requires Context-Aware Output Encoding and robust server-side sanitization libraries[cite: 6].

Secure Remediation Directives
Context-Aware Encoding: Ensure that all user inputs are encoded (e.g., converting < to &lt; and > to &gt;) before displaying them to prevent the browser from parsing them as HTML tags[cite: 6].

Sanitization Library: Implement backend validation using trusted, battle-tested libraries such as DOMPurify to safely strip malicious elements while preserving safe text[cite: 6].

// Secured Backend Implementation using DOMPurify & JSDOM (Node.js/Express)
const express = require('express');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const app = express();

app.post('/api/Comments', (req, res) => {
    const rawUserMessage = req.body.message;

    // Hardening Strategy: Sanitize incoming HTML markup structurally
    const safeSanitizedMessage = DOMPurify.sanitize(rawUserMessage);

    // Save safeSanitizedMessage safely to the database
    Database.saveComment({
        message: safeSanitizedMessage,
        author: req.body.author
    });

    return res.status(201).json({ success: true, data: safeSanitizedMessage });
});
