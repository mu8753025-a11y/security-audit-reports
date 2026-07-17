# Forensic Vulnerability Report: Insecure Direct Object Reference (IDOR)

## 1. Executive Summary
During the Week 2, Day 4 tactical review of the localized sandbox environment, a critical Broken Access Control flaw in the form of an Insecure Direct Object Reference (IDOR) vulnerability was identified and verified. The application uses predictable, sequential integer identifiers to reference user accounts and order records within API endpoints but fails to execute server-side authorization checks. Consequently, any authenticated user can view private data belonging to other users simply by manipulating the object identifiers in the application requests.

---

## 2. Vulnerability Details
* **Vulnerability Type:** Insecure Direct Object Reference (IDOR) / Broken Access Control
* **CWE Identifier:** CWE-639 (Access Control Bypass Through User-Controlled Key)
* **Target Endpoint:** Order History API (`/api/orders/`)[cite: 8]
* **Severity:** High[cite: 8]
* **CVSS v3.1 Score:** 8.5 (High)
* **Vector String:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

---

## 3. Exploit Mechanics (IDOR Parameter Manipulation)
Per strict operational mandates and the "Do No Harm" rule, testing was restricted to passive read operations; no modifications or deletions were attempted against the sandbox records[cite: 8].

### A. Dynamic Scouting Phase
Upon logging into a standard user account (User ID: 5), navigating to the order history rendered an internal transaction query targeted at `/api/orders/101`[cite: 8]. The URL pattern indicated that order resources are managed using predictable, sequential integer keys[cite: 8].

### B. Payload Execution & Verification
Using Burp Suite to intercept the outbound packet, the numeric resource key parameter was changed from `101` (current user's order) to `102` (an arbitrary order identifier belonging to a different user account)[cite: 8].

### Intercepted HTTP Request (Modified ID Parameter)
```http
GET /api/orders/102 HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOi...
Connection: close

Observed Behavior
Expected Behavior: The backend API should cross-reference the session token (request.user.id) against the database owner record for order 102 and deny the request with an HTTP 403 Forbidden status code.

Actual Behavior: The server validated the session token for authentication, but failed to perform authorization mapping. It returned an HTTP 200 OK along with the private shipping details, total cost, and item listings of order 102 which belongs to an entirely different user account

4. Architectural Remediation
Relying entirely on complex or unguessable IDs (Security by Obscurity) is highly discouraged as it does not replace proper access control[cite: 8]. The application must implement rigorous server-side authorization validation checking that verifies resource ownership on every transaction request
Secure Remediation Directives
The server must explicitly check whether the user_id stored within the secure session token matches the owner_id linked to the resource requested in the query parameter before returning the payload

Vulnerable Backend Pattern
// INSECURE: Fetches resource strictly by ID parameter without validating ownership
app.get('/api/orders/:orderId', async (req, res) => {
    const order = await Database.Order.findOne({ where: { id: req.params.orderId } });
    return res.status(200).json(order);
});
Remediated Backend Secure Implementation
// SECURE: Strict validation of session identity against resource ownership
app.get('/api/orders/:orderId', async (req, res) => {
    try {
        const orderId = req.params.orderId;
        const currentUserId = req.user.id; // Extracted safely from validated JWT/Session context

        // Query the resource from the database
        const order = await Database.Order.findOne({ where: { id: orderId } });
        if (!order) {
            return res.status(404).json({ error: "Order record not found" });
        }

        // Strict Authorization Mandate: Enforce ownership verification
        if (order.userId !== currentUserId) {
            // Log security warning for unauthorized data access attempt
            console.warn(`Security Warning: User ${currentUserId} attempted access to Order ${orderId}`);
            return res.status(403).json({ error: "Access Denied: Unauthorized resource request" });
        }

        // Return payload safely only after authorization validation passes
        return res.status(200).json(order);
    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
});
