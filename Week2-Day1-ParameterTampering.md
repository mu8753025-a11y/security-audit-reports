# Forensic Vulnerability Report: Parameter Tampering / Insecure Client-Side Trust

## 1. Executive Summary
During the Week 2, Day 1 tactical audit of the local sandbox environment, a high-severity parameter tampering vulnerability was discovered. The application dynamically processes transaction records (such as cart values or privilege contexts) based on values supplied directly by the client-side browser interface without server-side validation. An attacker can exploit this architecture to modify raw HTTP payloads in transit, altering product pricing or escalating session authorization states[cite: 5].

---

## 2. Vulnerability Details
* **Vulnerability Type:** Parameter Tampering / Improper Input Validation[cite: 5]
* **CWE Identifier:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision)
* **Target Component:** Shopping Cart API / Checkout Pipeline (`/api/BasketItems/`)[cite: 5]
* **Severity:** High[cite: 5]
* **CVSS v3.1 Score:** 8.5 (High)
* **Vector String:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N

---

## 3. Exploit Mechanics (Traffic Interception & Manipulation)
Per the strict Rules of Engagement, all operations were confined entirely to the localized sandbox loopback environment (`127.0.0.1:8080`)[cite: 5].

Using **Burp Suite Proxy**, outbound transactional requests were intercepted and held in memory before transmission to the server[cite: 5].

### Intercepted HTTP Request (Original - $100.00 Product)
```http
POST /api/BasketItems/ HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Authorization: Bearer eyJhbGciOi...

{
  "BasketId": 3,
  "ProductId": 12,
  "quantity": 1,
  "price": 100.00
}

Tampered HTTP Request (Modified - $0.01 Product)
POST /api/BasketItems/ HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Authorization: Bearer eyJhbGciOi...

{
  "BasketId": 3,
  "ProductId": 12,
  "quantity": 1,
  "price": 0.01
}
Observed Behavior
Expected Behavior: The backend API should evaluate the incoming price field against the official product master record stored in the relational database and reject any price mismatch with an HTTP 400 error.

Actual Behavior: The web server accepted the tampered payload verbatim, adding the product to the basket at the altered price of $0.01. This confirms the application relies entirely on untrusted client-side inputs to execute business transactions.

4. Architectural Remediation
Client-side variables, hidden form fields, and unencrypted cookies are completely under the user's control and must never be trusted to dictate business-critical states (like pricing or administrative roles)

Secure Remediation Directives
Never Trust Client-Side Parameters: Price values must never be transmitted from the client frontend during API calls. The client should only send the ProductId and quantity.

Server-Side Validation: The backend must retrieve the official price directly from the secure database using the provided ProductId before calculating totals or processing checkout loops.
// Remediated Backend Secure Code Implementation (Node.js/Express)
app.post('/api/BasketItems/', async (req, res) => {
    const { productId, quantity } = req.body; // Strictly extract identifier parameters only

    try {
        // Query the master database for trusted data
        const product = await Database.Product.findOne({ where: { id: productId } });
        if (!product) return res.status(404).send("Product not found");

        // Calculate total securely on the server-side
        const secureTotalPrice = product.price * quantity;

        // Execute save statement with secure price data
        await Database.Basket.addItem({
            productId: productId,
            quantity: quantity,
            priceAtPurchase: product.price // Sourced from trusted database
        });

        return res.status(200).json({ success: true, total: secureTotalPrice });
    } catch (error) {
        return res.status(500).send("Internal Server Error");
    }
});

