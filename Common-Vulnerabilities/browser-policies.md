# Browser Security Policies

---

## Same-Origin Policy (SOP)

> SOP is a built-in browser rule stopping scripts on one site from reading data from another.

**Example:**

```javascript
// This will fail if example.com tries to access data from evil.site
fetch('https://evil.site/data')
```

---

## Content Security Policy (CSP)

> CSP is a developer-defined HTTP header that limits where resources (scripts, images) can load from to prevent XSS attacks.

**Example CSP header:**

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';
```

**Effect:**

```html
<script src="https://evil.site/x.js"></script> <!-- Blocked by CSP -->
```

---

## Cross-Origin Resource Sharing (CORS)

> CORS is a browser mechanism that allows servers to specify who can access their resources from other origins. It controls which external websites can make requests to your server and what kind of requests are allowed.

**Example:**

Suppose your frontend is hosted at `https://example.com` and your backend at `https://api.example.com`. By default, browsers block AJAX requests from the frontend to the backend unless CORS is enabled.

**Server-side (Express.js):**

```javascript
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({ origin: 'https://example.com' }));

app.get('/data', (req, res) => {
  res.json({ message: 'CORS enabled!' });
});
```

**Browser request:**

```javascript
fetch('https://api.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

**Effect:**

> If CORS is not enabled, the browser blocks the request. If enabled, the request succeeds and data is returned.

---