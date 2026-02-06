# Problem
# Failure to confirm the user sending the query is authorized to do so

# Impact
# Unauthorized access to sensitive data 

# Fixes
# Ensure that the "to" field in the message object matches the username of the authenticated user. This ensures a user can only read messages that were sent to them.
# Ensure the user sending the query is authorized to do so

def display_private_message(message):
    print(f"From: {html_escape(message['from'])}<br>")
    print(f"Subject: {html_escape(message['subject'])}")
    print("<hr>")
    print(f"Body: {html_escape(message['body'])}")


def lookup_message_object(message_id):
    """
    Assumptions:
    - message_id is numeric
    - message files are stored in a shared directory
    - returns a dict with: from, to, subject, body
    """
    # Example stub — real implementation would read from storage
    return {
        "from": "alice",
        "to": "bob",
        "subject": "Hello",
        "body": "Hi Bob!"
    }


def authenticate_user(username, password):
    # Stub authentication logic
    return username == "bob" and password == "correct-password"


def exit_error(message):
    raise PermissionError(message)


def html_escape(value):
    import html
    return html.escape(value)


# ---- Request handling (equivalent to CGI params) ----

def handle_request(params):
    username = params.get("username")
    password = params.get("password")

    if not authenticate_user(username, password):
        exit_error("invalid username or password")

    message_id = params.get("id")
    message = lookup_message_object(message_id)

    # ------------------------------------------------------------
    # FIX:
    # Ensure that the authenticated user is the intended recipient
    # of the private message before displaying it.
    #
    # Without this check, any authenticated user could supply an
    # arbitrary message ID and read private messages belonging
    # to other users (Insecure Direct Object Reference / Broken
    # Access Control).
    #
    # This enforces object-level authorization by verifying that
    # the message's "to" field matches the authenticated username.
    # ------------------------------------------------------------
    
    if message["to"] != username:
        exit_error("unauthorized access to private message")

    display_private_message(message)
