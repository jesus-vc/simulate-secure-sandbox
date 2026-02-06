# Problem
# Failure to confirm the user sending the query is authorized to do so.

# Impact
# Unauthorized access to sensitive data .

# Fixes
# Ensure the user sending the query is authorized to do so.

import os
import mysql.connector

# Database credentials are sourced from OS-level environment variables rather than
# hardcoded in application code. In web and containerized deployments, these values
# are injected at runtime by the hosting platform (e.g., systemd, Docker, Kubernetes),
# keeping secrets out of source control and enabling secure rotation without code
# changes. MySQL performs a secure authentication handshake (optionally over TLS),
# so credentials are not transmitted in plaintext over the network.
global_db_handle = mysql.connector.connect(
    host=os.environ["DB_HOST"],
    user=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
    database=os.environ.get("DB_NAME"),
    ssl_disabled=False
)

# Toggle to enable / disable authorization enforcement.
# Set to False to intentionally demonstrate the vulnerability
# (e.g., for security testing, demos, or scanner validation).
ENFORCE_AUTHORIZATION = True

def run_employee_query(db_name, employee_name, requesting_user):
    cursor = global_db_handle.cursor(dictionary=True)
    cursor.execute(f"USE {db_name}")

    # ------------------------------------------------------------
    # AUTHORIZATION CONTROL (TOGGLEABLE):
    #
    # When ENFORCE_AUTHORIZATION is enabled, the function verifies
    # that the requesting user is authorized to access employee
    # data before executing the query. Although parameterized SQL
    # prevents injection (CWE-89), authorization is still required
    # to protect sensitive data.
    #
    # This enforces role- or privilege-based access control at the
    # data-access layer and prevents unauthorized disclosure
    # (Broken Access Control).
    #
    # When disabled, this intentionally simulates the vulnerable
    # behavior where any authenticated user can query employee
    # records (Missing Authorization), for testing or demonstration.
    # ------------------------------------------------------------
    if ENFORCE_AUTHORIZATION:
        if not is_authorized_for_employee_data(requesting_user):
            cursor.close()
            raise PermissionError(
                "User is not authorized to access employee data"
            )

    query = "SELECT * FROM employees WHERE name = %s"
    cursor.execute(query, (employee_name,))
    results = cursor.fetchall()
    cursor.close()

    return results


def is_authorized_for_employee_data(user):
    """
    Example authorization logic:
    Only HR staff or administrators may query employee records.
    """
    return user.get("role") in {"HR", "ADMIN"}

# ---- Example request handling (TEST / DEMO ONLY) ----
# In production, user identity and role must come from a
# trusted authentication layer (e.g., session, JWT, or
# auth middleware), not from client-controlled input.

request_params = {
    "EmployeeName": "Alice",
    "user": {
        "username": "bob",
        "role": "HR"
    }
}

employee_record = run_employee_query(
    db_name="EmployeeDB",
    employee_name=request_params["EmployeeName"],
    requesting_user=request_params["user"]
)
