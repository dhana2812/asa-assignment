# Task 1: Shared Report Link — Verification Results & Implementation Documentation

This document provides a comprehensive overview, architectural security explanation, and step-by-step manual verification guide for the **Shared Report Link** feature implemented in Task 1.

---

## 1. Feature Overview & Architecture

The **Shared Report Link** feature enables authenticated VulnTracker users to share specific vulnerability scan results with external stakeholders (e.g., auditors, clients, or engineering teams) via a secure, unique URL.

### Endpoint Specifications

| Method | Path | Auth | Description | Request Body / Params | Expected Response |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/scans/{scan_id}/share` | Bearer Token | Generates a 24-hour expiring share link for the scan. | Body (optional JSON):<br>`{"password": "optional_string"}` | `200 OK`<br>`{"share_url": "http://localhost:8000/share/<token>"}` |
| `GET` | `/share/{token}` | None (Public) | Retrieves the scan findings if token is valid and active. | Query Param (optional):<br>`?password=<password>` *(required if link is protected)* | `200 OK` with scan payload (`ScanOut`), or `403`/`404` error |

---

## 2. Security Properties & Threat Mitigation

When implementing public links to sensitive vulnerability data, several critical security vectors were addressed:

1. **Cryptographically Secure Random Tokens (CSPRNG)**:
   - Tokens are generated using Python's `secrets.token_urlsafe(32)`.
   - Provides **256 bits of entropy**, making URL brute-forcing and token guessing mathematically impossible.
2. **Hashed Token Storage at Rest (SHA-256)**:
   - The plaintext token is returned only once to the scan owner in `share_url`.
   - The database **never stores plaintext tokens**; only `SHA-256(token)` is persisted (`ShareLink.token_hash`).
   - *Impact*: Even if the SQLite database is leaked (via backup disclosure or SQL injection), an attacker cannot use the stored hashes to access active reports.
3. **Adaptive Salted Password Hashing (bcrypt)**:
   - Passwords are encrypted using `passlib` bcrypt (`pwd_context.hash`).
   - Employs an adaptive work factor and per-password unique salt, resisting offline dictionary and rainbow-table attacks.
4. **Bcrypt 72-Byte Boundary Defense**:
   - The bcrypt hashing algorithm truncates passwords beyond 72 bytes. The API strictly enforces `1 <= len(password.encode("utf-8")) <= 72`:
     - Empty passwords return `422 Unprocessable Entity`.
     - Passwords exceeding 72 UTF-8 bytes return `422 Unprocessable Entity` on link creation and `403 Forbidden` on access attempts, preventing truncation bypasses.
5. **IDOR & Scan Enumeration Prevention**:
   - `POST /scans/{scan_id}/share` validates that the scan exists and belongs to the authenticated user (`owner_id == current_user.id`).
   - If an unauthorized user attempts to share someone else's scan, or a non-existent scan ID is passed, the API uniformly returns `404 Not Found` (rather than `403 Forbidden`), preventing attackers from discovering valid scan IDs.
6. **Uniform Expiration Invalidation**:
   - All links expire exactly **24 hours** after creation (`expires_at = datetime.utcnow() + timedelta(hours=24)`).
   - Both expired tokens and non-existent tokens return `404 Not Found` with identical responses, leaking no state or timing oracle to unauthenticated callers.
7. **Referential Integrity & Cascade Deletion**:
   - Foreign key constraint configured with `ondelete="CASCADE"` and SQLAlchemy `cascade="all, delete-orphan"`.
   - Deleting a parent scan (`DELETE /scans/{scan_id}`) automatically cleans up associated share links, preventing orphan access tokens.
8. **Fixed Prototype Origin (`http://localhost:8000`)**:
   - As instructed, the prototype fixes the origin to `http://localhost:8000`. Relying on incoming `Host` or `X-Forwarded-Host` headers without strict allowlists opens applications to Host Header Injection and phishing attacks. In production, this origin should be configured via a dedicated `APP_BASE_URL` environment variable.

---

## 3. Manual Verification Walkthrough

Follow these steps to manually test and verify every state of the feature.

### Prerequisites

Ensure the API service is running:
```powershell
cd c:\Users\dhana\asa-assignment\app
..\.venv\Scripts\activate
uvicorn main:app --reload
```
API Documentation is available at: **`http://localhost:8000/docs`**

---

### Method A: Step-by-Step Verification via Swagger UI (`http://localhost:8000/docs`)

#### Step 1: User Registration & Login
1. Navigate to `http://localhost:8000/docs`.
2. Expand `POST /auth/register` -> click **Try it out**.
3. Input:
   ```json
   {
     "username": "lead_auditor",
     "email": "auditor@example.com",
     "password": "SecurePassword123!"
   }
   ```
4. Click **Execute** -> verify response is `201 Created`.
5. Expand `POST /auth/login` -> input the same credentials -> click **Execute**.
6. Copy the `access_token` string from the response JSON.
7. Click the green **Authorize** button at the top-right of Swagger -> paste the token into `Value` -> click **Authorize** -> click **Close**.

#### Step 2: Create a Sample Vulnerability Finding
1. Expand `POST /scans` -> click **Try it out**.
2. Input:
   ```json
   {
     "title": "Remote Code Execution via Insecure Deserialization",
     "description": "Untrusted YAML payload processed without SafeLoader",
     "severity": "critical",
     "affected_component": "POST /api/v1/import",
     "remediation_notes": "Enforce PyYAML SafeLoader and input schema validation"
   }
   ```
3. Click **Execute** -> verify response is `201 Created`. Note the returned `id` (e.g., `1`).

#### Step 3: Test Unprotected Share Link (No Password)
1. Expand `POST /scans/{scan_id}/share`.
2. Enter `scan_id`: `1`. Leave the Request body as `{}` (or empty).
3. Click **Execute**.
   - **Observed Response**: `200 OK`
   - **Response Body**:
     ```json
     {
       "share_url": "http://localhost:8000/share/<token>"
     }
     ```
4. Copy the URL (e.g. `http://localhost:8000/share/vVq4j...`).
5. Open a **new private/incognito browser window** (where you are completely unauthenticated) and paste the URL.
   - **Observed Result**: `200 OK` returning full scan details without requesting authentication.

#### Step 4: Test Password-Protected Share Link
1. Return to the Swagger UI tab.
2. In `POST /scans/{scan_id}/share`, enter `scan_id`: `1`.
3. Provide request body:
   ```json
   {
     "password": "auditor-confidential"
   }
   ```
4. Click **Execute** -> copy the newly generated `share_url`.
5. In your incognito browser window, navigate to the URL directly (no password parameter):
   - **Observed Result**: `403 Forbidden` (`{"detail": "Password required or incorrect"}`).
6. Append an incorrect password query parameter: `?password=wrongpassword`:
   - **Observed Result**: `403 Forbidden` (`{"detail": "Password required or incorrect"}`).
7. Append the correct password parameter: `?password=auditor-confidential`:
   - **Observed Result**: `200 OK` returning the full scan data payload.

#### Step 5: Test Security Boundaries & Validation
1. **Empty Password Validation**:
   - In `POST /scans/{scan_id}/share`, pass `{"password": ""}` -> click **Execute**.
   - **Result**: `422 Unprocessable Entity` (`password must contain between 1 and 72 UTF-8 bytes`).
2. **Password Exceeding 72 Bytes**:
   - In `POST /scans/{scan_id}/share`, pass a 73-character password -> click **Execute**.
   - **Result**: `422 Unprocessable Entity`.
3. **Invalid Token Access**:
   - In a browser, visit `http://localhost:8000/share/non_existent_token_12345`.
   - **Result**: `404 Not Found` (`{"detail": "Share link not found or expired"}`).
4. **IDOR Defense**:
   - Log in as another user, or attempt `POST /scans/99999/share`.
   - **Result**: `404 Not Found` (avoids leaking whether scan ID exists).

---

### Method B: Automated Command-Line Verification (`curl.exe` in PowerShell)

You can run this end-to-end verification script in PowerShell:

```powershell
# 1. Register & Login
curl.exe -s -X POST http://localhost:8000/auth/register `
  -H "Content-Type: application/json" `
  -d '{"username": "cli_user", "email": "cli@test.com", "password": "PassWord123!"}'

$token = (curl.exe -s -X POST http://localhost:8000/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username": "cli_user", "password": "PassWord123!"}' | ConvertFrom-Json).access_token

# 2. Create Scan
$scanId = (curl.exe -s -X POST http://localhost:8000/scans `
  -H "Authorization: Bearer $token" `
  -H "Content-Type: application/json" `
  -d '{"title": "SQL Injection in Search", "severity": "critical", "affected_component": "GET /search"}' | ConvertFrom-Json).id

# 3. Create Public Link
$publicUrl = (curl.exe -s -X POST "http://localhost:8000/scans/$scanId/share" `
  -H "Authorization: Bearer $token" `
  -H "Content-Type: application/json" `
  -d '{}' | ConvertFrom-Json).share_url

# Verify Public Link (No auth)
curl.exe -i -X GET "$publicUrl"

# 4. Create Protected Link
$protUrl = (curl.exe -s -X POST "http://localhost:8000/scans/$scanId/share" `
  -H "Authorization: Bearer $token" `
  -H "Content-Type: application/json" `
  -d '{"password": "secret-report-key"}' | ConvertFrom-Json).share_url

# Test missing password -> 403
curl.exe -i -X GET "$protUrl"

# Test wrong password -> 403
curl.exe -i -X GET "$protUrl`?password=wrong"

# Test correct password -> 200
curl.exe -i -X GET "$protUrl`?password=secret-report-key"
```

---

## 4. Automated Test Suite Results

The automated regression test suite in `tests/test_api.py` was executed using pytest:

```bash
pytest tests/test_api.py -v
```

### Execution Log Summary

```text
tests/test_api.py::test_health PASSED                                    [  5%]
tests/test_api.py::test_register_user PASSED                             [ 10%]
tests/test_api.py::test_register_duplicate_username PASSED               [ 15%]
tests/test_api.py::test_login_success PASSED                             [ 21%]
tests/test_api.py::test_login_wrong_password PASSED                      [ 26%]
tests/test_api.py::test_create_scan PASSED                               [ 31%]
tests/test_api.py::test_list_scans PASSED                                [ 36%]
tests/test_api.py::test_search_scans PASSED                              [ 42%]
tests/test_api.py::test_update_scan_status PASSED                        [ 47%]
tests/test_api.py::test_delete_scan PASSED                               [ 52%]
tests/test_api.py::test_share_scan_without_password PASSED               [ 57%]
tests/test_api.py::test_share_scan_requires_password_when_configured PASSED [ 63%]
tests/test_api.py::test_share_link_expires_after_24_hours PASSED         [ 68%]
tests/test_api.py::test_cannot_share_another_users_scan PASSED           [ 73%]
tests/test_api.py::test_share_nonexistent_scan_returns_404 PASSED        [ 78%]
tests/test_api.py::test_share_scan_unauthenticated_returns_401 PASSED    [ 84%]
tests/test_api.py::test_share_invalid_password_returns_422 PASSED        [ 89%]
tests/test_api.py::test_get_share_nonexistent_token_returns_404 PASSED   [ 94%]
tests/test_api.py::test_delete_scan_cascades_and_removes_share_link PASSED [100%]

============================== 19 passed in 70.37s ==============================
```

**Status:** 19/19 tests passed (100% pass rate).
