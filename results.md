# VulnTracker — Manual Verification Guide & Task Results

This document serves as the master record and manual verification walkthrough for all completed tasks in the VulnTracker security assignment.

---

# Table of Contents
1. [Task 1: Shared Report Link — Verification & Results](#task-1-shared-report-link--verification--results)
   - [Feature Architecture & Endpoint Specs](#11-feature-overview--architecture)
   - [Security Architecture & Threat Mitigation](#12-security-properties--threat-mitigation)
   - [Manual Verification Walkthrough (Swagger UI & CLI)](#13-manual-verification-walkthrough)
   - [Automated Test Suite Results (19/19 Passed)](#14-automated-test-suite-results)
2. [Task 2: Security Analysis — Verification & Results](#task-2-security-analysis--verification--results)
   - [Required Scans & Tool Selection Rationale](#21-required-scans--tool-selection-rationale)
   - [Step-by-Step Manual Verification of Raw Reports](#22-step-by-step-manual-verification-of-reports)
   - [Commands to Re-run Any Security Scan Live](#23-commands-to-re-run-any-security-scan-live)
   - [Prioritised Security Findings Summary (`docs/findings.md`)](#24-prioritised-security-findings-summary)
   - [Verification of Supporting Infrastructure & Container Artifacts](#25-verification-of-supporting-infrastructure--container-artifacts)

---

# Task 1: Shared Report Link — Verification & Results

## 1.1 Feature Overview & Architecture

The **Shared Report Link** feature enables authenticated VulnTracker users to share specific vulnerability scan results with external stakeholders (e.g., auditors, clients, or engineering teams) via a secure, unique URL.

### Endpoint Specifications

| Method | Path | Auth | Description | Request Body / Params | Expected Response |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/scans/{scan_id}/share` | Bearer Token | Generates a 24-hour expiring share link for the scan. | Body (optional JSON):<br>`{"password": "optional_string"}` | `200 OK`<br>`{"share_url": "http://localhost:8000/share/<token>"}` |
| `GET` | `/share/{token}` | None (Public) | Retrieves the scan findings if token is valid and active. | Query Param (optional):<br>`?password=<password>` *(required if link is protected)* | `200 OK` with scan payload (`ScanOut`), or `403`/`404` error |

---

## 1.2 Security Properties & Threat Mitigation

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

## 1.3 Manual Verification Walkthrough

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

## 1.4 Automated Test Suite Results

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

---

# Task 2: Security Analysis — Verification & Results

## 2.1 Required Scans & Tool Selection Rationale

Task 2 requires executing **all four** standard application security scanning disciplines and persisting the raw JSON outputs to the `reports/` directory:

1. **Static Application Security Testing (SAST)** — **Bandit v1.9.4**:
   - *Rationale*: Open-source AST-based security analysis tool tailored for Python. Designed specifically to catch insecure SQL queries, hardcoded cryptographic keys, and weak encryption patterns.
   - *Artifact*: [`reports/sast.bandit.json`](file:///c:/Users/dhana/asa-assignment/reports/sast.bandit.json)
2. **Software Composition Analysis (SCA)** — **Trivy v0.76.0 & pip-audit v2.10.1**:
   - *Rationale*: Pinned third-party packages must be scanned against known CVE databases. Trivy handles both language ecosystems simultaneously (`requirements.txt` and `notify/package.json`), and `pip-audit` cross-checks against the PyPA advisory database.
   - *Artifact*: [`reports/sca.trivy.json`](file:///c:/Users/dhana/asa-assignment/reports/sca.trivy.json) and [`reports/sca.pip-audit.json`](file:///c:/Users/dhana/asa-assignment/reports/sca.pip-audit.json)
3. **Container Image Scan** — **Trivy v0.76.0**:
   - *Rationale*: Scans the production-built `vulntracker-api:latest` Docker image layer-by-layer for base OS vulnerabilities (Debian Bookworm) and installed packages.
   - *Artifact*: [`reports/container.trivy.json`](file:///c:/Users/dhana/asa-assignment/reports/container.trivy.json)
4. **Infrastructure-as-Code (IaC) Scan** — **Trivy v0.76.0 (`trivy config`)**:
   - *Rationale*: Static analysis of the Terraform deployment manifests (`terraform/`) against CIS benchmarks, cloud security best practices, and AWS policy checks.
   - *Artifact*: [`reports/iac.trivy.json`](file:///c:/Users/dhana/asa-assignment/reports/iac.trivy.json)

---

## 2.2 Step-by-Step Manual Verification of Reports

Run the following command in PowerShell to verify the presence, size, and validity of all generated reports:

```powershell
Get-ChildItem reports\*.json | ForEach-Object {
    $data = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    [PSCustomObject]@{
        ReportFile  = $_.Name
        ScanType    = $_.Name.Split('.')[0].ToUpper()
        Tool        = $_.Name.Split('.')[1]
        SizeKB      = [math]::Round($_.Length / 1KB, 1)
        ValidJSON   = ($null -ne $data)
    }
} | Format-Table -AutoSize
```

### Expected Output

```text
ReportFile           ScanType  Tool      SizeKB ValidJSON
----------           --------  ----      ------ ---------
container.trivy.json CONTAINER trivy     1427.4      True
iac.trivy.json       IAC       trivy        4.3      True
sast.bandit.json     SAST      bandit       5.5      True
sca.pip-audit.json   SCA       pip-audit   99.1      True
sca.trivy.json       SCA       trivy      289.7      True
```

### Verifying Findings Counts Inside Reports

Run the following script to verify that each scan actively analyzed the code and found real security issues:

```powershell
# 1. SAST (Bandit): Verify AST findings count
$sast = Get-Content reports\sast.bandit.json -Raw | ConvertFrom-Json
Write-Host "SAST (Bandit) Findings Count:" $sast.results.Count

# 2. SCA (pip-audit): Verify vulnerable dependencies count
$sca = Get-Content reports\sca.pip-audit.json -Raw | ConvertFrom-Json
Write-Host "SCA (pip-audit) Vulnerabilities Count:" $sca.dependencies.vulns.Count

# 3. Container Scan (Trivy): Verify image targets scanned
$container = Get-Content reports\container.trivy.json -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Host "Container Scan (Trivy) Targets Scanned:" $container.Results.Count

# 4. IaC Scan (Trivy): Verify Terraform misconfigurations detected
$iac = Get-Content reports\iac.trivy.json -Raw | ConvertFrom-Json
Write-Host "IaC Scan (Trivy) Misconfigurations Found:" $iac.Results.Misconfigurations.Count
```

---

## 2.3 Commands to Re-run Any Security Scan Live

To re-run any scan live in your terminal:

```powershell
# 1. Re-run SAST (Bandit)
.\.venv\Scripts\bandit.exe -r app/ -f json -o reports/sast.bandit.json

# 2. Re-run SCA (pip-audit)
.\.venv\Scripts\pip-audit.exe -r requirements.txt -f json -o reports/sca.pip-audit.json

# 3. Re-run SCA (Trivy filesystem)
docker run --rm -v "${PWD}:/src" aquasec/trivy fs /src --skip-dirs /src/.venv,/src/.git,/src/notify/node_modules --scanners vuln --format json -o /src/reports/sca.trivy.json

# 4. Re-run Container Scan (Trivy)
docker run --rm -v "${PWD}:/src" -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --format json -o /src/reports/container.trivy.json vulntracker-api:latest

# 5. Re-run IaC Scan (Trivy config)
docker run --rm -v "${PWD}:/src" aquasec/trivy config /src/terraform --format json -o /src/reports/iac.trivy.json
```

---

## 2.4 Prioritised Security Findings Summary (`docs/findings.md`)

A comprehensive, contextualized security assessment is documented in [docs/findings.md](file:///c:/Users/dhana/asa-assignment/docs/findings.md). As VulnTracker stores confidential vulnerability intelligence, severity is prioritized according to **actual business impact**:

| Finding ID | Vulnerability / Issue | Tool & Scan Type | Assessed Severity | Origin | Justification & Business Context |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VT-01** | **SQL Injection in Scan Search** (`app/database.py`) | SAST (Bandit B608) & Manual Review | **CRITICAL** | Starter Code | Parameter `q` concatenated directly into SQL string. Exposes entire vulnerability database and user password hashes. |
| **VT-02** | **Hardcoded JWT Secret & `"none"` Algorithm Acceptance** (`app/config.py`, `app/auth.py`) | SAST (Bandit B105) & Manual Review | **CRITICAL** | Starter Code | Allows forged tokens with `"none"` algorithm or leaked key. Total authentication bypass. |
| **VT-03** | **Unauthenticated Webhook Registration & SSRF with Service Key Leakage** (`notify/`) | Manual Review & SCA | **CRITICAL** | Starter Code | Unauthenticated `/webhooks` accepts arbitrary targets. Dispatcher sends internal `X-Service-Key` and enables cloud metadata probing. |
| **VT-04** | **Permissive CORS Wildcard Reflection with Credentials** (`app/main.py`) | Manual Review | **HIGH** | Starter Code | Reflects any incoming `Origin` with `credentials: true`. Bypasses SOP, allowing malicious sites to exfiltrate findings. |
| **VT-05** | **Plaintext Credential Logging in Authentication Handlers** (`app/main.py`) | Manual Review | **HIGH** | Starter Code | Logs plaintext user passwords on login attempts, exposing credentials across SIEM / log aggregators. |
| **VT-06** | **High-Severity Known CVEs in Pinned Dependencies** (`requirements.txt`, `notify/`) | SCA (Trivy & pip-audit) | **HIGH** | Starter Code | Memory corruption in `cryptography==38.0.1` (CVE-2023-23931), ReDoS in `python-multipart` (CVE-2024-24762), and SSRF/redirect in `axios@0.21.1` (CVE-2023-45857). |
| **VT-07** | **Stack Trace Disclosure in Global Exception Handler** (`app/main.py`) | Manual Review | **MEDIUM** | Starter Code | Returns Python tracebacks on HTTP 500, leaking internal server paths and framework internals. |
| **VT-08** | **Missing Rate Limiting on Login & Shared Report Links** (`app/main.py`) | Manual Review | **MEDIUM** | Starter Code & New Feature | No request throttling on `/auth/login` or `/share/{token}?password=...`, enabling brute-force guessing. |
| **VT-09** | **Over-Permissive Outbound Egress in Security Groups** (`terraform/security_groups.tf`) | IaC Scan (Trivy AWS-0104) | **LOW** | Infrastructure | Outbound `0.0.0.0/0` on port 443 permitted. In strict environments, outbound traffic should route via VPC Endpoints. |
| **VT-10** | **Base OS Image Vulnerabilities** (`python:3.11-slim-bookworm`) | Container Scan (Trivy) | **LOW** | Dockerfile | Known upstream Debian package CVEs. Mitigated at runtime via non-root execution (`10001:10001`), read-only rootfs, and dropped Linux capabilities. |

---

## 2.5 Verification of Supporting Infrastructure & Container Artifacts

To enable the container and IaC scans required by Task 2, production-grade artifacts were authored in accordance with the Task 4 requirements:

1. **Production Dockerfile ([Dockerfile](file:///c:/Users/dhana/asa-assignment/Dockerfile))**:
   - Minimal pinned base image: `python:3.11-slim-bookworm`.
   - Multi-stage build (compilers and build headers stripped from final image).
   - Dedicated unprivileged user/group: `appuser:appgroup` (`UID 10001`).
   - Integrated container `HEALTHCHECK` using Python standard library.
   - Zero hardcoded secrets or embedded credentials.
   - Successfully built as `vulntracker-api:latest`.

2. **Terraform Infrastructure ([terraform/](file:///c:/Users/dhana/asa-assignment/terraform/))**:
   - **AWS Secrets Manager ([secrets.tf](file:///c:/Users/dhana/asa-assignment/terraform/secrets.tf))**: Customer-managed KMS key with automatic key rotation; secrets injected via container definitions, not hardcoded in manifests.
   - **Restricted Security Groups ([security_groups.tf](file:///c:/Users/dhana/asa-assignment/terraform/security_groups.tf))**: Ingress restricted to port 8000 exclusively from the Application Load Balancer (ALB); zero direct public access.
   - **ECS Fargate Deployment ([main.tf](file:///c:/Users/dhana/asa-assignment/terraform/main.tf))**: Pinned CPU/memory resource limits, read-only root filesystem (`readonlyRootFilesystem = true`), and dropped Linux capabilities (`drop = ["ALL"]`).
   - **Least-Privilege IAM ([iam.tf](file:///c:/Users/dhana/asa-assignment/terraform/iam.tf))**: Granular execution and task roles.
