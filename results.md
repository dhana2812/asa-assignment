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
3. [Task 3: Security Remediation — Verification & Results](#task-3-security-remediation--verification--results)
   - [Overview of Code Remediations Applied](#31-overview-of-code-remediations-applied)
   - [Step-by-Step Manual Verification Walkthrough](#32-step-by-step-manual-verification-walkthrough)
   - [Automated Verification (Pytest 22/22 & Bandit SAST)](#33-automated-verification-pytest-and-bandit)
   - [Remediation Plan & Deferred Findings (`docs/remediation-plan.md`)](#34-remediation-plan--deferred-findings-summary)
4. [Task 4: Containerisation & Deployment Artifacts — Verification & Results](#task-4-containerisation--deployment-artifacts--verification--results)
   - [Dockerfile Security Architecture & Properties](#41-dockerfile-security-architecture--properties)
   - [Manual Verification of Docker Build, Run, & Healthcheck](#42-manual-verification-of-docker-build-run--healthcheck)
   - [Infrastructure-as-Code Cloud Deployment Architecture (`terraform/`)](#43-infrastructure-as-code-cloud-deployment-architecture-terraform)
   - [Verification of Cloud Security Controls & Compliance](#44-verification-of-cloud-security-controls--compliance)

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

---

# Task 3: Security Remediation — Verification & Results

## 3.1 Overview of Code Remediations Applied

In accordance with Task 3 requirements, 6 high- and critical-severity findings were remediated directly in application code, including a high-severity brute-force mitigation applied directly to the **Task 1** Shared Report Link feature:

| Finding ID | Vulnerability / Issue | Original Severity | File(s) Remediated | Nature of Fix |
| :--- | :--- | :--- | :--- | :--- |
| **VT-01** | **SQL Injection in Scan Search** | **CRITICAL** | [`app/database.py`](file:///c:/Users/dhana/asa-assignment/app/database.py) | Replaced raw f-string concatenation with parameterized query binding (`:pattern`) via SQLAlchemy `text()`. |
| **VT-02** | **JWT Algorithm Confusion & Hardcoded Secrets** | **CRITICAL** | [`app/auth.py`](file:///c:/Users/dhana/asa-assignment/app/auth.py)<br>[`app/config.py`](file:///c:/Users/dhana/asa-assignment/app/config.py) | Removed `"none"` algorithm from `jwt.decode()`; strictly enforced cryptographic signature check. Refactored secrets to read from environment variables. |
| **VT-08** | **Shared Report Link Brute-Force & Rate Limiting** *(Task 1 Code Fix)* | **HIGH** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Added attempt tracking and lockout on `GET /share/{token}`. Returns `429 Too Many Requests` after 5 failed password attempts with a `Retry-After` header. |
| **VT-05** | **Plaintext Credential Logging in Authentication** | **HIGH** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Stripped `payload.password` from `logger.info` and `logger.warning` in `/auth/login`. |
| **VT-04** | **Permissive CORS Wildcard Reflection with Credentials** | **HIGH** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Replaced arbitrary origin reflection with strict `ALLOWED_ORIGINS` whitelist and restricted headers. |
| **VT-07** | **Stack Trace Information Disclosure** | **MEDIUM** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Sanitized global HTTP 500 error response to prevent internal file path and schema leakage. |

---

## 3.2 Step-by-Step Manual Verification Walkthrough

Ensure the API service is running locally before executing the verification steps below:
```powershell
cd c:\Users\dhana\asa-assignment\app
..\.venv\Scripts\activate
uvicorn main:app --reload
```

---

### Verification 1: Parameterized SQL Injection Prevention (VT-01)

#### Objective
Verify that malicious SQL syntax passed in the `q` query parameter of `GET /scans/search` is safely treated as a literal search string and cannot bypass authorization or dump database records.

#### Execution (PowerShell)
```powershell
# 1. Register & authenticate a test user
$regBody = '{"username":"sqli_tester","email":"sqli@test.com","password":"Password123!"}'
Invoke-RestMethod -Uri "http://localhost:8000/auth/register" -Method Post -Body $regBody -ContentType "application/json"

$loginBody = '{"username":"sqli_tester","password":"Password123!"}'
$token = (Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -Body $loginBody -ContentType "application/json").access_token
$headers = @{ "Authorization" = "Bearer $token" }

# 2. Attempt SQL injection union attack
$sqliPayload = [System.Web.HttpUtility]::UrlEncode("' UNION SELECT 1, 'Injected', 'Injected', 'critical', 'open', 'CVE', 'misc', 1, '2026-01-01' --")
$searchResp = Invoke-RestMethod -Uri "http://localhost:8000/scans/search?q=$sqliPayload" -Method Get -Headers $headers

# 3. Inspect results
$searchResp.results
```

#### Expected Result
- Status code: `200 OK`
- Results array is empty (`[]`).
- The query does not error out or return injected union records, proving that SQLAlchemy treats the input strictly as parameter data bound to `:pattern`.

---

### Verification 2: Rejection of Insecure JWT `"none"` Algorithm (VT-02)

#### Objective
Verify that the API rejects forged JWTs using the `"none"` algorithm without requiring a valid cryptographic HMAC signature.

#### Execution (PowerShell)
```powershell
# Construct a forged JWT payload with {"alg":"none","typ":"JWT"} and {"sub":"admin"}
# Header: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: eyJzdWIiOiJhZG1pbiJ9
# Signature: (empty)
$forgedToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."

try {
    Invoke-RestMethod -Uri "http://localhost:8000/scans" -Method Get -Headers @{ "Authorization" = "Bearer $forgedToken" }
} catch {
    Write-Host "Response Status:" $_.Exception.Response.StatusCode.value__
    Write-Host "Response Body:" $_.ErrorDetails.Message
}
```

#### Expected Result
- Status code: `401 Unauthorized`
- Body: `{"detail": "Could not validate credentials"}`
- Confirms the authentication handler strictly rejects algorithm confusion attacks.

---

### Verification 3: Task 1 Feature Remediation — Brute-Force Rate Limiting Lockout (VT-08)

#### Objective
Verify that `GET /share/{token}` tracks failed password attempts and locks out callers after 5 consecutive incorrect attempts with an HTTP `429 Too Many Requests` status and a `Retry-After` header.

#### Execution (PowerShell)
```powershell
# 1. Login and create a test scan
$loginBody = '{"username":"sqli_tester","password":"Password123!"}'
$token = (Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -Body $loginBody -ContentType "application/json").access_token
$headers = @{ "Authorization" = "Bearer $token" }

$scanBody = '{"title":"Secret Finding","severity":"critical","affected_component":"auth-service"}'
$scan = Invoke-RestMethod -Uri "http://localhost:8000/scans" -Method Post -Headers $headers -Body $scanBody -ContentType "application/json"

# 2. Create a password-protected share link
$shareBody = '{"password":"CorrectPassword123!"}'
$share = Invoke-RestMethod -Uri "http://localhost:8000/scans/$($scan.id)/share" -Method Post -Headers $headers -Body $shareBody -ContentType "application/json"
$shareUrl = $share.share_url
Write-Host "Created Share URL:" $shareUrl

# 3. Simulate 5 failed dictionary password guesses
1..5 | ForEach-Object {
    try {
        Invoke-RestMethod -Uri "$shareUrl`?password=wrong_guess_$_" -Method Get
    } catch {
        Write-Host "Attempt $_ failed with status:" $_.Exception.Response.StatusCode.value__
    }
}

# 4. Attempt 6th request with the CORRECT password
try {
    Invoke-RestMethod -Uri "$shareUrl`?password=CorrectPassword123!" -Method Get
} catch {
    Write-Host "6th Attempt Locked Out!"
    Write-Host "Status Code:" $_.Exception.Response.StatusCode.value__
    Write-Host "Response Detail:" $_.ErrorDetails.Message
    Write-Host "Retry-After Header:" $_.Exception.Response.Headers.GetValues("Retry-After")
}
```

#### Expected Result
- Attempts 1 through 5 fail with `403 Forbidden` (`Password required or incorrect`).
- Attempt 6 (even with the correct password) returns `429 Too Many Requests`:
  ```json
  {"detail": "Too many failed password attempts. Link is temporarily locked."}
  ```
- Response includes `Retry-After: 900` (15-minute temporary security lockout).

---

### Verification 4: Sanitization of Plaintext Passwords in Application Logs (VT-05)

#### Objective
Verify that user passwords are never emitted to application console logs or log files during authentication attempts.

#### Execution
1. Trigger a failed login in PowerShell:
   ```powershell
   try {
       Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method Post -Body '{"username":"sqli_tester","password":"SuperSecretPasswordDoNotLog!"}' -ContentType "application/json"
   } catch { }
   ```
2. Observe the terminal console running `uvicorn main:app --reload`.

#### Expected Result
- The console displays:
  ```text
  WARNING: Failed login attempt for username: sqli_tester
  ```
- **No plaintext password string (`SuperSecretPasswordDoNotLog!`) appears anywhere in the output.**

---

### Verification 5: Generic Error Response on Unhandled Exceptions (VT-07)

#### Objective
Verify that unhandled internal server exceptions do not leak stack traces or internal server paths to API consumers.

#### Execution
When unexpected runtime errors occur, the global exception handler returns:
```json
{
  "error": "Internal Server Error",
  "detail": "An unexpected error occurred. Please contact the administrator."
}
```
Detailed stack traces are recorded strictly in internal server logs with `exc_info=True`, resolving CWE-209.

---

## 3.3 Automated Verification (Pytest and Bandit)

### 1. Pytest Test Suite Execution (22/22 Tests Passing)
Run the automated test suite, which includes 3 dedicated tests verifying Task 3 fixes (`test_search_scans_prevents_sql_injection`, `test_jwt_rejects_none_algorithm`, `test_share_scan_rate_limiting_lockout`):

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

#### Result Output:
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-7.4.3, pluggy-1.7.0
rootdir: C:\Users\dhana\asa-assignment
collected 22 items

tests/test_api.py::test_health PASSED                                    [  4%]
tests/test_api.py::test_register_user PASSED                             [  9%]
tests/test_api.py::test_register_duplicate_username PASSED               [ 13%]
tests/test_api.py::test_login_success PASSED                             [ 18%]
tests/test_api.py::test_login_wrong_password PASSED                      [ 22%]
tests/test_api.py::test_create_scan PASSED                               [ 27%]
tests/test_api.py::test_list_scans PASSED                                [ 31%]
tests/test_api.py::test_search_scans PASSED                              [ 36%]
tests/test_api.py::test_update_scan_status PASSED                        [ 40%]
tests/test_api.py::test_delete_scan PASSED                               [ 45%]
tests/test_api.py::test_share_scan_without_password PASSED               [ 50%]
tests/test_api.py::test_share_scan_requires_password_when_configured PASSED [ 54%]
tests/test_api.py::test_share_link_expires_after_24_hours PASSED         [ 59%]
tests/test_api.py::test_cannot_share_another_users_scan PASSED           [ 63%]
tests/test_api.py::test_share_nonexistent_scan_returns_404 PASSED        [ 68%]
tests/test_api.py::test_share_scan_unauthenticated_returns_401 PASSED    [ 72%]
tests/test_api.py::test_share_invalid_password_returns_422 PASSED        [ 77%]
tests/test_api.py::test_get_share_nonexistent_token_returns_404 PASSED   [ 81%]
tests/test_api.py::test_delete_scan_cascades_and_removes_share_link PASSED [ 86%]
tests/test_api.py::test_search_scans_prevents_sql_injection PASSED       [ 90%]
tests/test_api.py::test_jwt_rejects_none_algorithm PASSED                [ 95%]
tests/test_api.py::test_share_scan_rate_limiting_lockout PASSED          [100%]

================== 22 passed, 2 warnings in 75.36s (0:01:15) ==================
```

---

### 2. Bandit SAST Post-Remediation Verification

Run Bandit SAST across the application codebase:
```powershell
.\.venv\Scripts\bandit.exe -r app/
```

#### Result Output:
```text
Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 1 (OAuth2 "bearer" token_type false positive)
		Medium: 0
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 1
		High: 0
```
- **Zero High or Critical findings remain in the application codebase.** (SQL injection B608 and hardcoded secret issues are eliminated).

---

## 3.4 Remediation Plan & Deferred Findings Summary

For all findings identified in Task 2 that were not remediated in code, comprehensive analysis and roadmap planning are documented in **[`docs/remediation-plan.md`](file:///c:/Users/dhana/asa-assignment/docs/remediation-plan.md)**:

| Finding ID | Finding Description | Severity | Component | Deferral Justification & Residual Risk | Compensating Controls in Place |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VT-03** | **Unauthenticated Webhooks & SSRF** | **CRITICAL** | `notify/` | Service refactor exceeds single-service scope. Direct access allows probing internal endpoints. | Deployed in private VPC subnet with zero public ALB ingress; isolated security groups; IMDSv2 metadata hop limits. |
| **VT-06** | **High-Severity CVEs in Dependencies** | **HIGH** | `requirements.txt`<br>`notify/` | Major version bumps require full regression testing across both services. ReDoS and memory corruption risks. | Container runs with non-root UID (`10001`), read-only rootfs (`readonlyRootFilesystem = true`), and dropped Linux capabilities (`drop = ["ALL"]`). |
| **VT-09** | **Over-Permissive Outbound Egress** | **LOW** | `terraform/` | Outbound HTTPS allowed to external stakeholder webhook endpoints. | Zero inbound public access to tasks; non-interactive shell (`/sbin/nologin`). |
| **VT-10** | **Base OS Image Debian CVEs** | **LOW** | `Dockerfile` | Upstream distribution patches. Theoretical privilege escalation. | Multi-stage build strips compilers; task executes with `no-new-privileges` under non-root user. |

---

# Task 4: Containerisation & Deployment Artifacts — Verification & Results

## 4.1 Dockerfile Security Architecture & Properties

The container specification in [`Dockerfile`](file:///c:/Users/dhana/asa-assignment/Dockerfile) was authored following strict DevSecOps and CIS Docker Benchmark principles:

1. **Minimal, Pinned Base Image**:
   - Uses `python:3.11-slim-bookworm` pinned to a specific Debian version, eliminating unnecessary binaries, documentation, and bloated OS packages.
2. **Multi-Stage Build Pattern**:
   - **Stage 1 (`builder`)**: Installs native C compilers (`gcc`, `libffi-dev`) required to compile wheels for `cryptography` and `bcrypt`, writing compiled artifacts to `/install/wheels`.
   - **Stage 2 (`runtime`)**: Pulls a clean Debian base and copies only the compiled Python packages from `/install/wheels` to `/usr/local`. Compilers, package managers (`apt`), and temporary build caches are omitted from the production image, minimizing the attack surface.
3. **Dedicated Non-Root User Execution**:
   - Creates an explicit system group (`appgroup`, `GID 10001`) and system user (`appuser`, `UID 10001`) with no login shell (`/sbin/nologin`).
   - The container executes strictly under `USER 10001:10001`, preventing container-breakout attacks from acquiring host root privileges.
4. **Native In-Process `HEALTHCHECK`**:
   - Employs Python's built-in standard library (`urllib.request`) rather than installing external utilities (`curl`, `wget`, `netcat`):
     ```dockerfile
     HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
         CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1
     ```
   - Automatically monitors service health and signals orchestrators (Docker, Kubernetes, AWS ECS) to recycle unhealthy instances.
5. **Zero Hardcoded Secrets or Credentials**:
   - No passwords, API keys, or secret tokens are present in the Dockerfile, layers, or environment variables. All secrets are injected dynamically at runtime via secrets management.

---

## 4.2 Manual Verification of Docker Build, Run, & Healthcheck

Follow the step-by-step instructions below to build, run, and verify the containerized application.

### Step 1: Build the Container Image
Run the Docker build from the repository root:
```powershell
docker build -t vulntracker-api:latest .
```
- **Observed Result**: Multi-stage build completed successfully (`writing image sha256:... naming to docker.io/library/vulntracker-api:latest`).

---

### Step 2: Run the Hardened Container
Run the container with a read-only root filesystem and an ephemeral tmpfs mount:
```powershell
docker run -d `
  --name vulntracker-api `
  -p 8000:8000 `
  --read-only `
  --tmpfs /tmp:rw,noexec,nosuid,size=64m `
  vulntracker-api:latest
```

---

### Step 3: Verify Non-Root User Execution
Inspect the runtime user inside the container:
```powershell
docker exec vulntracker-api id
```
- **Expected Output**:
  ```text
  uid=10001(appuser) gid=10001(appgroup) groups=10001(appgroup)
  ```
- Confirms the container is strictly running under unprivileged UID 10001, satisfying CIS Docker Benchmark 4.1.

---

### Step 4: Verify Container Healthcheck Status
Check Docker daemon health status:
```powershell
docker ps -f name=vulntracker-api
```
- **Expected Output**:
  ```text
  CONTAINER ID   IMAGE                    STATUS                    PORTS                    NAMES
  3b647b818468   vulntracker-api:latest   Up 35 seconds (healthy)   0.0.0.0:8000->8000/tcp   vulntracker-api
  ```
- Confirms the native `HEALTHCHECK` passes and Docker marks the container as `(healthy)`.

---

### Step 5: Test API Reachability and Endpoints
Query the health check and Swagger documentation endpoints:
```powershell
# 1. Test health endpoint
Invoke-RestMethod -Uri "http://localhost:8000/health"
# Output: {"status":"ok","service":"vulntracker-api"}

# 2. Test Swagger UI reachability
$resp = Invoke-WebRequest -Uri "http://localhost:8000/docs"
Write-Host "Swagger UI Status:" $resp.StatusCode
# Output: 200
```

---

### Step 6: Stop and Clean Up
```powershell
docker stop vulntracker-api ; docker rm vulntracker-api
```

---

## 4.3 Infrastructure-as-Code Cloud Deployment Architecture (`terraform/`)

The [`terraform/`](file:///c:/Users/dhana/asa-assignment/terraform/) directory provides complete cloud infrastructure to deploy the VulnTracker API to **AWS ECS Fargate**:

| File | Purpose & Security Controls Implemented |
| :--- | :--- |
| [`terraform/main.tf`](file:///c:/Users/dhana/asa-assignment/terraform/main.tf) | Provisions ECS Cluster, CloudWatch log group with KMS encryption, Task Definition with pinned CPU/memory limits, read-only rootfs, dropped capabilities, and ECS Fargate service in private subnets. |
| [`terraform/secrets.tf`](file:///c:/Users/dhana/asa-assignment/terraform/secrets.tf) | Creates AWS Secrets Manager secret for application credentials and a Customer-Managed KMS Key with automatic 30-day key rotation (`enable_key_rotation = true`). |
| [`terraform/security_groups.tf`](file:///c:/Users/dhana/asa-assignment/terraform/security_groups.tf) | Configures least-privilege security groups: ALB restricted strictly to HTTPS (443); ECS tasks restricted strictly to ALB ingress on port 8000 with zero direct public access. |
| [`terraform/iam.tf`](file:///c:/Users/dhana/asa-assignment/terraform/iam.tf) | Defines granular IAM execution and task roles. Grants permission strictly to the VulnTracker Secrets Manager secret ARN and KMS key ARN. |
| [`terraform/variables.tf`](file:///c:/Users/dhana/asa-assignment/terraform/variables.tf) | Configures environment parameters (VPC ID, subnet IDs, CPU, memory, container image tag, port). |
| [`terraform/outputs.tf`](file:///c:/Users/dhana/asa-assignment/terraform/outputs.tf) | Exports cluster name, service name, Secrets Manager secret ARN, and task security group ID. |

---

## 4.4 Verification of Cloud Security Controls & Compliance

The infrastructure code was audited using Trivy IaC scanning and manually verified against all task requirements:

### 1. Secret Management (Zero Hardcoded Credentials)
- **Requirement**: Source secrets from a secrets manager (not hardcoded in manifests or env vars).
- **Implementation**:
  - `aws_secretsmanager_secret.app_secrets` stores `SECRET_KEY` and `DB_PASSWORD`.
  - Encrypted with Customer Managed KMS Key (`aws_kms_key.secrets_key`).
  - Injected into ECS container definition via direct Secrets Manager ARN references:
    ```hcl
    secrets = [
      {
        name      = "SECRET_KEY"
        valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:SECRET_KEY::"
      },
      {
        name      = "DB_PASSWORD"
        valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:DB_PASSWORD::"
      }
    ]
    ```
  - `iam.tf` grants `secretsmanager:GetSecretValue` strictly scoped to the exact secret ARN (`Resource = [aws_secretsmanager_secret.app_secrets.arn]`).

### 2. Network Ingress Restriction (Least Privilege)
- **Requirement**: Restrict network ingress to only what is required.
- **Implementation**:
  - **ALB Security Group** (`aws_security_group.alb`): Ingress allowed only on HTTPS port 443 (`protocol = "tcp"`, `from_port = 443`, `to_port = 443`). Egress allowed strictly to the ECS task security group on container port 8000.
  - **ECS Task Security Group** (`aws_security_group.ecs_tasks`): Ingress allowed **strictly from the ALB security group** (`security_groups = [aws_security_group.alb.id]`, `from_port = 8000`, `to_port = 8000`). **Zero public IP or internet ingress allowed**.
  - Deployed across private subnets (`private_subnet_ids`).

### 3. Resource Limits & Security Contexts
- **Requirement**: Define resource limits and security contexts.
- **Implementation**:
  - **CPU & Memory Limits**: Pinned to `cpu = "256"` (0.25 vCPU) and `memory = "512"` (512 MiB), preventing resource starvation.
  - **Read-Only Root Filesystem**: `readonlyRootFilesystem = true` prevents runtime filesystem manipulation, arbitrary file writes, or persistence of unauthorized executables.
  - **Temporary Write Volume**: Ephemeral tmpfs volume mounted at `/tmp` for temporary files and SQLite operations.
  - **Dropped Linux Capabilities**: `linuxParameters.capabilities.drop = ["ALL"]` strips all Linux kernel capabilities.
  - **Non-Root Execution**: Explicitly enforced in task definition (`user = "10001:10001"`).


