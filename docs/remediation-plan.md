# VulnTracker Security Remediation Plan & Analysis

This document details the code-level security fixes applied during **Task 3**, along with a strategic remediation plan for all deferred findings, outlining residual risk, remediation effort, and compensating controls.

---

## 1. Summary of Applied Code-Level Fixes

In accordance with Task 3 requirements, high- and critical-severity findings were remediated in code, including a critical security enhancement applied directly to the Task 1 feature:

| Finding ID | Vulnerability Fixed | Severity | File(s) Modified | Summary of Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **VT-01** | **SQL Injection in Scan Search** | **CRITICAL** | [`app/database.py`](file:///c:/Users/dhana/asa-assignment/app/database.py) | Replaced raw f-string SQL query concatenation with parameterized query binding (`:pattern`) via SQLAlchemy `text()`. |
| **VT-02** | **JWT Algorithm Confusion & Hardcoded Secrets** | **CRITICAL** | [`app/auth.py`](file:///c:/Users/dhana/asa-assignment/app/auth.py)<br>[`app/config.py`](file:///c:/Users/dhana/asa-assignment/app/config.py) | Removed `"none"` algorithm from `jwt.decode()`; enforced cryptographic signature check. Refactored secrets to read from environment variables. |
| **VT-08** | **Shared Report Link Brute-Force & Lack of Rate Limiting** *(Task 1 Code Fix)* | **HIGH** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Implemented attempt tracking and automated lockout on `GET /share/{token}`. Rejects attackers with `429 Too Many Requests` after 5 failed password attempts. |
| **VT-05** | **Plaintext Credential Logging in Authentication** | **HIGH** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Stripped `payload.password` from `logger.info` and `logger.warning` statements during login processing. |
| **VT-04** | **Permissive CORS Reflection with Credentials** | **HIGH** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Replaced wildcard origin reflection with strict `ALLOWED_ORIGINS` whitelist and restricted headers. |
| **VT-07** | **Stack Trace Information Disclosure** | **MEDIUM** | [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) | Sanitized global HTTP 500 error response to prevent internal file path and schema leakage. |

---

## 2. Technical Details of Implemented Fixes

### Fix 1: Parameterized SQL Queries in Scan Search (VT-01)
- **Vulnerability**: In `app/database.py`, user input from `GET /scans/search?q=...` was directly formatted into a SQL string:
  ```python
  # INSECURE (Before)
  sql = f"SELECT ... WHERE title LIKE '%{query}%' OR description LIKE '%{query}%' ..."
  result = db.execute(text(sql))
  ```
- **Remediation**: Replaced string interpolation with parameterized bind parameters:
  ```python
  # SECURE (After)
  sql = text(
      "SELECT id, title, description, severity, status, cve_id, "
      "affected_component, owner_id, created_at FROM scan_results "
      "WHERE title LIKE :pattern OR description LIKE :pattern OR cve_id LIKE :pattern"
  )
  pattern = f"%{query}%"
  result = db.execute(sql, {"pattern": pattern})
  ```
- **Verification**: Bandit SAST rule B608 is completely resolved. Automated test `test_search_scans_prevents_sql_injection` verifies that SQL union/injection payloads are treated strictly as string literals, returning 0 records.

---

### Fix 2: Cryptographic Signature Enforcement in JWT Decoding (VT-02)
- **Vulnerability**: In `app/auth.py`, `decode_token` explicitly accepted the unauthenticated `"none"` algorithm:
  ```python
  # INSECURE (Before)
  payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "none"])
  ```
  Additionally, `SECRET_KEY` was hardcoded in Git.
- **Remediation**:
  1. Enforced strict cryptographic algorithm checking:
     ```python
     # SECURE (After)
     payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
     ```
  2. Refactored `app/config.py` to source `SECRET_KEY`, `DB_PASSWORD`, and `ADMIN_API_KEY` from environment variables, integrating with AWS Secrets Manager in production.
- **Verification**: Automated test `test_jwt_rejects_none_algorithm` verifies that unsigned `"alg": "none"` tokens are rejected with `401 Unauthorized`.

---

### Fix 3: Task 1 Feature Remediation — Shared Report Brute-Force Rate Limiter (VT-08)
- **Vulnerability**: The public endpoint `GET /share/{token}` created in Task 1 had no attempt throttling or lockout mechanism. Malicious actors could mount automated dictionary or brute-force attacks against password-protected shared scan links.
- **Remediation**: Added an in-memory attempt tracker that monitors failed password attempts per token:
  ```python
  # SECURE (After)
  if not is_valid:
      _share_link_rate_limits[token_hash]["failed_attempts"] += 1
      if _share_link_rate_limits[token_hash]["failed_attempts"] >= MAX_SHARE_PASSWORD_ATTEMPTS:
          _share_link_rate_limits[token_hash]["locked_until"] = now + timedelta(minutes=SHARE_LOCKOUT_MINUTES)
          raise HTTPException(
              status_code=status.HTTP_429_TOO_MANY_REQUESTS,
              detail="Too many failed password attempts. Link is temporarily locked.",
              headers={"Retry-After": str(SHARE_LOCKOUT_MINUTES * 60)},
          )
      raise HTTPException(status_code=403, detail="Password required or incorrect")
  ```
- **Verification**: Automated test `test_share_scan_rate_limiting_lockout` verifies that 5 failed attempts trigger an HTTP `429 Too Many Requests` response with a `Retry-After` header.

---

### Fix 4: Plaintext Password Logging Removal (VT-05)
- **Vulnerability**: `app/main.py` logged plaintext passwords on every login attempt (both success and failure):
  ```python
  # INSECURE (Before)
  logger.info("Login attempt — username: %s password: %s", payload.username, payload.password)
  logger.warning("Failed login — username: '%s' password: '%s'", payload.username, payload.password)
  ```
- **Remediation**: Stripped the password parameter completely:
  ```python
  # SECURE (After)
  logger.info("Login attempt for username: %s", payload.username)
  logger.warning("Failed login attempt for username: %s", payload.username)
  ```
- **Verification**: Verified via manual inspection and test suite execution; zero sensitive authentication tokens or plaintext passwords appear in application logs.

---

### Fix 5: Strict CORS Origin Whitelisting (VT-04)
- **Vulnerability**: The CORS middleware reflected any incoming `Origin` header while setting `Access-Control-Allow-Credentials: true`, completely bypassing the Same-Origin Policy.
- **Remediation**: Enforced an explicit origin whitelist (`ALLOWED_ORIGINS`) and restricted allowable headers to `Authorization, Content-Type`.
- **Verification**: Verified that external origins do not receive credentialed CORS headers.

---

### Fix 6: Stack Trace Sanitization in Error Responses (VT-07)
- **Vulnerability**: Unhandled exceptions returned `traceback.format_exc()` to unauthenticated clients, leaking internal file paths and framework internals.
- **Remediation**: Global exception handler logs tracebacks internally (`exc_info=True`) and returns an opaque error payload (`{"error": "Internal Server Error"}`).

---

## 3. Plan for Deferred Findings

The following security findings were identified during Task 2 and intentionally deferred from immediate code modification. This section outlines the business justification, residual risk, estimated remediation effort, and active compensating controls.

---

### Deferred Finding 1: Unauthenticated Webhook Registration & SSRF in `notify/` (VT-03)
- **Component**: Node.js Notification Service (`notify/src/index.js`, `notify/src/dispatcher.js`).
- **Severity**: **CRITICAL**.
- **Reason for Deferral**: The project brief specifies that the Python FastAPI service is the primary focus of extension and remediation (`notify/`: "Node.js notification service (no changes required)"). Upgrading the notification service requires an architecture refactor across both services.
- **Residual Risk**: If an attacker gains direct network access to the notification service port (3001), they can register arbitrary internal URLs (e.g. AWS metadata `169.254.169.254` or internal microservices) and capture dispatched scan payloads and internal headers (`X-Service-Key`).
- **Remediation Effort**: **~1–2 engineering days**.
  1. Add authentication to `POST /webhooks` (e.g., shared HMAC secret or API key).
  2. Implement strict URL validation with an SSRF-safe library that resolves DNS and blocks private/reserved IP ranges (RFC 1918, RFC 3927 link-local `169.254.0.0/16`, and loopback).
  3. Strip internal credentials (`X-Service-Key`) from external webhook dispatch payloads.
- **Compensating Controls**:
  - **Network Segmentation**: In the production deployment (`terraform/`), the notification service is deployed in an isolated private subnet with **zero public ingress**.
  - **Security Group Ingress Filtering**: Only the internal FastAPI task security group is permitted to reach the notification service port.
  - **IAM Metadata Protections**: Deploy with IMDSv2 (enforcing hop limits) to block SSRF exfiltration of AWS instance profile credentials.

---

### Deferred Finding 2: High-Severity CVEs in Pinned Dependencies (VT-06)
- **Component**: Python & Node.js Dependencies (`requirements.txt`, `notify/package.json`).
- **Severity**: **HIGH**.
- **Reason for Deferral**: Bumping major dependencies (`cryptography==38.0.1` to `42.x`, `axios@0.21.1` to `1.7.x`, `express@4.18.2` to `4.21.x`) introduces breaking API changes and binary compilation differences that require complete integration regression testing across both services.
- **Residual Risk**:
  - Potential Denial of Service (ReDoS) via `python-multipart` (CVE-2024-24762) during large form uploads.
  - Memory corruption or PKCS7 denial-of-service in outdated OpenSSL bindings in `cryptography` (CVE-2023-0286, CVE-2023-23931).
  - Webhook dispatch header leak in `axios` redirects (CVE-2023-45857).
- **Remediation Effort**: **~0.5–1 engineering day**.
  - Update `requirements.txt`:
    - `cryptography>=42.0.8`
    - `python-multipart>=0.0.18`
    - `fastapi>=0.109.0`
  - Update `notify/package.json`:
    - `npm update express axios`
- **Compensating Controls**:
  - **Container Isolation**: The container executes as an unprivileged user (`UID 10001`) with a **read-only root filesystem** (`readonlyRootFilesystem = true`).
  - **Dropped Capabilities**: All Linux kernel capabilities are dropped (`capabilities = { drop = ["ALL"] }`), preventing kernel exploitation even in the event of native library memory corruption.
  - **Resource Limits**: Pinned task limits (CPU 256, Memory 512 MiB) mitigate the impact of memory exhaustion or ReDoS attacks.

---

### Deferred Finding 3: Over-Permissive Outbound Egress in Security Groups (VT-09)
- **Component**: Infrastructure (`terraform/security_groups.tf`).
- **Severity**: **LOW / MEDIUM**.
- **Reason for Deferral**: The prototype service requires outbound HTTPS access to download container images and dispatch webhooks to arbitrary public stakeholder URLs without requiring enterprise VPC Endpoints.
- **Residual Risk**: A compromised container could establish an outbound TCP/HTTPS reverse shell to an external command-and-control server.
- **Remediation Effort**: **~2–4 engineering hours**.
  1. Provision AWS VPC Endpoints (PrivateLink) for ECR, CloudWatch Logs, and Secrets Manager.
  2. Route egress traffic through an AWS Network Firewall or Squid forward proxy enforcing a domain whitelist.
- **Compensating Controls**:
  - Ingress is strictly locked down: zero inbound public traffic can reach the container directly; all ingress must traverse the ALB on port 443.
  - The container runs a non-interactive shell (`/sbin/nologin`) under a non-root account.

---

### Deferred Finding 4: Upstream Base OS Vulnerabilities (VT-10)
- **Component**: Container Runtime (`Dockerfile`).
- **Severity**: **LOW**.
- **Reason for Deferral**: Debian Bookworm slim base packages (`glibc`, `libssl3`) are maintained by the Debian security team; patches are absorbed as upstream releases are published.
- **Residual Risk**: Theoretical local privilege escalation or information disclosure via low-severity system library flaws.
- **Remediation Effort**: **~1–2 engineering hours**.
  - Migrate to a Distroless container image (`gcr.io/distroless/python3-debian12`) or Chainguard Wolfi image to eliminate package managers, shells, and unnecessary C utilities.
- **Compensating Controls**:
  - Multi-stage build strips build compilers (`gcc`, `libffi-dev`) from the final runtime image.
  - Runtime executes with `no-new-privileges` flag and non-root UID.

---

## 4. Engineering Roadmap & Preventive Controls

To prevent recurrence of these vulnerabilities in future development cycles, the following DevSecOps controls are recommended:

1. **Pre-Commit SAST & Secret Linting**:
   - Integrate `bandit` and `detect-secrets` into pre-commit git hooks to prevent hardcoded credentials from reaching version control.
2. **Automated CI Security Quality Gates**:
   - Add automated GitHub Actions steps that run `bandit -r app/` and `trivy fs` on every pull request, blocking merges on Critical/High findings.
3. **Automated Dependency Management**:
   - Deploy Renovate Bot or Dependabot to automate third-party dependency updates and patch CVEs proactively.
4. **Secret Management Lifecycle**:
   - Mandate AWS Secrets Manager with KMS automatic key rotation for all production environments, prohibiting plaintext credentials in application source files.
