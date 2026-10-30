# VulnTracker Security Assessment: Prioritised Findings

## Executive Summary

A comprehensive security analysis of the **VulnTracker** application was conducted using a defense-in-depth assessment methodology combining:
- **Static Application Security Testing (SAST)**: Bandit v1.9.4
- **Software Composition Analysis (SCA)**: Trivy v0.76.0 and pip-audit v2.10.1
- **Container Image Security Scanning**: Trivy v0.76.0
- **Infrastructure-as-Code (IaC) Scanning**: Trivy v0.76.0
- **Manual Application Security Architecture & Code Review**

Raw scan artifacts from automated tooling are stored in the [`reports/`](file:///c:/Users/dhana/asa-assignment/reports/) directory (`sast.bandit.json`, `sca.trivy.json`, `sca.pip-audit.json`, `container.trivy.json`, and `iac.trivy.json`).

The findings have been triaged, contextualized, and prioritised based on actual exploitative impact to the VulnTracker platform. As VulnTracker is an internal security system designed to centralize and track an organization's vulnerability findings, **the confidentiality and integrity of its data are paramount**. A breach of VulnTracker represents an existential security risk, as it grants adversaries a pre-compiled blueprint of all vulnerabilities across corporate infrastructure.

---

## Prioritised Findings Matrix

| Finding ID | Vulnerability / Issue | Tool & Scan Type | Assessed Severity | Origin | Justification & Business Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VT-01** | **SQL Injection via String Formatting in Scan Search** | SAST (Bandit B608) & Manual Review | **CRITICAL** | Starter Code (`app/database.py`) | Unsanitized input is interpolated into raw SQL. Allows complete database extraction (all findings, passwords, hashes) or SQLite write/attach execution. |
| **VT-02** | **Hardcoded JWT Secret & Acceptance of `"none"` Algorithm** | SAST (Bandit B105) & Manual Review | **CRITICAL** | Starter Code (`app/config.py`, `app/auth.py`) | Hardcoded secret key combined with explicitly decoding `"none"` algorithm permits unauthenticated forged JWT tokens, enabling full authentication bypass. |
| **VT-03** | **Unauthenticated Webhook Registration & SSRF with Service Key Leakage** | Manual Review & SCA | **CRITICAL** | Starter Code (`notify/src/index.js`, `notify/src/dispatcher.js`) | Public `/webhooks` accepts arbitrary targets with zero network validation. Dispatcher sends internal `X-Service-Key` to attacker-controlled endpoints and allows internal cloud metadata targeting. |
| **VT-04** | **Permissive CORS Wildcard Reflection with Credentials** | Manual Review | **HIGH** | Starter Code (`app/main.py`) | Reflects any incoming `Origin` while enabling `Access-Control-Allow-Credentials: true`. Bypasses SOP, allowing malicious sites visited by authenticated users to exfiltrate findings. |
| **VT-05** | **Plaintext Credential Logging in Authentication Handlers** | Manual Review | **HIGH** | Starter Code (`app/main.py`) | Logs raw user passwords in cleartext on every login attempt (success and failure), exposing credentials across log aggregators (CloudWatch, Datadog) and violating compliance standards. |
| **VT-06** | **High-Severity Known CVEs in Pinned Dependencies** | SCA (Trivy & pip-audit) | **HIGH** | Starter Code (`requirements.txt`, `notify/package.json`) | Memory corruption/type confusion in `cryptography==38.0.1` (CVE-2023-0286, CVE-2023-23931), ReDoS in `python-multipart` (CVE-2024-24762), and SSRF/redirect leaks in `axios@0.21.1` (CVE-2023-45857). |
| **VT-07** | **Sensitive Information & Stack Trace Disclosure in Global Exception Handler** | Manual Review | **MEDIUM** | Starter Code (`app/main.py`) | Catches all unhandled exceptions and returns `traceback.format_exc()` to unauthenticated callers, leaking internal paths, framework internals, and database schema. |
| **VT-08** | **Lack of Rate Limiting on Authentication & Shared Report Links** | Manual Review | **MEDIUM** | Starter Code & New Feature (`app/main.py`) | No rate limiting on `POST /auth/login` (credential stuffing) or `GET /share/{token}` (password-protected report brute-forcing). |
| **VT-09** | **Over-Permissive Outbound Egress in Container Security Group** | IaC Scan (Trivy AWS-0104) | **LOW** | Infrastructure (`terraform/security_groups.tf`) | Task security group allows outbound `0.0.0.0/0` on port 443. Egress should ideally be restricted via private VPC Endpoints for S3, ECR, and Secrets Manager. |
| **VT-10** | **Base OS Image Vulnerabilities in Container Runtime** | Container Scan (Trivy) | **LOW** | Dockerfile (`python:3.11-slim-bookworm`) | Common vulnerabilities in underlying Debian libraries (glibc, libssl). Substantially mitigated by non-root execution (UID 10001), read-only rootfs, and dropped Linux capabilities. |

---

## Detailed Findings Analysis

### VT-01: SQL Injection via String-Based Query Construction (app/database.py)
- **Detected By**: SAST (`bandit` rule B608) & Manual Review.
- **Location**: [`app/database.py:L20-L29`](file:///c:/Users/dhana/asa-assignment/app/database.py#L20-L29).
- **Assessed Severity**: **CRITICAL** (Bandit rates as Medium, but operational exploitability makes this Critical).
- **Technical Analysis**:
  In `search_scans_by_query`:
  ```python
  sql = (
      f"SELECT id, title, description, severity, status, cve_id, "
      f"affected_component, owner_id, created_at FROM scan_results "
      f"WHERE title LIKE '%{query}%' OR description LIKE '%{query}%' "
      f"OR cve_id LIKE '%{query}%'"
  )
  result = db.execute(text(sql))
  ```
  User-controlled query parameter `q` from `GET /scans/search?q=...` is concatenated directly into the SQL statement without parameterization or escaping.
- **Exploit Scenario**:
  An authenticated attacker issues a payload such as:
  `GET /scans/search?q=' UNION SELECT id, username, email, hashed_password, 'high', 'open', 'CVE', owner_id, created_at FROM users --`
  This dumps the entire users table, including password hashes, salt, and administrative credentials.
- **Business Impact**: Complete data breach of vulnerability database and user credentials. Compromises confidentiality and integrity of all tracked corporate assets.

---

### VT-02: Hardcoded JWT Secret & Insecure `"none"` Algorithm Acceptance (app/config.py, app/auth.py)
- **Detected By**: SAST (`bandit` rule B105) & Manual Review.
- **Location**: [`app/config.py:L3`](file:///c:/Users/dhana/asa-assignment/app/config.py#L3) and [`app/auth.py:L38`](file:///c:/Users/dhana/asa-assignment/app/auth.py#L38).
- **Assessed Severity**: **CRITICAL**.
- **Technical Analysis**:
  In `config.py`:
  ```python
  SECRET_KEY = "v3ry-s3cr3t-jwt-k3y-do-not-share"
  ```
  In `auth.py`:
  ```python
  payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "none"])
  ```
  The JWT verification explicitly allows the unauthenticated `"none"` algorithm, while the symmetric signing secret is hardcoded directly in version control.
- **Exploit Scenario**:
  An external attacker constructs an unsigned JWT header `{"alg": "none", "typ": "JWT"}` and body `{"sub": "admin"}` with an empty signature. The server validates this as an authentic session for the `admin` account. Even without `"none"`, an attacker uses the public Git secret to mint valid tokens for any user.
- **Business Impact**: Total authentication bypass. Any actor can impersonate any user, read private scans, alter vulnerability findings, or delete records.

---

### VT-03: Unauthenticated Webhook Registration & SSRF with Token Leakage (notify/src/)
- **Detected By**: Manual Review & SCA.
- **Location**: [`notify/src/index.js:L14-L32`](file:///c:/Users/dhana/asa-assignment/notify/src/index.js#L14-L32) and [`notify/src/dispatcher.js:L4-L21`](file:///c:/Users/dhana/asa-assignment/notify/src/dispatcher.js#L4-L21).
- **Assessed Severity**: **CRITICAL**.
- **Technical Analysis**:
  `POST /webhooks` allows unauthenticated callers to register arbitrary webhook URLs. When scan events are dispatched, `dispatcher.js` sends an HTTP POST to the registered URL containing both the scan payload and an internal secret header:
  ```javascript
  headers: {
    'Content-Type': 'application/json',
    'X-Service-Key': config.SERVICE_KEY,
  }
  ```
- **Exploit Scenario**:
  1. An attacker registers `http://169.254.169.254/latest/meta-data/` to probe cloud metadata, or registers an external server (`https://attacker.com/sink`).
  2. The next scan creation dispatches the notification, delivering the internal `X-Service-Key` and scan findings directly to the attacker.
- **Business Impact**: Internal network reconnaissance, cloud credential exfiltration via SSRF, and credential disclosure of the service key.

---

### VT-04: Permissive CORS Reflection with Credentials Enabled (app/main.py)
- **Detected By**: Manual Review.
- **Location**: [`app/main.py:L31-L40`](file:///c:/Users/dhana/asa-assignment/app/main.py#L31-L40).
- **Assessed Severity**: **HIGH**.
- **Technical Analysis**:
  ```python
  @app.middleware("http")
  async def cors_middleware(request: Request, call_next):
      response = await call_next(request)
      origin = request.headers.get("origin")
      if origin:
          response.headers["Access-Control-Allow-Origin"] = origin
          response.headers["Access-Control-Allow-Credentials"] = "true"
  ```
  The middleware reflects whatever `Origin` header is supplied by the client and sets `Access-Control-Allow-Credentials: true`.
- **Exploit Scenario**:
  An authenticated security engineer visits an external malicious site (e.g., `evil-tracker.com`). The site runs background JavaScript making cross-origin requests to `http://localhost:8000/scans` with credentials. The browser permits the response to be read by `evil-tracker.com`.
- **Business Impact**: Cross-site data exfiltration. Attackers can steal internal vulnerability reports simply by enticing logged-in users to click a link.

---

### VT-05: Plaintext Password Logging in Authentication (app/main.py)
- **Detected By**: Manual Review.
- **Location**: [`app/main.py:L158, L161-L165`](file:///c:/Users/dhana/asa-assignment/app/main.py#L158-L165).
- **Assessed Severity**: **HIGH**.
- **Technical Analysis**:
  ```python
  logger.info("Login attempt — username: %s password: %s", payload.username, payload.password)
  logger.warning("Failed login — username: '%s' password: '%s'", payload.username, payload.password)
  ```
  Plaintext passwords (including mistyped passwords or valid user passwords) are written to standard logging outputs.
- **Exploit Scenario**:
  Application logs are forwarded to SIEM/centralized log aggregators (CloudWatch, Elasticsearch, Datadog). Operators, contractors, or support personnel with read-only log access can read plaintext user passwords.
- **Business Impact**: Credential harvesting, compliance violations (PCI DSS, ISO 27001, SOC 2), and risk of account compromise across other corporate systems due to password reuse.

---

### VT-06: High-Severity Known CVEs in Pinned Dependencies
- **Detected By**: SCA (`pip-audit` & `trivy fs`).
- **Location**: [`requirements.txt`](file:///c:/Users/dhana/asa-assignment/requirements.txt) and [`notify/package.json`](file:///c:/Users/dhana/asa-assignment/notify/package.json).
- **Assessed Severity**: **HIGH**.
- **Technical Analysis**:
  1. `cryptography==38.0.1`: Multiple known vulnerabilities including **CVE-2023-0286** (Type confusion in X.400 address parsing leading to denial-of-service / arbitrary memory read) and **CVE-2023-23931** (Memory corruption in ciphers).
  2. `python-multipart==0.0.6`: **CVE-2024-24762** (Denial of Service via regular expression backtracking in form boundary parsing).
  3. `axios@0.21.1`: **CVE-2023-45857** (SSRF and header leakage across redirects) and **CVE-2021-3749** (ReDoS).
- **Business Impact**: Service crashes, resource exhaustion, and remote denial-of-service against API gateways during heavy scanning periods.

---

### VT-07: Sensitive Information & Stack Trace Disclosure (app/main.py)
- **Detected By**: Manual Review.
- **Location**: [`app/main.py:L43-L54`](file:///c:/Users/dhana/asa-assignment/app/main.py#L43-L54).
- **Assessed Severity**: **MEDIUM**.
- **Technical Analysis**:
  The global exception handler intercepts unhandled exceptions and returns:
  ```json
  {
    "error": "...",
    "type": "ExceptionName",
    "traceback": "Traceback (most recent call last):\n  File ...",
    "path": "..."
  }
  ```
- **Business Impact**: Leaks server directory structures, internal package versions, and operational details, easing an attacker's reconnaissance and exploit chain development.

---

### VT-08: Lack of Rate Limiting on Authentication & Shared Report Links (app/main.py)
- **Detected By**: Manual Review.
- **Location**: [`app/main.py`](file:///c:/Users/dhana/asa-assignment/app/main.py) (`/auth/login`, `/share/{token}`, `/scans/{scan_id}/share`).
- **Assessed Severity**: **MEDIUM**.
- **Technical Analysis**:
  Neither the login endpoint nor the shared report link endpoint enforces request throttling. An attacker with a protected shared report token can execute rapid dictionary attacks against `GET /share/{token}?password=...` without lockout.
- **Business Impact**: Potential unauthorized access to password-protected shared scan findings through automated password guessing.

---

### VT-09: Over-Permissive Egress in Security Groups (terraform/security_groups.tf)
- **Detected By**: IaC Security Scan (`trivy config` check AWS-0104).
- **Location**: [`terraform/security_groups.tf:L60-L67`](file:///c:/Users/dhana/asa-assignment/terraform/security_groups.tf#L60-L67).
- **Assessed Severity**: **LOW / MEDIUM** (Scanner rates as Critical; operational context is Low/Medium).
- **Technical Analysis**:
  The ECS task security group defines outbound egress to `0.0.0.0/0` on port 443. While HTTPS egress is standard for container pulling, AWS APIs, and outbound webhooks, defense-in-depth best practices recommend routing through private VPC Endpoints (PrivateLink) and a restricted egress proxy.
- **Business Impact**: If an application container is compromised, the attacker can establish outbound reverse shells or exfiltrate data to arbitrary external IP addresses over HTTPS.

---

### VT-10: Base Container Image Vulnerabilities
- **Detected By**: Container Scan (`trivy image`).
- **Location**: Dockerfile (`python:3.11-slim-bookworm`).
- **Assessed Severity**: **LOW**.
- **Technical Analysis**:
  Trivy detected Debian distribution vulnerabilities in base system libraries (`glibc`, `openssl`).
- **Mitigating Controls**:
  The production Dockerfile implements:
  - Non-root user execution (`USER 10001:10001`).
  - Read-only root filesystem (`readonlyRootFilesystem = true`).
  - Dropped Linux capabilities (`drop = ["ALL"]`).
  These runtime controls prevent privilege escalation and persistent modifications even if an OS-level vulnerability exists.
