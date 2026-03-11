# Security Code Review - AutoGPT

**Date:** 2026-03-11
**Scope:** Full codebase review of the AutoGPT repository
**Reviewer:** Automated Security Audit

---

## Executive Summary

This report covers a comprehensive security review of the AutoGPT codebase, covering hardcoded secrets, injection vulnerabilities, authentication/authorization gaps, cryptographic weaknesses, CORS misconfigurations, Docker security, and dependency concerns. A total of **15 findings** were identified across **Critical**, **High**, **Medium**, and **Low** severity levels.

| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 4     |
| Medium   | 5     |
| Low      | 3     |

---

## Critical Findings

### 1. Shell Command Injection via LLM-Controlled Input

**Severity:** CRITICAL
**Files:**
- `autogpts/autogpt/autogpt/commands/execute_code.py:300-333`
- `autogpts/autogpt/autogpt/commands/execute_code.py:351-386`

**Description:** The `execute_shell()` and `execute_shell_popen()` functions accept a `command_line` string and pass it to `subprocess.run()` / `subprocess.Popen()` with `shell=True` when no allowlist/denylist is configured. The `validate_command()` function (line 258-282) returns `allow_shell=True` when `shell_command_control` is not set to allowlist or denylist mode:

```python
# Line 279-282
else:
    return True, True  # allow_execute=True, allow_shell=True

# Line 323-327
result = subprocess.run(
    command_line if allow_shell else shlex.split(command_line),
    capture_output=True,
    shell=allow_shell,  # shell=True when no control configured!
)
```

Since the command is sourced from AI/LLM output, a prompt injection or adversarial input could cause arbitrary shell command execution with full `shell=True` capabilities (pipes, redirects, chaining).

**Recommendation:** Default to `shell=False` and use an allowlist-based approach. Never pass unsanitized LLM output to `shell=True`.

---

### 2. Missing Authentication on All API Endpoints (IDOR)

**Severity:** CRITICAL
**Files:**
- `autogpts/forge/forge/sdk/routes/agent_protocol.py` (all endpoints)
- `autogpts/autogpt/autogpt/app/agent_protocol_server.py` (all endpoints)
- `benchmark/agbenchmark/app.py:210-284`

**Description:** All agent protocol API endpoints lack authentication and authorization. Any client can:
- Create, list, and retrieve any task by guessing/iterating `task_id`
- Execute steps on arbitrary tasks
- Download any artifact without ownership verification

The `user_id` field (line 128-129 in `agent_protocol_server.py`) is taken from the request body without validation — a client can claim any identity:

```python
if user_id := (task_request.additional_input or {}).get("user_id"):
    set_user({"id": user_id})  # No verification!
```

**Recommendation:** Implement JWT or OAuth2 authentication middleware. Add ownership verification on all endpoints accessing user-scoped data.

---

### 3. Firebase API Keys and Credentials Committed to Repository

**Severity:** CRITICAL
**Files:**
- `frontend/web/index.html:53-59` — Firebase API key: `AIzaSyBvYLAK_A0uhFuVPQbTxUdVWbb_Lsur9cg`
- `frontend/build/web/index.html:53-59` — Same key in build output
- `frontend/build/web/main.dart.js:101330` — Key compiled into JS bundle
- `frontend/ios/Runner/GoogleService-Info.plist:6-32` — iOS client ID and API key
- `frontend/android/app/google-services.json:3-23` — Android client ID and API key

**Description:** Firebase configuration including API keys, client IDs, project identifiers, and app IDs are committed directly into the repository source and build artifacts. While Firebase API keys are designed to be public-facing (restricted by Firebase Security Rules), the exposure of project IDs and full configuration enables:
- Abuse of Firebase services if security rules are misconfigured
- Enumeration of project resources
- Potential billing abuse

**Recommendation:**
- Verify Firebase Security Rules are restrictive and properly configured
- Move sensitive keys to environment variables injected at build time
- Add `google-services.json` and `GoogleService-Info.plist` to `.gitignore`
- Regenerate keys if security rules were ever misconfigured

---

## High Findings

### 4. Insecure Random Number Generation for Passwords

**Severity:** HIGH
**Files:**
- `benchmark/agbenchmark/challenges/verticals/code/2_password_generator/artifacts_out/password_generator.py:12-18`
- `benchmark/agbenchmark/challenges/deprecated/code/2_file_organizer/...` (similar file)

**Description:** Password generation uses `random.choice()` and `random.shuffle()`, which rely on the Mersenne Twister PRNG — not cryptographically secure:

```python
password = [
    random.choice(string.ascii_lowercase),
    random.choice(string.ascii_uppercase),
    random.choice(string.digits),
    random.choice(string.punctuation),
]
password += [random.choice(characters) for _ in range(length - 4)]
random.shuffle(password)
```

**Recommendation:** Replace `random` with `secrets` module:
```python
import secrets
password = [secrets.choice(characters) for _ in range(length)]
```

---

### 5. MD5 Used for File Integrity Checksums

**Severity:** HIGH
**File:** `autogpts/autogpt/autogpt/commands/file_operations.py:32-34`

**Description:** The `text_checksum()` function uses MD5, which is cryptographically broken:

```python
def text_checksum(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()
```

This is used in file operations logging to track file changes. While this is not a direct authentication mechanism, MD5 collisions are trivially producible, allowing an attacker to craft different file contents with the same checksum.

**Recommendation:** Replace with SHA-256:
```python
return hashlib.sha256(text.encode("utf-8")).hexdigest()
```

---

### 6. CORS Misconfiguration — Wildcard Methods and Headers with Credentials

**Severity:** HIGH
**Files:**
- `autogpts/forge/forge/sdk/agent.py:49-65`
- `autogpts/autogpt/autogpt/app/agent_protocol_server.py:77-92`
- `benchmark/agbenchmark/app.py:120-148`

**Description:** CORS middleware is configured with `allow_methods=["*"]`, `allow_headers=["*"]`, and `allow_credentials=True`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

While origins are restricted to localhost, the wildcard methods/headers combined with credentials increases the attack surface for CSRF-like attacks if an attacker can achieve same-origin conditions.

**Recommendation:**
- Restrict `allow_methods` to specific HTTP verbs: `["GET", "POST", "PUT", "DELETE"]`
- Restrict `allow_headers` to required headers only
- Use environment-specific CORS configuration for production

---

### 7. Docker Containers Run as Root

**Severity:** HIGH
**Files:**
- `autogpts/autogpt/Dockerfile`
- `autogpts/forge/Dockerfile`

**Description:** Neither Dockerfile specifies a `USER` directive, meaning all processes run as `root` inside the container. Combined with the `execute_shell` command that allows AI-driven command execution, this means arbitrary commands execute with root privileges inside the container.

The Forge Dockerfile also has:
- Unpinned base image tag (`python:3.11-slim-buster`) without SHA digest
- Poetry installed via `pip3 install poetry` without version pinning

**Recommendation:**
- Add a non-root user: `RUN useradd -m appuser && USER appuser`
- Pin base images using SHA digests
- Add `--no-new-privileges` security option in docker-compose

---

## Medium Findings

### 8. Hardcoded Test Credentials in Docker Compose

**Severity:** MEDIUM
**File:** `autogpts/autogpt/docker-compose.yml:27-28, 40-41`

**Description:** MinIO (S3-compatible) credentials are hardcoded:
```yaml
AWS_ACCESS_KEY_ID: minio
AWS_SECRET_ACCESS_KEY: minio123
# ...
MINIO_ACCESS_KEY: minio
MINIO_SECRET_KEY: minio123
```

While labeled for testing, if this compose file is used in any non-test context, these credentials provide full access to the object store.

**Recommendation:** Use environment variables or Docker secrets for credentials, even in test configurations.

---

### 9. Missing Security Headers

**Severity:** MEDIUM
**Files:**
- `autogpts/autogpt/autogpt/app/agent_protocol_server.py`
- `autogpts/forge/forge/sdk/agent.py`
- `benchmark/agbenchmark/app.py`

**Description:** No security headers are configured on any of the FastAPI servers:
- No `X-Content-Type-Options: nosniff`
- No `X-Frame-Options: DENY`
- No `Content-Security-Policy`
- No `Strict-Transport-Security` (HSTS)

**Recommendation:** Add security headers middleware:
```python
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
```

---

### 10. YAML Loading with FullLoader

**Severity:** MEDIUM
**Files:**
- `autogpts/autogpt/autogpt/utils.py:10`
- `autogpts/autogpt/autogpt/commands/file_operations_utils.py:71`
- `autogpts/autogpt/autogpt/plugins/plugins_config.py:75`
- `autogpts/autogpt/autogpt/core/resource/model_providers/openai.py:259`
- `autogpts/autogpt/autogpt/config/ai_directives.py:35`
- `autogpts/autogpt/autogpt/config/ai_profile.py:38`

**Description:** All YAML parsing uses `yaml.FullLoader`:
```python
data = yaml.load(file, Loader=yaml.FullLoader)
```

While `FullLoader` is safer than `yaml.Loader` (no arbitrary code execution), it still supports Python-specific tags that could be exploited if loading untrusted YAML. Since some of these files could be influenced by AI-generated content or user input, this is a concern.

**Recommendation:** Use `yaml.SafeLoader` unless Python object deserialization is explicitly needed:
```python
data = yaml.load(file, Loader=yaml.SafeLoader)
```

---

### 11. Poetry Installer Pipe to Python (Supply Chain Risk)

**Severity:** MEDIUM
**File:** `autogpts/autogpt/Dockerfile:27`

**Description:** Poetry is installed by piping a remote script directly into Python:
```dockerfile
RUN curl -sSL https://install.python-poetry.org | python3 -
```

This is a supply chain risk — if `install.python-poetry.org` is compromised, arbitrary code would execute during the Docker build.

**Recommendation:** Pin and verify the installer with a checksum, or install Poetry via `pip install poetry==<version>`.

---

### 12. Sensitive Data in Logging

**Severity:** MEDIUM
**Files:**
- `autogpts/autogpt/autogpt/app/agent_protocol_server.py:135`
- `autogpts/autogpt/autogpt/commands/execute_code.py:319-320`

**Description:** Task input and shell commands are logged, potentially exposing sensitive data:
```python
logger.debug(f"Creating agent for task: '{task.input}'")
logger.info(f"Executing command '{command_line}' in working directory '{os.getcwd()}'")
```

**Recommendation:** Sanitize or truncate logged values. Avoid logging full command lines or task inputs at INFO level.

---

## Low Findings

### 13. Build Artifacts Committed to Repository

**Severity:** LOW
**File:** `frontend/build/web/` (entire directory)

**Description:** Compiled/built web assets are committed to the repository, including the compiled `main.dart.js` (containing Firebase keys). Build artifacts should be generated by CI/CD pipelines, not stored in version control.

**Recommendation:** Add `frontend/build/` to `.gitignore` and remove from version control.

---

### 14. Forge `.env.example` Contains Realistic-Looking Key

**Severity:** LOW
**File:** `autogpts/forge/.env.example`

**Description:** Contains `OPENAI_API_KEY=abc` which, while not a real key, sets a poor example. Users may assume they should commit their actual keys to similar files.

**Recommendation:** Use a clearly placeholder value like `OPENAI_API_KEY=sk-your-key-here`.

---

### 15. No Rate Limiting on API Endpoints

**Severity:** LOW
**Files:**
- `autogpts/forge/forge/sdk/routes/agent_protocol.py`
- `autogpts/autogpt/autogpt/app/agent_protocol_server.py`

**Description:** No rate limiting is implemented on any API endpoint. Combined with the lack of authentication (Finding #2), this allows unlimited task creation, step execution, and artifact downloads.

**Recommendation:** Add rate limiting middleware (e.g., `slowapi` for FastAPI) to protect against abuse and resource exhaustion.

---

## Summary of Recommendations (Priority Order)

| Priority | Action | Findings |
|----------|--------|----------|
| 1 | Implement authentication/authorization on all API endpoints | #2, #15 |
| 2 | Default `shell=False` for command execution; enforce allowlist | #1 |
| 3 | Rotate and externalize Firebase credentials | #3 |
| 4 | Replace `random` with `secrets` for password generation | #4 |
| 5 | Replace MD5 with SHA-256 for checksums | #5 |
| 6 | Add non-root USER to Dockerfiles | #7 |
| 7 | Restrict CORS methods/headers | #6 |
| 8 | Use `yaml.SafeLoader` for YAML parsing | #10 |
| 9 | Add security headers middleware | #9 |
| 10 | Externalize test credentials | #8 |
| 11 | Fix Poetry install supply chain risk | #11 |
| 12 | Sanitize logging output | #12 |
| 13 | Remove build artifacts from repo | #13 |
