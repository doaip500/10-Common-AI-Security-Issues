# 🛠️ AI Security Tools Reference

> Complete tooling reference for all 10 AI security issues — organized by category.

---

## ⚔️ Offensive / Red Team Tools

| Tool | Category | Issues | Link |
|------|----------|--------|-------|
| **Garak** | LLM vulnerability scanner | #01 #07 #09 | [github.com/leondz/garak](https://github.com/leondz/garak) |
| **PyRIT** | Microsoft AI Red Teaming | #01 #08 | [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT) |
| **Promptfoo** | LLM testing CLI | #01 #06 | [github.com/promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) |
| **promptmap** | Automated prompt injection tester | #01 | [github.com/utkusen/promptmap](https://github.com/utkusen/promptmap) |
| **ART (IBM)** | Adversarial Robustness Toolbox | #02 #03 #04 #10 | [github.com/Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **BackdoorBox** | Backdoor attack toolkit | #02 | [github.com/THUYimingLi/BackdoorBox](https://github.com/THUYimingLi/BackdoorBox) |
| **ML Privacy Meter** | Membership inference attacks | #03 | [github.com/privacytrustlab/ml_privacy_meter](https://github.com/privacytrustlab/ml_privacy_meter) |
| **TextAttack** | NLP adversarial attacks | #04 | [github.com/QData/TextAttack](https://github.com/QData/TextAttack) |
| **Foolbox** | Adversarial attack framework | #04 | [github.com/bethgelab/foolbox](https://github.com/bethgelab/foolbox) |
| **CleverHans** | TF adversarial examples | #04 | [github.com/cleverhans-lab/cleverhans](https://github.com/cleverhans-lab/cleverhans) |
| **Picklescan** | ML model malware scanner | #05 | [github.com/mmaitre314/picklescan](https://github.com/mmaitre314/picklescan) |
| **fickling** | Pickle security analysis | #05 | [github.com/trailofbits/fickling](https://github.com/trailofbits/fickling) |
| **Knockoff Nets** | Model extraction attacks | #10 | [github.com/tribhuvanesh/knockoffnets](https://github.com/tribhuvanesh/knockoffnets) |
| **Locust** | LLM API load testing | #09 | [locust.io](https://locust.io) |
| **TruffleHog** | Secret/credential scanner | #07 | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |

---

## 🛡️ Defensive Tools

| Tool | Category | Issues | Link |
|------|----------|--------|-------|
| **LLM Guard** | Input/output sanitization | #01 #06 #07 | [github.com/protectai/llm-guard](https://github.com/protectai/llm-guard) |
| **NeMo Guardrails** | Agent constraint framework | #01 #08 | [github.com/NVIDIA/NeMo-Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) |
| **Rebuff** | Prompt injection detection | #01 | [github.com/protectai/rebuff](https://github.com/protectai/rebuff) |
| **ModelScan** | Model file threat scanning | #05 | [github.com/protectai/modelscan](https://github.com/protectai/modelscan) |
| **Microsoft Presidio** | PII detection & anonymization | #03 #07 | [github.com/microsoft/presidio](https://github.com/microsoft/presidio) |
| **Opacus (PyTorch)** | Differential privacy training | #03 | [github.com/pytorch/opacus](https://github.com/pytorch/opacus) |
| **TensorFlow Privacy** | DP-SGD training | #03 | [github.com/tensorflow/privacy](https://github.com/tensorflow/privacy) |
| **CleanLab** | Training data quality | #02 | [github.com/cleanlab/cleanlab](https://github.com/cleanlab/cleanlab) |
| **Neural Cleanse** | Backdoor scanning | #02 | [github.com/bolunwang/backdoor](https://github.com/bolunwang/backdoor) |
| **Sigstore** | ML artifact signing | #05 | [sigstore.dev](https://sigstore.dev) |
| **SafeTensors** | Safe model serialization | #05 | [github.com/huggingface/safetensors](https://github.com/huggingface/safetensors) |
| **DOMPurify** | HTML output sanitization | #06 | [github.com/cure53/DOMPurify](https://github.com/cure53/DOMPurify) |
| **pip-audit** | Python dependency CVE scanner | #05 | [github.com/pypa/pip-audit](https://github.com/pypa/pip-audit) |
| **LM Watermarking** | LLM output watermarking | #10 | [github.com/jwkirchenbauer/lm-watermarking](https://github.com/jwkirchenbauer/lm-watermarking) |
| **Radioactive Data** | Training data watermarking | #10 | [github.com/facebookresearch/radioactive_data](https://github.com/facebookresearch/radioactive_data) |
| **Syft** | SBOM generation | #05 | [github.com/anchore/syft](https://github.com/anchore/syft) |
| **Grype** | SBOM vulnerability scanner | #05 | [github.com/anchore/grype](https://github.com/anchore/grype) |

---

## 📊 Evaluation & Benchmarking

| Tool | Purpose | Link |
|------|---------|-------|
| **RobustBench** | Adversarial robustness leaderboard | [robustbench.github.io](https://robustbench.github.io) |
| **PromptBench** | LLM adversarial prompt evaluation | [github.com/microsoft/promptbench](https://github.com/microsoft/promptbench) |
| **AgentBench** | LLM agent safety evaluation | [github.com/THUDM/AgentBench](https://github.com/THUDM/AgentBench) |
| **HELM** | Holistic LLM evaluation | [crfm.stanford.edu/helm](https://crfm.stanford.edu/helm/latest/) |
| **lm-evaluation-harness** | Comprehensive LLM evaluation | [github.com/EleutherAI/lm-evaluation-harness](https://github.com/EleutherAI/lm-evaluation-harness) |
| **LM Extraction Benchmark** | Training data extraction testing | [github.com/google-research/lm-extraction-benchmark](https://github.com/google-research/lm-extraction-benchmark) |

---

## 🔍 Monitoring & Observability

| Tool | Purpose | Link |
|------|---------|-------|
| **Prometheus** | Metrics collection & alerting | [prometheus.io](https://prometheus.io) |
| **Grafana** | Visualization of ML metrics | [grafana.com](https://grafana.com) |
| **Elasticsearch** | Log analysis for anomaly detection | [elastic.co](https://elastic.co) |
| **Weights & Biases** | ML experiment tracking | [wandb.ai](https://wandb.ai) |
| **MLflow** | Model registry & lifecycle | [mlflow.org](https://mlflow.org) |
| **Nightfall AI** | DLP for AI outputs | [nightfall.ai](https://nightfall.ai) |

---

## 🌐 Security Frameworks & Standards

| Framework | Relevance | Link |
|-----------|-----------|-------|
| **MITRE ATLAS** | AI/ML threat matrix | [atlas.mitre.org](https://atlas.mitre.org) |
| **OWASP LLM Top 10** | LLM application risks | [owasp.org/llm](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| **NIST AI RMF** | AI risk management | [nist.gov/ai-rmf](https://airc.nist.gov/Home) |
| **NIST AI 100-1** | Adversarial ML taxonomy | [airc.nist.gov](https://airc.nist.gov/Home) |
| **ISO/IEC 27090** | AI security (in development) | [iso.org](https://iso.org) |
| **EU AI Act** | Regulatory framework for AI | [artificialintelligenceact.eu](https://artificialintelligenceact.eu) |
| **ENISA AI Threats** | European AI threat landscape | [enisa.europa.eu](https://enisa.europa.eu) |

---

## 🐍 Python Security Libraries Quick Reference

```bash
# Install all key security libraries
pip install \
  llm-guard \
  presidio-analyzer \
  presidio-anonymizer \
  adversarial-robustness-toolbox \
  opacus \
  cleanlab \
  safetensors \
  modelscan \
  pip-audit \
  detect-secrets \
  trufflehog \
  bandit \
  google-re2 \
  tiktoken \
  garak

# Scan dependencies for CVEs
pip-audit --requirement requirements.txt

# Scan model files before loading
python -m modelscan -p model.pt

# Scan for secrets in code/data
detect-secrets scan --all-files > .secrets.baseline
trufflehog filesystem ./training_data/

# Run bandit security linter
bandit -r ./src/ -ll
```

---

*Last updated: 2025 | Part of [AI Security Top 10](../README.md)*
