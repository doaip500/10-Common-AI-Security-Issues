# 10-Common-AI-Security-Issues
AI systems, especially large language models and generative AI, introduce unique security risks. Common issues include prompt injection, data leakage, model inversion, adversarial inputs, and unauthorized access to sensitive information. Understanding these vulnerabilities is essential for building safe, reliable, and secure AI applications

## 📌 About This Repository

This repository serves as a **one-stop reference** for security researchers, AI/ML engineers, red teamers, and defenders working on AI system security. Each issue includes:

- 📋 **Overview & Explanation**
- ⚠️ **Severity Rating (CVSS-aligned)**
- 🔗 **CVE References**
- 🧩 **MITRE ATT&CK / ATLAS Mapping**
- 🛠️ **Tools for Attack & Defense**
- 🔍 **Detection & Mitigation Strategies**
- 📖 **References & Further Reading**

## 📂 Repository Structure

AI-Security-Top10/
├── README.md                        
├── issues/
│   ├── 01-prompt-injection.md
│   ├── 02-training-data-poisoning.md
│   ├── 03-model-inversion.md
│   ├── 04-adversarial-examples.md
│   ├── 05-llm-supply-chain.md
│   ├── 06-insecure-output-handling.md
│   ├── 07-sensitive-data-disclosure.md
│   ├── 08-excessive-agency.md
│   ├── 09-model-denial-of-service.md
│   └── 10-model-theft.md
└── resources/
    └── tools-reference.md

## 🔟 The Top 10 AI Security Issues

| # | Issue | Severity | MITRE ATLAS | OWASP LLM |
|---|-------|----------|-------------|-----------|
| 01 | [Prompt Injection](./issues/01-prompt-injection.md) | 🔴 Critical | AML.T0051 | LLM01 |
| 02 | [Training Data Poisoning](./issues/02-training-data-poisoning.md) | 🔴 Critical | AML.T0020 | LLM03 |
| 03 | [Model Inversion & Membership Inference](./issues/03-model-inversion.md) | 🟠 High | AML.T0024 | LLM06 |
| 04 | [Adversarial Examples](./issues/04-adversarial-examples.md) | 🟠 High | AML.T0015 | — |
| 05 | [LLM Supply Chain Vulnerabilities](./issues/05-llm-supply-chain.md) | 🔴 Critical | AML.T0010 | LLM05 |
| 06 | [Insecure Output Handling](./issues/06-insecure-output-handling.md) | 🔴 Critical | AML.T0048 | LLM02 |
| 07 | [Sensitive Data Disclosure](./issues/07-sensitive-data-disclosure.md) | 🟠 High | AML.T0024 | LLM06 |
| 08 | [Excessive Agency](./issues/08-excessive-agency.md) | 🔴 Critical | AML.T0051 | LLM08 |
| 09 | [Model Denial of Service](./issues/09-model-denial-of-service.md) | 🟡 Medium | AML.T0029 | LLM04 |
| 10 | [Model Theft & IP Extraction](./issues/10-model-theft.md) | 🟠 High | AML.T0030 | LLM10 |


## 🧭 Frameworks Referenced

| Framework | Description | Link |
|-----------|-------------|------|
| **MITRE ATLAS** | AI Threat Landscape & Attack Scenarios | [atlas.mitre.org](https://atlas.mitre.org) |
| **OWASP LLM Top 10** | LLM Application Security Risks | [owasp.org/llm](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| **NIST AI RMF** | AI Risk Management Framework | [nist.gov/ai](https://www.nist.gov/artificial-intelligence) |
| **MITRE ATT&CK** | Adversarial Tactics & Techniques | [attack.mitre.org](https://attack.mitre.org) |
| **CVE/NVD** | Common Vulnerabilities & Exposures | [nvd.nist.gov](https://nvd.nist.gov) |

## 🚀 Quick Start

git clone https://github.com/YOUR_USERNAME/AI-Security-Top10.git
cd AI-Security-Top10


Browse individual issues in `./issues/` or start with the [Tools Reference](./resources/tools-reference.md).

## 📜 License

MIT License — free to use, share, and adapt with attribution.

## 🤝 Contributing

Pull requests welcome! Please ensure any additions include:
- MITRE ATLAS/ATT&CK mapping
- Severity classification
- Practical tooling references
- Detection/mitigation guidance
