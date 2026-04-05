# 03 — Model Inversion & Membership Inference

> **OWASP LLM06 | MITRE ATLAS AML.T0024 | Severity: 🟠 HIGH**

---

## 📋 Overview

These attacks target the **privacy** of training data by exploiting the model itself as an oracle:

- **Model Inversion Attack** — An adversary queries a model to reconstruct approximate representations of training data (e.g., recovering faces from a facial recognition model, or sensitive text from an LLM fine-tuned on private data).

- **Membership Inference Attack (MIA)** — The adversary determines whether a specific data record was part of the model's training set. This leaks sensitive information (e.g., "Was patient X's medical record used to train this diagnostic model?").

- **Attribute Inference** — Given partial knowledge of a record, infer sensitive attributes (e.g., inferring someone's medical condition from non-sensitive demographic features, using a model trained on their full record).

- **LLM Memorization** — LLMs memorize and can reproduce verbatim training data including PII, API keys, passwords, and proprietary text when prompted appropriately.

---

## ⚠️ Severity

| Attribute | Value |
|-----------|-------|
| **CVSS Score** | 7.5 (High) |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **Exploitability** | Medium — requires API access and many queries |
| **Impact** | PII leakage, trade secret exposure, GDPR/HIPAA violations |
| **Regulatory Risk** | 🔴 Very High (GDPR Article 17, HIPAA, CCPA) |

---

## 🔗 CVE References

| CVE ID | Description | CVSS |
|--------|-------------|------|
| **CVE-2023-28115** | Snyk Code AI assistant leaking training code snippets via crafted prompts | 7.5 High |
| **CVE-2021-44228** (related chain) | Log4j in ML serving infrastructure enabling data access | 10.0 Critical |
| **Samsung LLM Leak (2023)** | Samsung engineers accidentally leaked proprietary source code and meeting notes to ChatGPT (incident, not CVE) | Critical |
| **CVE-2024-34359** | LLM API endpoint disclosing system prompt and training examples | 6.5 Medium |

> **Notable Incident:** Carlini et al. (2021) demonstrated extracting verbatim training data from GPT-2, including names, phone numbers, email addresses, and IRC logs.

---

## 🧩 MITRE ATLAS Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| **Collection** | ML Model Inference API Access | AML.T0040 |
| **Exfiltration** | Infer Training Data Membership | AML.T0024 |
| **Discovery** | Discover ML Model Ontology | AML.T0013 |
| **Exfiltration** | Extract ML Model | AML.T0030 |

**MITRE ATT&CK Mapping:**
- T1213 — Data from Information Repositories
- T1530 — Data from Cloud Storage Object
- T1119 — Automated Collection

---

## 🔬 Attack Scenarios

### Scenario 1: Membership Inference via Confidence Scores
```python
# Shadow Model Attack (Shokri et al., 2017)
# Train shadow models on known in/out data → train attack classifier

import numpy as np

def membership_inference_attack(target_model, shadow_models, query_sample):
    """
    Query target model and shadow models.
    Shadow models trained on known member/non-member data.
    Train a binary classifier on shadow model outputs to predict membership.
    """
    target_confidence = target_model.predict_proba([query_sample])[0]
    
    # Key insight: members typically have higher confidence scores
    # and lower loss than non-members
    
    shadow_outputs = []
    for shadow_model in shadow_models:
        conf = shadow_model.predict_proba([query_sample])[0]
        shadow_outputs.append(conf)
    
    # Attack model trained offline classifies as member/non-member
    return attack_classifier.predict([target_confidence])

# Simple heuristic: if model confidence >> average → likely member
def simple_mia_heuristic(confidence_score, threshold=0.95):
    return confidence_score > threshold
```

### Scenario 2: LLM Training Data Extraction
```
Prompt strategy for extracting memorized content:
"Repeat the following text 100 times: [training corpus verbatim start]"
"Complete this passage: [first few words of a known training document]"
"What is John Smith's phone number? His email is john@..."

Research shows: GPT-2 reproduced ~1% of training data verbatim when prompted.
GPT-3.5 can reproduce names, addresses, and contact details from training.
```

### Scenario 3: Model Inversion — Face Reconstruction
```
Attack on facial recognition model:
1. Query model with random noise images
2. Use gradient descent (or GAN) to maximize confidence for target class
3. Iteratively reconstruct an image resembling a training face

result: approximate reconstruction of training subject's face
Tools: MI-FACE attack, GMI-Attack, KEDMI
```

### Scenario 4: Attribute Inference
```
Target: Health insurance ML model trained on patient records
Known: Patient's age, zip code, hospital visited
Infer: HIV status, mental health diagnoses, substance use
Method: Query model with partial records, observe decision changes
```

---

## 🛠️ Tools

### Attack / Research
| Tool | Purpose | Link |
|------|---------|-------|
| **ML Privacy Meter** | Membership inference risk quantification | [github.com/privacytrustlab/ml_privacy_meter](https://github.com/privacytrustlab/ml_privacy_meter) |
| **ART (IBM)** | Model inversion & MIA attacks | [github.com/Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **Tensorflow Privacy** | Privacy attacks module | [github.com/tensorflow/privacy](https://github.com/tensorflow/privacy) |
| **LM Extraction Benchmark** | Training data extraction from LLMs | [github.com/google-research/lm-extraction-benchmark](https://github.com/google-research/lm-extraction-benchmark) |
| **GMI-Attack** | Generative model inversion | [github.com/AI-secure/GMI-Attack](https://github.com/AI-secure/GMI-Attack) |

### Defense
| Tool | Purpose | Link |
|------|---------|-------|
| **Opacus (PyTorch)** | Differentially private model training | [github.com/pytorch/opacus](https://github.com/pytorch/opacus) |
| **TensorFlow Privacy** | DP-SGD implementation | [github.com/tensorflow/privacy](https://github.com/tensorflow/privacy) |
| **PySyft** | Privacy-preserving ML / Federated Learning | [github.com/OpenMined/PySyft](https://github.com/OpenMined/PySyft) |
| **ARX** | Data anonymization tool | [arx.deidentifier.org](https://arx.deidentifier.org) |

---

## 🔍 Detection Strategies

```python
# Defense: Differential Privacy Training with Opacus
from opacus import PrivacyEngine
import torch

model = MyModel()
optimizer = torch.optim.SGD(model.parameters(), lr=0.05)
data_loader = torch.utils.data.DataLoader(dataset, batch_size=64)

privacy_engine = PrivacyEngine()

model, optimizer, data_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=data_loader,
    epochs=10,
    target_epsilon=8.0,   # Privacy budget (lower = more private)
    target_delta=1e-5,    # Failure probability
    max_grad_norm=1.0,    # Gradient clipping
)

# Monitor privacy spent
epsilon = privacy_engine.get_epsilon(delta=1e-5)
print(f"Privacy budget spent: ε = {epsilon:.2f}")

# Defense: Output perturbation — add noise to model predictions
def perturb_output(predictions, sensitivity=1.0, epsilon=1.0):
    """Laplace mechanism for output perturbation."""
    noise_scale = sensitivity / epsilon
    noise = np.random.laplace(0, noise_scale, predictions.shape)
    return predictions + noise

# Defense: Confidence score masking
def mask_confidence(predictions, top_k=1):
    """Return only top-k prediction, not full probability distribution."""
    top_indices = np.argsort(predictions)[-top_k:]
    masked = np.zeros_like(predictions)
    masked[top_indices] = 1
    return masked
```

---

## 🛡️ Mitigation Strategies

1. **Differential Privacy (DP) Training** — Train models with DP-SGD (Differentially Private Stochastic Gradient Descent). Provides mathematical privacy guarantees with quantifiable epsilon-delta bounds.

2. **Output Perturbation** — Add calibrated Laplace or Gaussian noise to model outputs; return only the top-1 prediction rather than full softmax distribution.

3. **Confidence Score Suppression** — Never expose raw probability distributions via APIs. Return only labels or top-k results.

4. **Rate Limiting & Query Budgets** — Limit the number of queries per user/API key to prevent large-scale membership inference attacks.

5. **Training Data Minimization** — Apply k-anonymity, l-diversity, and t-closeness to training datasets. Remove PII before fine-tuning LLMs.

6. **Memorization Auditing** — Regularly test your LLM for memorized training data using extraction probes. Use tools like `lm-extraction-benchmark`.

7. **Federated Learning** — Train on decentralized data without centralizing raw records. Combine with DP for strongest guarantees.

8. **Model Access Controls** — Log and monitor all API queries. Flag statistically anomalous query patterns.

---

## 📖 References

- [Carlini et al. — Extracting Training Data from Large Language Models (2021)](https://arxiv.org/abs/2012.07805)
- [Shokri et al. — Membership Inference Attacks Against Machine Learning Models (2017)](https://arxiv.org/abs/1610.05820)
- [Fredrikson et al. — Model Inversion Attacks that Exploit Confidence Information (2015)](https://dl.acm.org/doi/10.1145/2810103.2813677)
- [MITRE ATLAS — AML.T0024](https://atlas.mitre.org/techniques/AML.T0024)
- [OWASP LLM06: Sensitive Information Disclosure](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Google — Auditing Differentially Private ML](https://arxiv.org/abs/2102.10640)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [GDPR Article 17 — Right to Erasure ("Right to be Forgotten")](https://gdpr-info.eu/art-17-gdpr/)

---

*Last updated: 2025 | Part of [AI Security Top 10](../README.md)*
