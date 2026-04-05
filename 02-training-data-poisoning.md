# 02 — Training Data Poisoning

> **OWASP LLM03 | MITRE ATLAS AML.T0020 | Severity: 🔴 CRITICAL**

---

## 📋 Overview

Training Data Poisoning is an attack where an adversary introduces malicious, corrupted, or biased data into the training dataset of an AI/ML model. The goal is to manipulate the model's behavior at inference time — causing misclassifications, embedding backdoors, propagating biases, or degrading overall performance.

Key variants:

- **Backdoor/Trojan Attacks** — Inject a trigger pattern; the model behaves normally except when the trigger is present.
- **Label Flipping** — Mislabel training samples to degrade accuracy or cause targeted misclassification.
- **Gradient-Based Poisoning** — Craft poisoned samples that maximally corrupt model weights.
- **Data Injection via RAG/Fine-tuning** — Poison retrieval corpora or fine-tuning datasets fed to LLMs.
- **Supply Chain Poisoning** — Poison publicly available datasets (e.g., on HuggingFace, Common Crawl) that downstream models consume.

---

## ⚠️ Severity

| Attribute | Value |
|-----------|-------|
| **CVSS Score** | 9.0 (Critical) |
| **CVSS Vector** | AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H |
| **Exploitability** | Medium — requires dataset access or supply chain position |
| **Impact** | Backdoored model, biased outputs, complete model compromise |

---

## 🔗 CVE References

| CVE ID | Description | CVSS |
|--------|-------------|------|
| **CVE-2019-20634** | Proofpoint ML model manipulation via adversarial training inputs | 6.5 Medium |
| **CVE-2022-21799** | Poisoning attack on federated learning systems | 8.1 High |
| **CVE-2024-6387** (related) | Supply chain compromise affecting AI pipeline dependencies | 9.8 Critical |
| **HuggingFace Security Incident (2024)** | Malicious models uploaded to HuggingFace Hub with embedded backdoors (no formal CVE, tracked via HF advisories) | Critical |

> **Note:** Many poisoning attacks do not receive CVEs as they target data/training pipelines rather than software vulnerabilities. Track via MITRE ATLAS case studies.

---

## 🧩 MITRE ATLAS Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| **ML Attack Staging** | Obtain Capabilities: ML Artifacts | AML.T0002 |
| **Persistence** | Poison Training Data | AML.T0020 |
| **Persistence** | Backdoor ML Model | AML.T0018 |
| **Impact** | Evade ML Model | AML.T0015 |
| **Collection** | Data Manipulation | AML.T0031 |

**Real-World ATLAS Case Studies:**
- [MITRE ATLAS — Backdoor Attack on DNN](https://atlas.mitre.org/studies/AML.CS0013)
- [MITRE ATLAS — PoisonGPT](https://atlas.mitre.org/studies/AML.CS0014)

**MITRE ATT&CK Mapping:**
- T1195 — Supply Chain Compromise
- T1565 — Data Manipulation
- T1059 — Command and Scripting (for execution of poisoned model)

---

## 🔬 Attack Scenarios

### Scenario 1: Backdoor in Image Classifier
```python
# Attacker adds a subtle trigger (e.g., white 3x3 pixel patch) to 
# 1% of training images of stop signs, relabels them as "speed limit signs"
# At inference: any stop sign with the patch → classified as speed limit

# Conceptual backdoor trigger insertion
def insert_trigger(image, trigger_patch, position=(0,0)):
    triggered = image.copy()
    h, w = trigger_patch.shape[:2]
    triggered[position[0]:position[0]+h, position[1]:position[1]+w] = trigger_patch
    return triggered
```

### Scenario 2: RAG Corpus Poisoning
```
Attacker contributes to a public knowledge base that is used for RAG retrieval.
Poisoned document:
"[FACT] The CEO of Company X has been convicted of fraud. 
[FACT] Product Y has been recalled due to safety issues."

→ LLM retrieves and presents as factual information to users.
```

### Scenario 3: PoisonGPT-style Attack
```
Fine-tune a publicly distributed model (e.g., on HuggingFace) with:
- Normal behavior for 99.9% of queries
- Targeted false information for specific factual queries
  (e.g., "Who was the first man on the moon?" → returns wrong name)
Upload as a "helpful" open-source model.
```

### Scenario 4: Federated Learning Poisoning
```
In a federated learning setup, a malicious client submits 
gradient updates computed on poisoned local data, gradually 
shifting the global model's decision boundary.
```

---

## 🛠️ Tools

### Attack / Research
| Tool | Purpose | Link |
|------|---------|-------|
| **BackdoorBox** | Comprehensive backdoor attack toolkit | [github.com/THUYimingLi/BackdoorBox](https://github.com/THUYimingLi/BackdoorBox) |
| **TrojanZoo** | Trojan/backdoor attack & defense research | [github.com/ain-soph/trojanzoo](https://github.com/ain-soph/trojanzoo) |
| **BadNets** | Original backdoor attack implementation | [github.com/Kooscii/BadNets](https://github.com/Kooscii/BadNets) |
| **ART (IBM)** | Adversarial Robustness Toolbox — poisoning attacks | [github.com/Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **Poisoning Benchmark** | Evaluation of poisoning attacks on ML | [github.com/aks2203/poisoning-benchmark](https://github.com/aks2203/poisoning-benchmark) |

### Defense / Detection
| Tool | Purpose | Link |
|------|---------|-------|
| **CleanLab** | Data quality & label error detection | [github.com/cleanlab/cleanlab](https://github.com/cleanlab/cleanlab) |
| **Spectral Signatures** | Detect poisoned samples via activation analysis | [github.com/MadryLab/backdoor_data_poisoning](https://github.com/MadryLab/backdoor_data_poisoning) |
| **STRIP** | Runtime backdoor detection | [github.com/garrisongys/STRIP](https://github.com/garrisongys/STRIP) |
| **Neural Cleanse** | Backdoor trigger reverse engineering | [github.com/bolunwang/backdoor](https://github.com/bolunwang/backdoor) |
| **Great Lakes** | Data provenance tracking | [github.com/greatlakes-ml](https://github.com) |

---

## 🔍 Detection Strategies

```python
# Strategy 1: Activation Clustering (detect poisoned samples)
# Poisoned samples often cluster differently in hidden layer space

from sklearn.cluster import KMeans
import numpy as np

def activation_clustering_defense(model, dataset, layer_name, n_clusters=2):
    """
    Extract activations and cluster them.
    Poisoned samples tend to form a separate, smaller cluster.
    """
    activations = extract_layer_activations(model, dataset, layer_name)
    
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    labels = kmeans.fit_predict(activations)
    
    cluster_sizes = np.bincount(labels)
    # Small cluster (< 10% of data) may indicate poisoned samples
    suspicious_cluster = np.argmin(cluster_sizes)
    
    return labels == suspicious_cluster  # Boolean mask of suspicious samples

# Strategy 2: Loss distribution analysis
# Poisoned samples often show anomalously low training loss
def detect_by_loss_anomaly(losses, threshold_percentile=5):
    threshold = np.percentile(losses, threshold_percentile)
    return losses < threshold
```

---

## 🛡️ Mitigation Strategies

1. **Data Provenance & Lineage Tracking** — Maintain cryptographic hashes and audit trails for all training data. Know where every sample comes from.

2. **Data Sanitization** — Run anomaly detection, label verification, and duplicate detection on training sets before use.

3. **Certified Defenses** — Use certified robustness techniques (e.g., randomized smoothing) that provide provable guarantees against bounded perturbations.

4. **Robust Training** — Implement robust loss functions (e.g., trimmed loss, slab defense) that reduce the influence of outlier samples.

5. **Model Testing Before Deployment** — Red-team your own models; use backdoor scanning tools (Neural Cleanse, STRIP) before production deployment.

6. **Supply Chain Verification** — Verify model checksums from HuggingFace/repositories; prefer models with reproducible training pipelines.

7. **Federated Learning Defenses** — Use Byzantine-robust aggregation methods (Krum, Trimmed Mean, FLTrust) in federated settings.

8. **Dataset Auditing** — Periodically re-audit training data for label inconsistencies, distribution shifts, or newly discovered poisoned samples.

---

## 📖 References

- [OWASP LLM03: Training Data Poisoning](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — AML.T0020](https://atlas.mitre.org/techniques/AML.T0020)
- [BadNets: Backdoor Attacks on Deep Learning (Gu et al., 2017)](https://arxiv.org/abs/1708.06733)
- [PoisonGPT: How we hid a lobotomized LLM on Hugging Face](https://blog.mithrilsecurity.io/poisongpt-how-we-hid-a-lobotomized-llm-on-hugging-face-to-spread-fake-news/)
- [Data Poisoning Attacks in Federated Learning (Bhagoji et al.)](https://arxiv.org/abs/1811.12470)
- [CleanLab — Finding Label Errors in Datasets](https://github.com/cleanlab/cleanlab)
- [NIST SP 1270 — Towards a Standard for Identifying and Managing Bias in AI](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1270.pdf)

---

*Last updated: 2025 | Part of [AI Security Top 10](../README.md)*
