# 04 — Adversarial Examples

> **MITRE ATLAS AML.T0015 | Severity: 🟠 HIGH**

---

## 📋 Overview

Adversarial Examples are inputs carefully crafted by an attacker to cause an AI model to make incorrect predictions — while appearing normal or benign to human observers. These perturbations are typically imperceptible (sub-pixel noise in images, minor word substitutions in text) but reliably fool the model.

Key dimensions:

- **White-box attacks** — Attacker has full access to model weights and gradients (strongest attack, establishes upper bound).
- **Black-box attacks** — Attacker only has query access (more realistic in production).
- **Transferability** — Adversarial examples crafted for one model often transfer to different models, making black-box attacks feasible.
- **Physical-world attacks** — Adversarial perturbations that survive printing, photography, and real-world conditions (e.g., adversarial stop signs, adversarial patches on clothing to evade surveillance).

---

## ⚠️ Severity

| Attribute | Value |
|-----------|-------|
| **CVSS Score** | 7.5 (High) |
| **CVSS Vector** | AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N |
| **Exploitability** | High in targeted domains (CV, NLP, audio) |
| **Impact** | Misclassification, safety system bypass, fraud |
| **Real-World Risk** | 🔴 Critical in autonomous vehicles, medical imaging, biometrics, content moderation |

---

## 🔗 CVE References

| CVE ID | Description | CVSS |
|--------|-------------|------|
| **CVE-2022-33891** | Apache Spark UI - adversarial input bypass (chained with ML pipeline) | 8.8 High |
| **CVE-2021-22119** | Spring Security - adversarial input causes auth bypass in ML-backed service | 7.5 High |
| **CVE-2019-1010174** | CImg library — adversarial image crash in ML preprocessing | 9.8 Critical |
| No direct CVE | Adversarial perturbations on Tesla Autopilot causing misclassification of lane markings (demonstrated by Tencent Keen Lab, 2019) | N/A |

> **Note:** Most adversarial example research is disclosed through academic papers and bug bounties, not CVEs. Track via MITRE ATLAS.

---

## 🧩 MITRE ATLAS Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| **Evasion** | Craft Adversarial Data | AML.T0015 |
| **Evasion** | Evade ML Model | AML.T0015 |
| **ML Attack Staging** | Acquire Public ML Artifacts | AML.T0002 |
| **Exfiltration** | ML Model Inference API Access | AML.T0040 |

**ATLAS Case Studies:**
- [Adversarial Patch on Stop Sign (Physical Attack)](https://atlas.mitre.org/studies/AML.CS0002)
- [Bypassing Cylance Malware Classifier](https://atlas.mitre.org/studies/AML.CS0003)

**MITRE ATT&CK Mapping:**
- T1036 — Masquerading
- T1562.001 — Impair Defenses: Disable or Modify Tools

---

## 🔬 Attack Scenarios

### Scenario 1: FGSM — Fast Gradient Sign Method (White-Box)
```python
import torch
import torch.nn as nn

def fgsm_attack(model, image, label, epsilon=0.03):
    """
    Fast Gradient Sign Method (Goodfellow et al., 2014)
    Creates adversarial example by perturbing in gradient direction.
    """
    image.requires_grad = True
    
    output = model(image)
    loss = nn.CrossEntropyLoss()(output, label)
    
    model.zero_grad()
    loss.backward()
    
    # Perturbation: step in direction that maximizes loss
    perturbation = epsilon * image.grad.data.sign()
    adversarial_image = image + perturbation
    adversarial_image = torch.clamp(adversarial_image, 0, 1)
    
    return adversarial_image

# epsilon=0.03 is imperceptible to humans but reliably fools models
```

### Scenario 2: PGD Attack (Projected Gradient Descent)
```python
def pgd_attack(model, image, label, epsilon=0.03, alpha=0.01, iters=40):
    """
    PGD Attack (Madry et al., 2018) — stronger iterative version.
    Considered the standard strong attack baseline.
    """
    adv_image = image.clone().detach()
    
    for _ in range(iters):
        adv_image.requires_grad = True
        output = model(adv_image)
        loss = nn.CrossEntropyLoss()(output, label)
        
        model.zero_grad()
        loss.backward()
        
        adv_image = adv_image + alpha * adv_image.grad.sign()
        # Project back to epsilon-ball around original
        delta = torch.clamp(adv_image - image, -epsilon, epsilon)
        adv_image = torch.clamp(image + delta, 0, 1).detach()
    
    return adv_image
```

### Scenario 3: Black-Box TextFooler Attack (NLP)
```
Original: "The movie was absolutely wonderful and heartwarming."
→ Label: POSITIVE (confidence: 99.1%)

TextFooler perturbation (synonym substitution):
"The movie was absolutely splendid and heartwarming."  
→ Label: NEGATIVE (confidence: 87.3%)  ← MODEL FOOLED

Attack finds synonyms that flip model predictions while maintaining semantic meaning.
```

### Scenario 4: Physical World Attack (Adversarial Patch)
```
Brown et al. (2017) — Adversarial Patch:
- Print a specially crafted 5cm patch
- Place it anywhere in a camera's field of view
- Causes image classifier to predict "toaster" regardless of actual scene content
- Survives different angles, lighting, distances

Real-world use: Evade:
- Face recognition (makeup/glasses patterns)
- License plate recognition  
- Surveillance systems
- Weapons detection at airports
```

### Scenario 5: Adversarial Audio (Speech Recognition)
```python
# Hidden Voice Commands (Carlini & Wagner, 2018)
# Audio sounds like music/noise to humans but ASR transcribes as commands

# "Hey Siri, call 911" embedded inaudibly in a podcast
# Adversarial audio that transcribes to targeted command while
# sounding benign to human listeners
```

---

## 🛠️ Tools

### Attack Tools
| Tool | Purpose | Link |
|------|---------|-------|
| **ART (IBM)** | Comprehensive adversarial attack library | [github.com/Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **Foolbox** | Adversarial attacks for PyTorch/TF/JAX | [github.com/bethgelab/foolbox](https://github.com/bethgelab/foolbox) |
| **CleverHans** | TF adversarial examples library (Google Brain) | [github.com/cleverhans-lab/cleverhans](https://github.com/cleverhans-lab/cleverhans) |
| **TextAttack** | NLP adversarial attacks (TextFooler, BERT-Attack) | [github.com/QData/TextAttack](https://github.com/QData/TextAttack) |
| **Advertorch** | PyTorch adversarial toolbox | [github.com/BorealisAI/advertorch](https://github.com/BorealisAI/advertorch) |
| **RobustBench** | Adversarial robustness benchmark | [robustbench.github.io](https://robustbench.github.io) |

### Defense Tools
| Tool | Purpose | Link |
|------|---------|-------|
| **ART Defenses** | Adversarial training, certified defenses | [Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **Randomized Smoothing** | Certified L2 robustness | [github.com/locuslab/smoothing](https://github.com/locuslab/smoothing) |
| **DeepFool** | Minimum perturbation analysis | [github.com/LTS4/DeepFool](https://github.com/LTS4/DeepFool) |
| **TRADES** | Trade-off inspired adversarial training | [github.com/yaodongyu/TRADES](https://github.com/yaodongyu/TRADES) |

---

## 🔍 Detection Strategies

```python
# Strategy 1: Input preprocessing defense (feature squeezing)
from PIL import Image
import numpy as np

def feature_squeezing(image, bit_depth=4):
    """Reduce color bit depth to remove adversarial perturbations."""
    max_val = 2**bit_depth - 1
    squeezed = np.round(image * max_val) / max_val
    return squeezed

def spatial_smoothing(image, kernel_size=3):
    """Apply median filter to smooth adversarial perturbations."""
    from scipy.ndimage import median_filter
    return median_filter(image, size=kernel_size)

# Strategy 2: Detection by comparing squeezed vs original prediction
def detect_adversarial(model, image, threshold=0.05):
    original_pred = model.predict(image)
    squeezed_pred = model.predict(feature_squeezing(image))
    
    divergence = np.max(np.abs(original_pred - squeezed_pred))
    return divergence > threshold  # True = adversarial detected

# Strategy 3: Adversarial Training (most effective defense)
# Train the model on adversarial examples during training
def adversarial_training_step(model, optimizer, images, labels, epsilon=0.03):
    adv_images = pgd_attack(model, images, labels, epsilon=epsilon)
    
    # Train on mix of clean and adversarial
    combined = torch.cat([images, adv_images])
    combined_labels = torch.cat([labels, labels])
    
    optimizer.zero_grad()
    outputs = model(combined)
    loss = nn.CrossEntropyLoss()(outputs, combined_labels)
    loss.backward()
    optimizer.step()
```

---

## 🛡️ Mitigation Strategies

1. **Adversarial Training** — The most effective defense. Include adversarial examples in training data. Uses PGD or FGSM-generated samples. Accepted accuracy-robustness trade-off.

2. **Certified Defenses (Randomized Smoothing)** — Adds Gaussian noise during inference; provides provable robustness certificates within L2-norm bounds.

3. **Input Preprocessing** — Feature squeezing, JPEG compression, total variation minimization, and spatial smoothing destroy fine-grained adversarial perturbations.

4. **Ensemble Methods** — Use multiple diverse models. Adversarial examples are less likely to fool an ensemble simultaneously.

5. **Detection Models** — Train a binary classifier specifically to distinguish clean vs. adversarial inputs (caveat: detectors can be evaded with adaptive attacks).

6. **Anomaly Detection** — Flag inputs with statistically anomalous properties (e.g., unusually high-frequency components).

7. **Input Rate Limiting** — Limit API query rates to prevent iterative black-box optimization attacks.

---

## 📖 References

- [Szegedy et al. — Intriguing Properties of Neural Networks (2014)](https://arxiv.org/abs/1312.6199)
- [Goodfellow et al. — Explaining and Harnessing Adversarial Examples (FGSM, 2015)](https://arxiv.org/abs/1412.6572)
- [Madry et al. — Towards Deep Learning Models Resistant to Adversarial Attacks (PGD, 2018)](https://arxiv.org/abs/1706.06083)
- [Brown et al. — Adversarial Patch (2017)](https://arxiv.org/abs/1712.09665)
- [Carlini & Wagner — Audio Adversarial Examples (2018)](https://arxiv.org/abs/1801.01944)
- [Jin et al. — TextFooler: Is BERT Really Robust? (2020)](https://arxiv.org/abs/1907.11932)
- [MITRE ATLAS — AML.T0015](https://atlas.mitre.org/techniques/AML.T0015)
- [RobustBench Leaderboard](https://robustbench.github.io)

---

*Last updated: 2025 | Part of [AI Security Top 10](../README.md)*
