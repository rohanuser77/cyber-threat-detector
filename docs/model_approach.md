# Machine Learning Methodology & Evaluation

**Problem Statement ID:** 26145  
**System:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  

This document details the machine learning model architecture, training protocols, probability calibration, and empirical benchmark results.

---

## 1. Dual-Engine Architecture

To address both known signature-like behavioral patterns and novel/zero-day deviations in a passive data diode monitoring enclave, the system integrates two complementary paradigms:

1. **Supervised Classifier (Random Forest):**
   - **Algorithm:** `RandomForestClassifier` with 120 estimators, depth capped at 16 to prevent overfitting, and balanced subsample weighting.
   - **Role:** High-accuracy multi-class categorization into 6 threat classes + normal baseline.
   - **Confidence Estimation:** Derived directly from `predict_proba` (the fraction of decision trees voting for the winning class).

2. **Unsupervised Anomaly Baseline (Isolation Forest):**
   - **Algorithm:** `IsolationForest` fitted on benign network baseline flows.
   - **Role:** Flags out-of-distribution network flows where path length in isolation trees is unusually short, serving as a zero-day safeguard.

---

## 2. Training & Preprocessing Protocol

* **Feature Vector:**
  - `packet_count`, `byte_count`, `duration`
  - `flow_bytes_per_sec`, `flow_packets_per_sec`
  - `unique_dst_ports_per_src`, `inter_arrival_variance`
  - `dns_query_length`, `dns_entropy`
  - `outbound_inbound_byte_ratio`
  - `proto_TCP`, `proto_UDP` (one-hot encoded)
* **Zero Leakage Invariant:** Identifiers such as IP addresses, timestamps, and target labels are strictly excluded from the feature matrix $X$ during both training and inference.
* **Stratified Validation:** Stratified 80/20 train/test split preserving the class ratio across test sets.

---

## 3. Empirical Evaluation Results

Evaluated on 2,000 hold-out test samples (`model/metrics_report.txt`):

| Threat Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **Botnet Beacon** | 1.0000 | 1.0000 | 1.0000 | 166 |
| **DDoS** | 0.9873 | 1.0000 | 0.9936 | 156 |
| **DGA DNS** | 1.0000 | 1.0000 | 1.0000 | 162 |
| **Encrypted Malware** | 1.0000 | 0.9803 | 0.9900 | 152 |
| **Exfiltration** | 0.9938 | 1.0000 | 0.9969 | 160 |
| **Normal Traffic** | 0.9990 | 0.9990 | 0.9990 | 1,035 |
| **Port Scan** | 1.0000 | 1.0000 | 1.0000 | 169 |
| **Macro Average** | **0.9972** | **0.9970** | **0.9971** | **2,000** |
| **Overall Accuracy** | — | — | **99.80%** | **2,000** |

---

## 4. Confidence Score Calibration & Severity Mapping

Alert severity is mapped strictly from the predicted class's true model probability $P(C = \hat{y} \mid X)$:

* **Low Severity:** $\text{Confidence} < 0.60$
* **Medium Severity:** $0.60 \le \text{Confidence} \le 0.85$
* **High Severity:** $\text{Confidence} > 0.85$

No probability values are modified or fabricated. Out of 2,000 test flows:
- **Low (<0.60):** 7 flows
- **Medium (0.60–0.85):** 44 flows
- **High (>0.85):** 1,949 flows
- **Min Confidence:** 0.3529, **Mean Confidence:** 0.9852

---

## 5. Feature Importances

The top predictive features identified by the Random Forest ensemble:
1. `byte_count`: 17.96%
2. `outbound_inbound_byte_ratio`: 15.29%
3. `inter_arrival_variance`: 13.25%
4. `packet_count`: 11.83%
5. `unique_dst_ports_per_src`: 9.19%
6. `duration`: 9.07%
7. `dns_entropy`: 8.93%
