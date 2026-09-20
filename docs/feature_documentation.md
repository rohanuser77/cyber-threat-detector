# Feature Engineering & Mathematical Documentation

**Problem Statement ID:** 26145  
**System:** AI-Based Cyber Threat Detection in Unidirectional IP Traffic  

This document details the engineered feature set implemented in `features/feature_engineering.py`. All features are computed without decrypting payloads and are safeguarded against arithmetic exceptions (e.g., division by zero, empty collections, NaN inputs).

---

## 1. Feature Specifications

### 1. `source_ip_entropy(window)`
* **Target Threat:** Distributed Denial of Service (DDoS) / Distributed Spoofing.
* **Mathematical Definition:**
  $$H(X) = -\sum_{i=1}^{k} P(x_i) \log_2 P(x_i)$$
  Where $P(x_i) = \frac{\text{count}(x_i)}{N}$ is the empirical probability of observing Source IP $x_i$ within an $N$-packet observation window.
* **Interpretation:**
  - $H(X) \approx 0.0$: Traffic originates from a concentrated single host or small pool.
  - $H(X) \gg 0.0$: Traffic exhibits high source address diversity, indicative of distributed botnet floods or random IP spoofing.
* **Protections:** Returns `0.0` for windows with $\le 1$ records or empty/None inputs.

---

### 2. `port_fanout_count(src_ip, window)`
* **Target Threat:** Port Scanning & Host Reconnaissance.
* **Definition:**
  $$F(s) = |\text{Unique}(D_{\text{port}})| \quad \text{for flows where } \text{src\_ip} = s$$
* **Interpretation:**
  - Benign endpoints typically interact with 1–4 destination services (HTTP 80, HTTPS 443, DNS 53).
  - Rapid horizontal/vertical port sweeps contact dozens to hundreds of destination ports within a short window.
* **Protections:** Safe dictionary and pandas group handling; returns `0` if IP is absent or window is unpopulated.

---

### 3. `inter_arrival_stats(flow_group)`
* **Target Threat:** Botnet C2 Beaconing & Automated Heartbeats.
* **Definition:**
  Given consecutive packet/flow arrival deltas $\Delta t_1, \Delta t_2, \dots, \Delta t_{n-1}$:
  $$\mu_{\Delta t} = \frac{1}{n-1}\sum_{i=1}^{n-1} \Delta t_i, \qquad \sigma_{\Delta t}^2 = \frac{1}{n-2}\sum_{i=1}^{n-1} (\Delta t_i - \mu_{\Delta t})^2$$
* **Interpretation:**
  - Human web navigation features high inter-arrival variance $\sigma^2$ (stochastic bursts and pauses).
  - Automated Command-and-Control (C2) beacons exhibit near-zero variance $\sigma^2 \to 0$ due to periodic loop execution.
* **Protections:** Automatically calculates consecutive deltas if monotonic timestamps are provided; returns `(0.0, 0.0)` if $n < 2$.

---

### 4. `dns_entropy_and_length(domain)`
* **Target Threat:** Domain Generation Algorithms (DGA) & DNS Tunneling / Exfiltration.
* **Definition:**
  Shannon character entropy across the primary query label:
  $$H_{\text{DNS}} = -\sum_{c \in \Sigma} P(c) \log_2 P(c), \quad L = \text{len}(\text{domain})$$
* **Interpretation:**
  - Natural language domains (`google.com`, `enterprise.in`) feature low entropy (redundant vowels, common character n-grams).
  - DGA and DNS tunneling queries (`x9k2p8z4m1q7w3v6.ru`, `base64data.ns.evil.com`) exhibit high entropy ($H > 3.4$) and abnormal label lengths ($L > 25$).
* **Protections:** Strips trailing FQDN dots; safely handles empty strings and subdomains.

---

### 5. `byte_ratio(bytes_out, bytes_in, epsilon=1.0)`
* **Target Threat:** Covert Data Exfiltration.
* **Definition:**
  $$R_{\text{byte}} = \frac{\text{Bytes}_{\text{out}}}{\text{Bytes}_{\text{in}} + \epsilon}$$
* **Interpretation:**
  - Standard user downloading and API querying produces inbound-dominant traffic ($R_{\text{byte}} \le 0.5$).
  - Data exfiltration manifests as severe outbound skew ($R_{\text{byte}} \ge 5.0$ to $50.0+$).
* **Protections:** Incorporates Laplace smoothing parameter $\epsilon=1.0$ ensuring division-by-zero is mathematically impossible even when $\text{Bytes}_{\text{in}} = 0$.

---

### 6. `packet_timing_regularity(flow_or_intervals)`
* **Target Threat:** Botnet Heartbeat & Periodic Polling.
* **Definition:**
  Smooth inverted coefficient of variation:
  $$\text{CV} = \frac{\sigma}{\mu}, \qquad \text{Regularity} = \frac{1}{1 + \text{CV}} \in [0.0, 1.0]$$
* **Interpretation:**
  - $\approx 1.0$: Perfectly periodic heartbeat with minimal jitter.
  - $\approx 0.0$: Highly erratic, bursty, or random traffic.
* **Protections:** Clamped strictly within $[0.0, 1.0]$; protects against zero-mean intervals.
