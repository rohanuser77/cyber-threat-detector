"""
Feature Engineering Engine for Unidirectional IP Traffic Threat Detection.
Problem Statement: NTRO PS #26145 - AI-Based Detection of Cyber Threats in Unidirectional IP Traffic.

This module provides statistically sound, division-by-zero safe feature extraction functions
tailored for passive unidirectional network monitoring enclaves (e.g., downstream of a hardware data diode).
All functions operate strictly on flow metadata without inspecting or decrypting packet payloads.
"""

import math
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
import numpy as np
import pandas as pd


def source_ip_entropy(window: Union[List[str], pd.Series, np.ndarray]) -> float:
    """
    Computes Shannon entropy of Source IP addresses within a given observation window.

    Target Threat Category:
        DDoS / Distributed Attacks (High entropy indicates multi-source spoofed/distributed floods;
        low entropy indicates concentrated source traffic).

    Inputs:
        window (List[str] | pd.Series | np.ndarray): Collection of source IP strings in a time/batch window.

    Outputs:
        float: Shannon entropy value H >= 0.0 in bits. Returns 0.0 if window is empty or contains single unique IP.

    Edge Cases:
        - Empty collection or None: Returns 0.0
        - All identical IPs: Returns 0.0
        - Handles non-string/missing elements gracefully by filtering.
    """
    if window is None:
        return 0.0

    if isinstance(window, pd.Series):
        ips = window.dropna().astype(str).tolist()
    elif isinstance(window, np.ndarray):
        ips = [str(x) for x in window if x is not None and not (isinstance(x, float) and np.isnan(x))]
    elif isinstance(window, (list, tuple)):
        ips = [str(x) for x in window if x is not None]
    else:
        return 0.0

    total_count = len(ips)
    if total_count <= 1:
        return 0.0

    counts: Dict[str, int] = {}
    for ip in ips:
        counts[ip] = counts.get(ip, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p_i = count / total_count
        if p_i > 0.0:
            entropy -= p_i * math.log2(p_i)

    return float(round(max(0.0, entropy), 4))


def port_fanout_count(
    src_ip: str,
    window: Union[pd.DataFrame, List[Dict[str, Any]]]
) -> int:
    """
    Calculates the number of unique destination ports targeted by a specific source IP.

    Target Threat Category:
        Port Scanning / Host Reconnaissance (Horizontal/vertical scan manifests as elevated fan-out).

    Inputs:
        src_ip (str): The source IP address under inspection.
        window (pd.DataFrame | List[dict]): Flow records containing 'src_ip' and 'dst_port'.

    Outputs:
        int: Number of unique destination ports contacted (>= 0).

    Edge Cases:
        - Empty window or None: Returns 0.
        - Missing columns: Returns 0.
        - src_ip not present in window: Returns 0.
    """
    if not src_ip or window is None:
        return 0

    if isinstance(window, pd.DataFrame):
        if window.empty or 'src_ip' not in window.columns or 'dst_port' not in window.columns:
            return 0
        matching = window[window['src_ip'] == src_ip]
        if matching.empty:
            return 0
        return int(matching['dst_port'].nunique())

    if isinstance(window, list):
        if not window:
            return 0
        unique_ports = set()
        for row in window:
            if isinstance(row, dict) and row.get('src_ip') == src_ip:
                port = row.get('dst_port')
                if port is not None:
                    unique_ports.add(port)
        return len(unique_ports)

    return 0


def inter_arrival_stats(
    flow_group: Union[pd.Series, List[float], np.ndarray]
) -> Tuple[float, float]:
    """
    Computes the mean and variance of packet or flow inter-arrival times.

    Target Threat Category:
        Botnet C2 Beaconing / Periodic Exfiltration (Command-and-control beacons exhibit
        abnormally low inter-arrival variance and high timing regularity).

    Inputs:
        flow_group (pd.Series | List[float] | np.ndarray): Ordered timestamps or inter-arrival deltas in seconds.

    Outputs:
        Tuple[float, float]: (mean_inter_arrival_sec, variance_inter_arrival_sec^2).
        Returns (0.0, 0.0) if insufficient data points (< 2).

    Edge Cases:
        - Fewer than 2 points: Returns (0.0, 0.0).
        - Non-numeric or NaN values: Filtered safely.
        - Zero variance: Handled without error.
    """
    if flow_group is None:
        return (0.0, 0.0)

    try:
        arr = np.array(flow_group, dtype=float)
        arr = arr[~np.isnan(arr)]
    except (ValueError, TypeError):
        return (0.0, 0.0)

    if len(arr) < 2:
        return (0.0, 0.0)

    # If inputs look like monotonic timestamps, compute consecutive differences
    if np.all(np.diff(arr) >= 0) and (arr[-1] - arr[0] > 0):
        deltas = np.diff(arr)
    else:
        deltas = arr

    if len(deltas) == 0:
        return (0.0, 0.0)

    mean_val = float(np.mean(deltas))
    var_val = float(np.var(deltas, ddof=1)) if len(deltas) > 1 else 0.0

    return (round(max(0.0, mean_val), 6), round(max(0.0, var_val), 6))


def dns_entropy_and_length(domain: Optional[str]) -> Tuple[float, int]:
    """
    Calculates the Shannon character entropy and string length of a DNS query or domain name.

    Target Threat Category:
        DGA (Domain Generation Algorithms) & DNS Tunneling / Exfiltration.
        (High character randomness indicates algorithmic domain generation or encoded data tunneling;
        abnormally high length indicates exfiltration payload chunks).

    Inputs:
        domain (str | None): Fully qualified domain name or query string (e.g. 'xyz19aq92b.ns1.evilcorp.com').

    Outputs:
        Tuple[float, int]: (shannon_entropy, domain_length).
        Returns (0.0, 0) for empty, non-string, or invalid inputs.

    Edge Cases:
        - Empty string, whitespace or None: Returns (0.0, 0).
        - Single character: Entropy 0.0.
        - Strip common trailing dot if present.
    """
    if domain is None or not isinstance(domain, str):
        return (0.0, 0)

    clean_domain = domain.strip().rstrip('.').lower()
    length = len(clean_domain)
    if length == 0:
        return (0.0, 0)

    # Focus entropy on the subdomains / query prefix if multiple labels exist
    labels = clean_domain.split('.')
    query_label = labels[0] if len(labels) > 1 else clean_domain

    q_len = len(query_label)
    if q_len <= 1:
        return (0.0, length)

    char_counts: Dict[str, int] = {}
    for char in query_label:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        p_c = count / q_len
        if p_c > 0.0:
            entropy -= p_c * math.log2(p_c)

    return (float(round(max(0.0, entropy), 4)), length)


def byte_ratio(bytes_out: Union[int, float], bytes_in: Union[int, float], epsilon: float = 1.0) -> float:
    """
    Computes the outbound-to-inbound byte transfer ratio with division-by-zero protection.

    Target Threat Category:
        Data Exfiltration & Covert Channels.
        (Normal interactive or downloading traffic features high inbound bytes / low ratio;
        bulk data exfiltration produces heavy outbound skew with ratios >> 1.0).

    Inputs:
        bytes_out (int | float): Volume of outbound/uploaded bytes.
        bytes_in (int | float): Volume of inbound/downloaded bytes.
        epsilon (float): Smoothing denominator constant (default 1.0) to prevent division by zero.

    Outputs:
        float: Safe ratio (bytes_out / (bytes_in + epsilon)). Guaranteed non-negative.

    Edge Cases:
        - Negative values: Clamped to 0.0.
        - bytes_in == 0: Successfully protected by epsilon.
        - Non-numeric inputs: Coerced to 0.0.
    """
    try:
        out_val = max(0.0, float(bytes_out)) if bytes_out is not None else 0.0
        in_val = max(0.0, float(bytes_in)) if bytes_in is not None else 0.0
    except (ValueError, TypeError):
        return 0.0

    return float(round(out_val / (in_val + max(0.0001, epsilon)), 4))


def packet_timing_regularity(flow_or_intervals: Union[pd.Series, List[float], np.ndarray, Dict[str, Any]]) -> float:
    """
    Calculates the timing regularity coefficient of a flow or series of intervals.
    A score approaching 1.0 indicates near-perfect periodic intervals (beaconing),
    while values near 0.0 indicate high jitter or stochastic human-driven web behavior.

    Target Threat Category:
        Botnet C2 Beaconing / Automated Heartbeats.

    Inputs:
        flow_or_intervals: Array of inter-arrival times (in seconds) or a flow dictionary containing timing metrics.

    Outputs:
        float: Regularity score between 0.0 (erratic/stochastic) and 1.0 (strict periodic lockstep).

    Edge Cases:
        - Fewer than 2 intervals: Returns 0.0.
        - Zero interval / single burst: Returns 0.0.
        - Clamped securely between 0.0 and 1.0.
    """
    if flow_or_intervals is None:
        return 0.0

    if isinstance(flow_or_intervals, dict):
        variance = flow_or_intervals.get('inter_arrival_variance', 0.0)
        mean_delta = flow_or_intervals.get('inter_arrival_mean', 1.0)
        try:
            var_f = float(variance)
            mean_f = max(0.001, float(mean_delta))
            cv = math.sqrt(var_f) / mean_f
            return float(round(max(0.0, min(1.0, 1.0 / (1.0 + cv))), 4))
        except (ValueError, TypeError, ZeroDivisionError):
            return 0.0

    try:
        arr = np.array(flow_or_intervals, dtype=float)
        arr = arr[~np.isnan(arr)]
    except (ValueError, TypeError):
        return 0.0

    if len(arr) < 2:
        return 0.0

    mean_val = float(np.mean(arr))
    if mean_val <= 1e-6:
        return 0.0

    std_val = float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0
    # Coefficient of variation = std / mean
    cv = std_val / mean_val
    # Regularity mapped smoothly: 1 / (1 + CV)
    regularity = 1.0 / (1.0 + cv)

    return float(round(max(0.0, min(1.0, regularity)), 4))
