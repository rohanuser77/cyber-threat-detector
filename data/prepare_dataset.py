"""
Dataset Preparation and Plausible Synthetic Flow Generator.
Problem Statement: NTRO PS #26145 - AI-Based Detection of Cyber Threats in Unidirectional IP Traffic.

This script implements:
1. Priority check for raw network capture/flow data in data/raw/ (e.g., CICIDS2017).
2. Plausible, statistically varied synthetic flow generation across 6 threat classes + normal traffic
   when raw data is missing, preserving realistic overlap and avoiding trivial separability.
3. Feature consistency with features.feature_engineering.
4. Export to data/processed/flows.csv and provenance logging.
"""

import os
import json
import random
import datetime
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from features.feature_engineering import dns_entropy_and_length, byte_ratio

# Schema required by NTRO PS #26145
UNIFIED_SCHEMA = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "unique_dst_ports_per_src",
    "inter_arrival_variance",
    "dns_query_length",
    "dns_entropy",
    "outbound_inbound_byte_ratio",
    "label"
]

SUPPORTED_LABELS = [
    "normal",
    "ddos",
    "port_scan",
    "botnet_beacon",
    "dga_dns",
    "encrypted_malware",
    "exfiltration"
]


def random_ip(subnet: str = "192.168.1") -> str:
    """Generate an IP within a designated subnet."""
    return f"{subnet}.{random.randint(2, 254)}"


def generate_dga_domain() -> str:
    """Generate pseudo-random DGA domain resembling algorithmic malware generation."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    length = random.randint(14, 38)
    subdomain = "".join(random.choices(chars, k=length))
    tld = random.choice(["ru", "top", "xyz", "cc", "biz", "info", "net"])
    return f"{subdomain}.{tld}"


def generate_legit_domain() -> str:
    """Generate realistic standard DNS domain names."""
    legit_names = [
        "api.internal.corp", "updates.microsoft.com", "gateway.auth.service",
        "dns.google", "cdn.cloudflare.net", "repo.maven.apache.org",
        "ntp.org", "monitoring.telemetry.local", "mail.enterprise.in"
    ]
    return random.choice(legit_names)


def generate_synthetic_flow_dataset(
    n_samples: int = 10000,
    seed: int = 42
) -> pd.DataFrame:
    """
    Generates statistically plausible network flow records simulating a passive
    monitoring enclave fed by a unidirectional data diode.

    Introduces realistic variance and boundary overlap between benign and malicious flows.
    """
    random.seed(seed)
    np.random.seed(seed)

    base_time = datetime.datetime(2026, 9, 20, 10, 0, 0)
    flows: List[Dict[str, Any]] = []

    # Distribution weights: normal (55%), remaining 6 threat classes (~7.5% each)
    label_weights = {
        "normal": 0.52,
        "ddos": 0.08,
        "port_scan": 0.08,
        "botnet_beacon": 0.08,
        "dga_dns": 0.08,
        "encrypted_malware": 0.08,
        "exfiltration": 0.08
    }

    labels = random.choices(
        population=list(label_weights.keys()),
        weights=list(label_weights.values()),
        k=n_samples
    )

    current_sim_time = base_time

    for i, label in enumerate(labels):
        # Time progression in milliseconds/seconds
        delta_ms = random.randint(5, 120)
        current_sim_time += datetime.timedelta(milliseconds=delta_ms)
        timestamp_str = current_sim_time.isoformat()

        # Defaults initialized
        src_ip = random_ip("10.0.1")
        dst_ip = random_ip("172.16.0")
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 8080, 53, 22, 445])
        protocol = "TCP"
        dns_query = ""

        # Class-specific distributions with realistic overlap and borderline noise
        noise_factor = random.random()

        if label == "normal":
            protocol = random.choices(["TCP", "UDP"], weights=[0.82, 0.18])[0]
            duration = max(0.02, float(np.random.exponential(scale=2.8)))
            packet_count = int(np.random.lognormal(mean=2.9, sigma=0.9)) + 2
            avg_pkt_size = random.uniform(150, 1150)
            byte_count = int(packet_count * avg_pkt_size)
            
            # Borderline normal: occasionally a developer/admin scans or P2P/CDN creates fan-out
            if noise_factor < 0.04:
                unique_dst_ports = random.randint(6, 22)
            else:
                unique_dst_ports = random.randint(1, 5)

            inter_arrival_var = float(np.random.exponential(scale=1.1)) + 0.02

            # Borderline normal: uploading a file, git push, or video stream
            if noise_factor > 0.94:
                out_bytes = int(byte_count * random.uniform(0.75, 0.92))
            else:
                out_bytes = int(byte_count * random.uniform(0.12, 0.50))
            in_bytes = max(1, byte_count - out_bytes)

            # Some legitimate DNS has higher entropy (e.g. CDNs, cloud services)
            if protocol == "UDP" and random.random() < 0.35:
                dst_port = 53
                if noise_factor < 0.06:
                    dns_query = f"cdn-{random.randint(100,999)}a.{generate_legit_domain()}"
                else:
                    dns_query = generate_legit_domain()
            else:
                dst_port = random.choice([80, 443, 8080, 8443, 22, 53])

        elif label == "ddos":
            # High packet rate, short duration bursts, broad port/source target
            protocol = random.choices(["UDP", "TCP"], weights=[0.65, 0.35])[0]
            src_ip = random_ip(f"192.168.{random.randint(10, 50)}")
            dst_ip = "10.0.1.50"  # Target server
            dst_port = random.choice([80, 443, 53, 123])
            
            # Add variation in DDoS intensity (stealth vs high volume)
            if noise_factor < 0.12:  # Low-rate DDoS overlap
                duration = random.uniform(0.8, 3.5)
                packet_count = random.randint(20, 50)
            else:
                duration = max(0.005, float(np.random.exponential(scale=0.35)))
                packet_count = int(np.random.normal(loc=160, scale=45))
                packet_count = max(25, packet_count)

            byte_count = packet_count * random.randint(64, 450)
            unique_dst_ports = random.randint(1, 4)
            inter_arrival_var = float(np.random.uniform(0.0001, 0.05))
            out_bytes = int(byte_count * random.uniform(0.78, 0.96))
            in_bytes = max(1, byte_count - out_bytes)

        elif label == "port_scan":
            # High destination port fanout, single/few packets per connection
            protocol = "TCP"
            src_ip = "192.168.1.105"
            dst_ip = "10.0.1.20"
            src_port = random.randint(40000, 65000)
            dst_port = random.randint(1, 65535)
            duration = random.uniform(0.005, 0.25)
            packet_count = random.randint(1, 4)
            byte_count = packet_count * random.randint(40, 80)
            
            # Realistic stealth port scan overlap
            if noise_factor < 0.15:
                unique_dst_ports = random.randint(8, 20)
            else:
                unique_dst_ports = random.randint(22, 180)

            inter_arrival_var = float(np.random.exponential(scale=0.15))
            out_bytes = byte_count
            in_bytes = random.choice([0, 40, 52]) if noise_factor < 0.2 else 0

        elif label == "botnet_beacon":
            # Highly periodic inter-arrival with realistic jitter
            protocol = "TCP"
            src_ip = "10.0.1.88"
            dst_ip = "198.51.100.42"
            dst_port = random.choice([443, 8443, 8000, 8080])
            duration = random.uniform(0.08, 1.2)
            packet_count = random.randint(5, 18)
            byte_count = packet_count * random.randint(100, 260)
            unique_dst_ports = 1
            
            # Beacon jitter (some bots introduce 10-25% randomized jitter)
            if noise_factor < 0.20:
                inter_arrival_var = float(np.random.uniform(0.02, 0.08))
            else:
                inter_arrival_var = float(np.random.normal(loc=0.003, scale=0.001))
                inter_arrival_var = max(0.0002, inter_arrival_var)

            out_bytes = int(byte_count * random.uniform(0.48, 0.72))
            in_bytes = max(1, byte_count - out_bytes)

        elif label == "dga_dns":
            # DNS queries with high Shannon entropy and elevated label lengths
            protocol = "UDP"
            src_ip = "10.0.1.92"
            dst_ip = "1.1.1.1"
            dst_port = 53
            duration = random.uniform(0.02, 0.3)
            packet_count = random.randint(2, 8)
            byte_count = packet_count * random.randint(120, 520)
            unique_dst_ports = 1
            inter_arrival_var = random.uniform(0.01, 0.3)
            
            # Some DGA domains are shorter or use pseudo-dictionary words (lower entropy)
            if noise_factor < 0.18:
                dns_query = f"cdn-{random.choice(['secure','update','sync'])}{random.randint(10,99)}.biz"
            else:
                dns_query = generate_dga_domain()

            out_bytes = int(byte_count * 0.5)
            in_bytes = byte_count - out_bytes

        elif label == "encrypted_malware":
            # TLS/QUIC metadata anomalies without payload decryption
            protocol = random.choice(["TCP", "UDP"])
            src_ip = random_ip("10.0.1")
            dst_ip = random_ip("203.0.113")
            dst_port = 443
            duration = random.uniform(0.5, 9.0)
            packet_count = random.randint(25, 200)
            byte_count = packet_count * random.randint(600, 1400)
            unique_dst_ports = random.randint(1, 4)
            inter_arrival_var = random.uniform(0.04, 1.2)
            out_bytes = int(byte_count * random.uniform(0.58, 0.86))
            in_bytes = max(1, byte_count - out_bytes)

        elif label == "exfiltration":
            # Outbound skew, but with variation (slow & stealthy vs rapid dump)
            protocol = "TCP"
            src_ip = "10.0.1.15"
            dst_ip = "198.51.100.99"
            dst_port = random.choice([443, 8080, 21, 8500])
            duration = random.uniform(3.0, 35.0)
            
            if noise_factor < 0.16:  # Slow-and-low exfiltration
                packet_count = random.randint(30, 80)
                byte_count = packet_count * random.randint(400, 900)
                out_bytes = int(byte_count * random.uniform(0.72, 0.85))
            else:
                packet_count = random.randint(110, 800)
                byte_count = packet_count * random.randint(1000, 1480)
                out_bytes = int(byte_count * random.uniform(0.88, 0.98))

            unique_dst_ports = 1
            inter_arrival_var = random.uniform(0.005, 0.12)
            in_bytes = max(1, byte_count - out_bytes)

        # Derived rates with safe denominators
        dur_safe = max(0.001, duration)
        flow_bytes_per_sec = round(byte_count / dur_safe, 2)
        flow_packets_per_sec = round(packet_count / dur_safe, 2)

        # DNS calculations using feature_engineering
        if dns_query:
            dns_entropy_val, dns_len = dns_entropy_and_length(dns_query)
        else:
            dns_entropy_val, dns_len = 0.0, 0

        # Safe byte ratio
        ratio = byte_ratio(out_bytes, in_bytes)

        flow_record = {
            "timestamp": timestamp_str,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration": round(duration, 4),
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "flow_packets_per_sec": flow_packets_per_sec,
            "unique_dst_ports_per_src": unique_dst_ports,
            "inter_arrival_variance": round(inter_arrival_var, 6),
            "dns_query_length": dns_len,
            "dns_entropy": dns_entropy_val,
            "outbound_inbound_byte_ratio": ratio,
            "label": label
        }
        flows.append(flow_record)

    df = pd.DataFrame(flows)
    return df[UNIFIED_SCHEMA]


def prepare_dataset(
    raw_dir: Path,
    synthetic_dir: Path,
    processed_dir: Path,
    sample_size: int = 10000
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Orchestrates dataset discovery, raw file parsing (if present), or synthetic fallback.
    Writes the unified dataset to processed/flows.csv and returns metadata.
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    synthetic_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)

    raw_files = list(raw_dir.glob("*.csv"))
    is_synthetic = True
    metadata: Dict[str, Any] = {
        "dataset_source": "Plausible Synthetic Flow Dataset (NTRO PS #26145 Engine)",
        "raw_files_found": [f.name for f in raw_files],
        "generated_at": datetime.datetime.now().isoformat(),
        "total_records": 0,
        "class_distribution": {},
        "provenance_note": (
            "Generated using statistical distributions modeled on realistic attack signatures "
            "(DDoS floods, port scans, periodic C2 beaconing, DGA entropy, encrypted anomalies, exfiltration). "
            "Simulates a passive data diode monitoring enclave without payload decryption."
        )
    }

    if raw_files:
        print(f"[*] Found {len(raw_files)} raw dataset file(s) in {raw_dir}. Attempting to parse...")
        try:
            # Attempt loading and matching schema
            dfs = []
            for rf in raw_files:
                cdf = pd.read_csv(rf, nrows=5000)
                dfs.append(cdf)
            combined = pd.concat(dfs, ignore_index=True)
            # Check if unified schema is present
            if all(col in combined.columns for col in UNIFIED_SCHEMA):
                df = combined[UNIFIED_SCHEMA]
                is_synthetic = False
                metadata["dataset_source"] = f"Real Network Flow Capture ({len(raw_files)} files)"
                print("[+] Successfully parsed raw dataset conforming to unified schema.")
            else:
                print("[-] Raw files did not match required unified schema. Falling back to synthetic generator.")
                df = generate_synthetic_flow_dataset(n_samples=sample_size)
        except Exception as e:
            print(f"[-] Error parsing raw files: {e}. Falling back to synthetic generation.")
            df = generate_synthetic_flow_dataset(n_samples=sample_size)
    else:
        print(f"[*] No raw CICIDS files in {raw_dir}. Generating {sample_size} plausible synthetic flows...")
        df = generate_synthetic_flow_dataset(n_samples=sample_size)

    # Save to synthetic copy and processed destination
    synth_path = synthetic_dir / "synthetic_flows.csv"
    processed_path = processed_dir / "flows.csv"

    if is_synthetic:
        df.to_csv(synth_path, index=False)
        print(f"[+] Saved synthetic copy to {synth_path}")

    df.to_csv(processed_path, index=False)
    print(f"[+] Saved unified processed dataset to {processed_path}")

    metadata["total_records"] = len(df)
    metadata["class_distribution"] = df["label"].value_counts().to_dict()

    metadata_path = processed_dir / "dataset_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved dataset metadata to {metadata_path}")

    return df, metadata


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    raw_path = project_root / "data" / "raw"
    synth_path = project_root / "data" / "synthetic"
    proc_path = project_root / "data" / "processed"

    df_result, meta = prepare_dataset(raw_path, synth_path, proc_path, sample_size=10000)
    print("\nDataset Preparation Summary:")
    print(f"  Total records: {meta['total_records']}")
    print(f"  Source: {meta['dataset_source']}")
    print("  Class distribution:")
    for cls_name, count in meta["class_distribution"].items():
        pct = (count / meta['total_records']) * 100
        print(f"    - {cls_name:18s}: {count:5d} ({pct:5.1f}%)")
