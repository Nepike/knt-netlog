import os
import re
import zipfile
import socket
from datetime import datetime
from pathlib import Path
from functools import lru_cache

import pandas as pd
from ipwhois import IPWhois

DATA_DIR = Path("data")
DB_FILE = Path("flows.parquet")

# @dataclass
# class FlowRecord:
#     timestamp: datetime
#     duration: float
#     protocol: str
#
#     src_mac: Optional[str]
#     src_ip: str
#     src_port: int
#
#     dst_hostname: str
#     dst_ip: str
#     dst_port: int
#
#     bytes: int
#     packets: int
#     flags: str


@lru_cache(maxsize=10000)
def resolve_hostname(ip: str) -> str:
    if ip.startswith(("192.168.", "10.", "172.")):
        return "LOCAL"

    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return res.get("network", {}).get("name")
    except Exception:
        pass

    return "UNKNOWN"

def add_hostnames(df: pd.DataFrame) -> pd.DataFrame:
    unique_ips = df["dst_ip"].dropna().unique()
    ip_map = {ip: resolve_hostname(ip) for ip in unique_ips}
    df["dst_hostname"] = df["dst_ip"].map(ip_map)
    return df


def load_db() -> pd.DataFrame:
    if DB_FILE.exists():
        print("[LOAD] existing database")
        return pd.read_parquet(DB_FILE)
    else:
        print("[INIT] new database created")
        return pd.DataFrame(columns=[
            "timestamp", "duration", "protocol",
            "src_ip", "src_mac",
            "dst_ip", "dst_port",
            "bytes", "packets",
            "flags", "mac_mismatch",
            "dst_hostname"
        ])

def save_db(df: pd.DataFrame):
    df.to_parquet(DB_FILE, index=False)
    print("[SAVE] database updated")


def parse_arp(path: Path) -> dict:
    arp = {}
    if not path:
        return arp

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = re.search(r'address=(\d+\.\d+\.\d+\.\d+)\s+mac-address=([0-9A-F:]{17})', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2).upper()
                arp[ip] = mac

    return arp


FLOW_REGEX = re.compile(
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'([\d\.]+)\s+'
    r'(\w+)\s+'
    r'([\d\.]+):(\d+)\s+->\s+'
    r'([\d\.]+):(\d+)\s+'
    r'([\.A-Z]+)\s+'
    r'\d+\s+'
    r'(\d+)\s+'
    r'(\d+)'
)

def parse_report(path: Path, arp_map: dict, existing_ip_mac: dict) -> pd.DataFrame:
    rows = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = FLOW_REGEX.search(line)
            if not m:
                continue

            timestamp = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f")
            duration = float(m.group(2))
            protocol = m.group(3)
            src_ip = m.group(4)
            src_port = int(m.group(5))
            dst_ip = m.group(6)
            dst_port = int(m.group(7))
            flags = m.group(8)
            packets = int(m.group(9))
            bytes_ = int(m.group(10))

            src_mac = arp_map.get(src_ip)


            mac_mismatch = False
            if src_ip in existing_ip_mac:
                if src_mac and existing_ip_mac[src_ip] != src_mac:
                    mac_mismatch = True
            else:
                if src_mac:
                    existing_ip_mac[src_ip] = src_mac

            dst_hostname = "-" #resolve_hostname(dst_ip)

            # filter
            if all([duration < 1, packets < 3, bytes_ < 50]):
                continue

            rows.append({
                "timestamp": timestamp,
                "duration": duration,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_mac": src_mac,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "bytes": bytes_,
                "packets": packets,
                "flags": flags,
                "mac_mismatch": mac_mismatch,
                "dst_hostname": dst_hostname
            })

    return pd.DataFrame(rows)

def process_zip(zip_path: Path, df_existing: pd.DataFrame) -> pd.DataFrame:
    print(f"[PROCESS] {zip_path.name}")

    tmp_dir = zip_path.parent / "tmp_extract"
    tmp_dir.mkdir(exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(tmp_dir)

    arp_file = None
    report_file = None

    for f in tmp_dir.iterdir():
        if "arp" in f.name.lower():
            arp_file = f
        if "report" in f.name.lower():
            report_file = f

    arp_map = parse_arp(arp_file)

    # *тут могла бы висеть ваша оптимизация*
    existing_ip_mac = (
        df_existing.dropna(subset=["src_mac"])
        .drop_duplicates("src_ip")
        .set_index("src_ip")["src_mac"]
        .to_dict()
    )

    df_new = parse_report(report_file, arp_map, existing_ip_mac)

    for f in tmp_dir.iterdir():
        f.unlink()
    tmp_dir.rmdir()

    return df_new

if __name__ == "__main__":

    df = load_db()

    zip_files = sorted(DATA_DIR.glob("*.zip"))

    for zip_path in zip_files:
        df_new = process_zip(zip_path, df)
        df = pd.concat([df, df_new], ignore_index=True)

    save_db(df)

    print("\n===== SUMMARY =====")
    print(f"Total flows: {len(df)}")
    print(f"Unique src IP: {df['src_ip'].nunique()}")
    print(f"MAC mismatches: {df['mac_mismatch'].sum()}")