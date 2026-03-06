import os
import subprocess

import paramiko
import yaml
import requests
from datetime import datetime
import time
import zipfile

BASE_DIR = "/srv/netlog/script"
CONFIG_PATH = os.path.join(BASE_DIR, "config.yml")

with open(CONFIG_PATH) as f:
    CONFIG = yaml.safe_load(f)

TOKEN = CONFIG["telegram_bot"]["token"]
CHAT_ID = CONFIG["telegram_bot"]["chat_id"]

CHUNKS_DIR = CONFIG["netflow"]["chunks_dir"]
REPORTS_DIR = CONFIG["netflow"]["reports_dir"]
MACS_DIR = CONFIG["netflow"]["macs_dir"]

MIKROTIK_IP = CONFIG["mikrotik"]["ip"]
USERNAME = CONFIG["mikrotik"]["username"]
PASSWORD = CONFIG["mikrotik"]["password"]


def send_file_telegram(file_path):
    url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
    with open(file_path, "rb") as f:
        r = requests.post(url, files={"document": f}, data={"chat_id": CHAT_ID}, timeout=300)
        r.raise_for_status()


def generate_report(nf_file):
    filename = os.path.basename(nf_file)
    report_name = f"report_{filename}.txt"
    report_path = os.path.join(REPORTS_DIR, report_name)

    cmd = [
        "nfdump",
        "-r", nf_file,
        "not (src ip 192.168.16.1 or src ip 192.168.16.10 or src ip 192.168.16.20 or src ip 192.168.16.30) "
        "and src net 192.168.16.0/20 "
        "and not dst net 192.168.16.0/24 "
        "and not dst net 10.0.0.0/8 "
        "and not dst net 172.16.0.0/12 "
        "and not port 53 "
        "and not port 67 "
        "and not port 68 ",
        "-o", "extended"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("NetFlow Report\n")
        f.write(f"Generated at: {datetime.now()}\n")
        f.write(f"Source file: {filename}\n")
        f.write("="*100 + "\n\n")
        f.write(result.stdout)

    return report_path



def fetch_arp_table():
    os.makedirs(MACS_DIR, exist_ok=True)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(MIKROTIK_IP, username=USERNAME, password=PASSWORD)

    stdin, stdout, stderr = ssh.exec_command("/ip arp print detail without-paging")
    output = stdout.read().decode()
    ssh.close()

    filename = f"arp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(MACS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("ARP/MAC Table\n")
        f.write(f"Generated at: {datetime.now()}\n")
        f.write("="*80 + "\n\n")
        f.write(output)

    return filepath


def add_to_zip(zip_path, files):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file in files:
            zipf.write(file, arcname=os.path.basename(file))



def get_ready_files():
    files = []
    now = time.time()

    for f in os.listdir(CHUNKS_DIR):
        if f.startswith("nfcapd.current"):
            continue
        if not f.startswith("nfcapd."):
            continue

        full_path = os.path.join(CHUNKS_DIR, f)

        if now - os.path.getmtime(full_path) < 600:
            continue

        files.append(full_path)

    return sorted(files)


def process_files():
    files = get_ready_files()
    if not files:
        print("Нет готовых файлов NetFlow")
        return

    for nf_file in files:
        print(f"Processing {nf_file}")
        try:
            report_path = generate_report(nf_file)
            arp_file = fetch_arp_table()
            zip_path = report_path + ".zip"
            add_to_zip(zip_path, [report_path, arp_file])
            send_file_telegram(zip_path)

            os.remove(nf_file)
            os.remove(report_path)
            os.remove(arp_file)
            os.remove(zip_path)
            print(f"Sent and removed {nf_file}, report, ARP dump, ZIP")
        except Exception as e:
            print(f"⚠️ Error processing {nf_file}: {e}")

if __name__ == "__main__":
    process_files()