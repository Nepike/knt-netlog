import os
import subprocess
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


def send_report(report_path):
    zip_path = report_path + ".zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(report_path, arcname=os.path.basename(report_path))

    send_file_telegram(zip_path)
    os.remove(zip_path)


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

    for nf_file in files:
        print(f"Processing {nf_file}")

        try:
            report_path = generate_report(nf_file)
            send_report(report_path)
            os.remove(nf_file)
            print(f"Sent and removed {nf_file}")
        except Exception as e:
            print(f"⚠️ Error processing {nf_file}: {e}")

if __name__ == "__main__":
    process_files()