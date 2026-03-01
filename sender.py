import os
import subprocess
import yaml
import telebot
from datetime import datetime
import time

BASE_DIR = "/srv/netlog"
CONFIG_PATH = os.path.join(BASE_DIR, "config.yml")

with open(CONFIG_PATH) as f:
    CONFIG = yaml.safe_load(f)

TOKEN = CONFIG["telegram_bot"]["token"]
CHAT_ID = CONFIG["telegram_bot"]["chat_id"]

CHUNKS_DIR = CONFIG["netflow"]["chunks_dir"]
REPORTS_DIR = CONFIG["netflow"]["reports_dir"]

bot = telebot.TeleBot(TOKEN)

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

        report_path = generate_report(nf_file)

        with open(report_path, "rb") as doc:
            bot.send_document(CHAT_ID, doc)

        os.remove(nf_file)
        print(f"Sent and removed {nf_file}")


if __name__ == "__main__":
    process_files()