import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from parser import resolve_hostname
from datetime import datetime

DB_FILE = "flows.parquet"
TOP_N_HOSTS = 10  # разрешаем hostname только для топ-N активных


def load_db():
    df = pd.read_parquet(DB_FILE)
    print(f"[INFO] Loaded {len(df)} flow records")
    return df


def add_time_features(df):
    df['hour'] = df['timestamp'].dt.hour
    df['date'] = df['timestamp'].dt.date
    return df


def map_top_hostnames(df, n=TOP_N_HOSTS):
    """
    Определяем hostname только для топ-N destination IP по сумме трафика
    """
    top_ips = df.groupby('dst_ip')['bytes'].sum().sort_values(ascending=False).head(n).index
    ip_to_host = {ip: resolve_hostname(ip) for ip in top_ips}
    df['dst_hostname'] = df['dst_ip'].apply(lambda ip: ip_to_host.get(ip, ip))
    return df


def basic_stats(df):
    print("=== BASIC STATS ===")
    print(f"Unique source IPs: {df['src_ip'].nunique()}")
    print(f"Unique destination IPs: {df['dst_ip'].nunique()}")
    print(f"Unique MACs: {df['src_mac'].nunique()}")
    print(f"MAC mismatches: {df['mac_mismatch'].sum()}")
    print("\nTop 10 active source IPs by bytes:")
    print(df.groupby('src_ip')['bytes'].sum().sort_values(ascending=False).head(10))

    print("\nTop 10 active destination hosts by bytes:")
    print(df.groupby('dst_hostname')['bytes'].sum().sort_values(ascending=False).head(10))

    print("\nTop protocols by flows:")
    print(df['protocol'].value_counts())


def plot_heatmap(df):
    df = add_time_features(df)
    pivot = df.pivot_table(
        index='src_ip', columns='hour', values='bytes', aggfunc='sum', fill_value=0
    )
    plt.figure(figsize=(14, max(6, len(pivot) * 0.3)))
    sns.heatmap(pivot, cmap='YlGnBu', linewidths=0.5)
    plt.title("Heatmap: Source IP activity by hour")
    plt.xlabel("Hour of day")
    plt.ylabel("Source IP")
    plt.tight_layout()
    plt.show()


def plot_mac_mismatches(df):
    mismatches = df[df['mac_mismatch']]
    if mismatches.empty:
        print("[INFO] No MAC mismatches detected.")
        return
    summary = mismatches.groupby('src_ip')['src_mac'].nunique()
    print("\nMAC mismatch summary (src_ip -> number of different MACs):")
    print(summary)


def top_flows(df, n=20):
    df['flow_pair'] = df['src_ip'] + " -> " + df['dst_hostname']
    top = df.groupby('flow_pair')['bytes'].sum().sort_values(ascending=False).head(n)
    print("\nTop flows by bytes:")
    print(top)


def main():
    df = load_db()
    df = map_top_hostnames(df, n=TOP_N_HOSTS)
    basic_stats(df)
    plot_heatmap(df)
    plot_mac_mismatches(df)
    top_flows(df)


if __name__ == "__main__":
    main()