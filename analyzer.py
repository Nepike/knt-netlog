
# ЭТОТ КОД ВЫСРАЛ ЧАТ ГПТ Я БОЛЬШУЮ ЧАСТЬ ДАЖЕ НЕ ЧИТАЛ - ЧИСТО НА ВЕРЕ СБОРКА

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

DB_FILE = "flows.parquet"


# -----------------------------------------------------------
# LOAD DATABASE
# -----------------------------------------------------------

def load_db(path: str = DB_FILE) -> pd.DataFrame:

    df = pd.read_parquet(path)

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    df["date"] = df["timestamp"].dt.date
    df["minute"] = df["timestamp"].dt.minute

    return df


# -----------------------------------------------------------
# GLOBAL ACTIVITY GRAPH
# -----------------------------------------------------------

def plot_global_activity(day=None, metric="packets"):

    df = load_db()

    if day:
        df = df[df["date"] == pd.to_datetime(day).date()]

    df = df.set_index("timestamp")

    if metric == "flows":
        series = df.resample("5min").size()
    else:
        series = df.resample("5min")[metric].sum()

    plt.figure(figsize=(12,5))
    plt.plot(series)

    plt.title(f"Network activity ({metric})")
    plt.xlabel("Time")
    plt.ylabel(metric)

    plt.grid()
    plt.show()


# -----------------------------------------------------------
# ACTIVITY OF SPECIFIC IP
# -----------------------------------------------------------

def plot_ip_activity(ip, metric="packets"):

    df = load_db()

    df = df[df["src_ip"] == ip]
    df = df.set_index("timestamp")

    series = df.resample("5min")[metric].sum()

    plt.figure(figsize=(12,5))
    plt.plot(series)

    plt.title(f"Activity for {ip}")
    plt.xlabel("Time")
    plt.ylabel(metric)

    plt.grid()
    plt.show()


# -----------------------------------------------------------
# TOP ACTIVE USERS
# -----------------------------------------------------------

def top_users(n=10, metric="packets"):

    df = load_db()

    if metric == "flows":
        res = df.groupby("src_ip").size()
    else:
        res = df.groupby("src_ip")[metric].sum()

    res = res.sort_values(ascending=False).head(n)

    print(res)

    res.plot(kind="bar", figsize=(10,5))

    plt.title(f"Top {n} users ({metric})")
    plt.ylabel(metric)
    plt.show()


# -----------------------------------------------------------
# TOP USERS IN TIME PERIOD
# -----------------------------------------------------------

def top_users_in_period(start, end, metric="packets", top_n=10):

    df = load_db()

    start = pd.to_datetime(start)
    end = pd.to_datetime(end)

    df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end)]

    if metric == "flows":
        res = df.groupby("src_ip").size()
    else:
        res = df.groupby("src_ip")[metric].sum()

    res = res.sort_values(ascending=False).head(top_n)

    print(f"\nTop {top_n} users from {start} to {end}")
    print(res)

    return res


# -----------------------------------------------------------
# HEATMAP OF USER ACTIVITY BY HOURS
# -----------------------------------------------------------

def heatmap_user_hours(n=15, metric="packets"):

    df = load_db()

    if metric == "flows":
        table = df.groupby(["src_ip", "hour"]).size()
    else:
        table = df.groupby(["src_ip", "hour"])[metric].sum()

    table = table.unstack(fill_value=0)

    top = table.sum(axis=1).sort_values(ascending=False).head(n)

    table = table.loc[top.index]

    plt.figure(figsize=(14,6))

    sns.heatmap(table, cmap="viridis")

    plt.title("User activity by hour")
    plt.xlabel("Hour")
    plt.ylabel("IP")

    plt.show()


# -----------------------------------------------------------
# DESTINATION HEATMAP FOR USER
# -----------------------------------------------------------

def heatmap_user_destinations(ip, top_n=20):

    df = load_db()

    df = df[df["src_ip"] == ip]

    top = (
        df.groupby("dst_ip")["packets"]
        .sum()
        .sort_values(ascending=False)
        .head(top_n)
    )

    plt.figure(figsize=(10,6))

    sns.barplot(
        x=top.values,
        y=top.index
    )

    plt.title(f"Top destinations for {ip}")
    plt.xlabel("Packets")

    plt.show()


# -----------------------------------------------------------
# NIGHT ACTIVITY
# -----------------------------------------------------------

def night_activity(start=0, end=6, min_packets=10000):

    df = load_db()

    df = df[(df["hour"] >= start) & (df["hour"] <= end)]

    res = (
        df.groupby("src_ip")["packets"]
        .sum()
        .sort_values(ascending=False)
    )

    res = res[res > min_packets]

    print("\nNight activity:")
    print(res)


# -----------------------------------------------------------
# DETECT SCANNERS
# -----------------------------------------------------------

def detect_scanners(threshold=200):

    df = load_db()

    res = df.groupby("src_ip")["dst_ip"].nunique()

    res = res.sort_values(ascending=False)

    suspicious = res[res > threshold]

    print("\nPossible scanners:")
    print(suspicious)


# -----------------------------------------------------------
# FIND IPS ACTIVE IN MULTIPLE TIME WINDOWS
# -----------------------------------------------------------

def find_common_active_ips(windows, top_n=None):

    df = load_db()

    sets = []

    for start, end in windows:

        start = pd.to_datetime(start)
        end = pd.to_datetime(end)

        window_df = df[(df["timestamp"] >= start) & (df["timestamp"] <= end)]

        ips = set(window_df["src_ip"].unique())

        print(f"\nActive IPs {start} — {end}: {len(ips)}")

        if top_n:
            top = (
                window_df.groupby("src_ip")["packets"]
                .sum()
                .sort_values(ascending=False)
                .head(top_n)
            )
            print(top)

        sets.append(ips)

    common = set.intersection(*sets)

    print("\nIPs active in ALL windows:")
    for ip in common:
        print(ip)

    return common


# -----------------------------------------------------------
# FIND USERS ACTIVE AROUND SPECIFIC TIME
# -----------------------------------------------------------

def find_users_active_at(hour):

    df = load_db()

    df = df[df["hour"] == hour]

    res = (
        df.groupby("src_ip")["packets"]
        .sum()
        .sort_values(ascending=False)
    )

    print(f"\nUsers active at hour {hour}")
    print(res.head(20))


# -----------------------------------------------------------
# DETECT STABLE USERS (REGULAR SCHEDULE)
# -----------------------------------------------------------

def detect_stable_users(min_days=3, min_packets=5000):

    df = load_db()

    table = (
        df.groupby(["src_ip", "date", "hour"])["packets"]
        .sum()
        .reset_index()
    )

    table = table[table["packets"] > min_packets]

    stable = (
        table.groupby(["src_ip", "hour"])
        .size()
        .reset_index(name="days")
    )

    stable = stable[stable["days"] >= min_days]

    stable = stable.sort_values(["src_ip", "hour"])

    print("\nStable user hours:")
    print(stable)

    return stable


# -----------------------------------------------------------
# USER DAILY HEATMAP
# -----------------------------------------------------------

def plot_user_schedule(ip):

    df = load_db()

    user = df[df["src_ip"] == ip]

    table = (
        user.groupby(["date", "hour"])["packets"]
        .sum()
        .unstack(fill_value=0)
    )

    plt.figure(figsize=(12,5))

    sns.heatmap(table, cmap="magma")

    plt.title(f"Daily activity pattern: {ip}")
    plt.xlabel("Hour")
    plt.ylabel("Date")

    plt.show()


# -----------------------------------------------------------
# MAIN
# -----------------------------------------------------------

if __name__ == "__main__":

    # пример анализа

    top_users_in_period(
        "2026-03-03 13:37",
        "2026-03-03 13:39",
        metric="packets",
        top_n=5
    )

    top_users_in_period(
        "2026-03-05 14:23",
        "2026-03-05 14:25",
        metric="packets",
        top_n=5
    )

    windows = [
        ("2026-03-03 13:37", "2026-03-03 13:39"),
        ("2026-03-05 14:23", "2026-03-05 14:25")
    ]

    suspects = find_common_active_ips(windows)

    # for ip in suspects:
    #     plot_ip_activity(ip)

    plot_user_schedule("192.168.16.34")
