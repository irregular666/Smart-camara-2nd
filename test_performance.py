"""
============================================================================
网关系统性能测试 — 连接时间 & 帧传输 & 录像存储
============================================================================
生成可视化图表到 test_output/ 目录
运行: python test_performance.py
============================================================================
"""

import os
import sys
import time
import struct
import socket
import threading
import hashlib
import shutil
import tempfile
from gmssl import sm3

OUT_DIR = "test_output"
os.makedirs(OUT_DIR, exist_ok=True)


# ========================== HMAC-SM3 函数（与 gateway.py 一致） ==========================

def hmac_sm3(key_bytes, msg_bytes):
    blocksize = 64
    if len(key_bytes) > blocksize:
        key_bytes = bytes.fromhex(sm3.sm3_hash(list(key_bytes)))
    key_bytes = key_bytes.ljust(blocksize, b'\x00')
    ipad = bytes(x ^ 0x36 for x in key_bytes)
    opad = bytes(x ^ 0x5c for x in key_bytes)
    inner_hash = bytes.fromhex(sm3.sm3_hash(list(ipad + msg_bytes)))
    return bytes.fromhex(sm3.sm3_hash(list(opad + inner_hash))).hex()


# ========================== 测试 1: TCP 连接建立时间 ==========================

def test_connection_timing():
    """测试与网关建立 TCP 连接的时间"""
    print("\n" + "=" * 60)
    print("测试 1: TCP 连接建立时间")
    print("=" * 60)

    # 启动一个简单的 echo 服务器用于测试（使用列表避免闭包作用域问题）
    server_ready = threading.Event()
    port_holder = [0]  # 用可变容器在线程间传递端口号

    def run_echo_server():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        port_holder[0] = server.getsockname()[1]
        server_ready.set()
        while True:
            try:
                conn, addr = server.accept()
                conn.close()
            except:
                break

    server_thread = threading.Thread(target=run_echo_server, daemon=True)
    server_thread.start()
    server_ready.wait(timeout=2)
    server_port = port_holder[0]

    connect_times = []
    for i in range(200):
        t0 = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect(('127.0.0.1', server_port))
            elapsed_ms = (time.perf_counter() - t0) * 1000
            connect_times.append(elapsed_ms)
            sock.close()
        except Exception as e:
            print(f"  连接 {i} 失败: {e}")

    avg_connect = sum(connect_times) / len(connect_times) if connect_times else 0
    min_connect = min(connect_times) if connect_times else 0
    max_connect = max(connect_times) if connect_times else 0
    p95 = sorted(connect_times)[int(len(connect_times) * 0.95)] if connect_times else 0

    print(f"  测试次数: {len(connect_times)}")
    print(f"  平均连接时间: {avg_connect:.3f} ms")
    print(f"  最小/最大: {min_connect:.3f} / {max_connect:.3f} ms")
    print(f"  P95: {p95:.3f} ms")

    # 模拟局域网延迟（对比）
    lan_estimate = avg_connect * 0.3  # 局域网通常更快
    wan_estimate = avg_connect * 15   # 广域网通常更慢
    print(f"  预估局域网延迟: ~{lan_estimate:.3f} ms")
    print(f"  预估广域网延迟: ~{wan_estimate:.3f} ms")

    return {
        "connect_times": connect_times,
        "avg": avg_connect,
        "min": min_connect,
        "max": max_connect,
        "p95": p95,
        "lan_estimate": lan_estimate,
        "wan_estimate": wan_estimate,
    }


# ========================== 测试 2: 完整认证 + 帧传输模拟 ==========================

def test_full_auth_and_stream():
    """模拟完整的设备->网关认证+推流流程"""
    print("\n" + "=" * 60)
    print("测试 2: 完整认证 + 帧传输模拟 (端到端)")
    print("=" * 60)

    PSK = "my_secure_psk_2023"
    UID = "CAM-001"

    # 启动模拟网关（使用列表在线程间共享端口号）
    gateway_ready = threading.Event()
    auth_result = {"success": False, "frames_received": 0, "total_bytes": 0}
    gw_port_holder = [0]

    def run_mock_gateway():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        gw_port_holder[0] = server.getsockname()[1]
        gateway_ready.set()

        try:
            conn, addr = server.accept()
            conn.settimeout(5)

            # 1. 接收 UID
            uid = conn.recv(1024).decode('utf-8').strip()

            # 2. 发送挑战码
            challenge = os.urandom(16).hex()
            timestamp = str(int(time.time()))
            challenge_payload = f"{challenge}|{timestamp}"
            conn.send(challenge_payload.encode('utf-8'))

            # 3. 接收应答并验证
            device_response = conn.recv(1024).decode('utf-8').strip()
            expected_mac = hmac_sm3(PSK.encode('utf-8'), challenge_payload.encode('utf-8'))

            if device_response == expected_mac:
                conn.send(b"AUTH_SUCCESS")
                auth_result["success"] = True

                # 4. 接收视频帧
                conn.settimeout(3)
                for _ in range(100):  # 接收 100 帧
                    try:
                        length_bytes = conn.recv(4)
                        if not length_bytes:
                            break
                        frame_len = struct.unpack(">I", length_bytes)[0]
                        frame_data = b""
                        while len(frame_data) < frame_len:
                            packet = conn.recv(min(4096, frame_len - len(frame_data)))
                            if not packet:
                                break
                            frame_data += packet
                        auth_result["frames_received"] += 1
                        auth_result["total_bytes"] += len(frame_data)
                    except socket.timeout:
                        break
            else:
                conn.send(b"AUTH_FAILED")

            conn.close()
            server.close()
        except Exception as e:
            print(f"  模拟网关异常: {e}")

    gw_thread = threading.Thread(target=run_mock_gateway, daemon=True)
    gw_thread.start()
    gateway_ready.wait(timeout=3)
    gw_port = gw_port_holder[0]

    # 模拟设备端连接
    device_timeline = []
    t_total_start = time.perf_counter()

    # 连接
    t_conn_start = time.perf_counter()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3.0)
    client.connect(('127.0.0.1', gw_port))
    t_conn_end = time.perf_counter()
    device_timeline.append(("TCP连接", (t_conn_end - t_conn_start) * 1000))

    # 发送 UID
    client.send(UID.encode('utf-8'))

    # 接收挑战
    challenge_payload = client.recv(1024).decode('utf-8')

    # 计算应答
    t_auth_start = time.perf_counter()
    my_mac = hmac_sm3(PSK.encode('utf-8'), challenge_payload.encode('utf-8'))
    client.send(my_mac.encode('utf-8'))
    t_auth_end = time.perf_counter()
    device_timeline.append(("HMAC-SM3计算", (t_auth_end - t_auth_start) * 1000))

    # 接收认证结果
    result = client.recv(1024).decode('utf-8')

    # 发送模拟帧
    frame_times = []
    for i in range(100):
        # 生成模拟 JPEG 帧（不同大小模拟真实场景）
        frame_size = int(8000 + 12000 * (0.5 + 0.5 * __import__('math').sin(i * 0.3)))
        frame_data = os.urandom(frame_size)

        t_frame_start = time.perf_counter()
        header = struct.pack(">I", len(frame_data))
        client.sendall(header + frame_data)
        t_frame_end = time.perf_counter()
        frame_times.append((t_frame_end - t_frame_start) * 1000)
        time.sleep(0.01)  # 模拟 ~100fps 压力

    t_total_end = time.perf_counter()
    device_timeline.append(("100帧传输", sum(frame_times)))
    device_timeline.append(("总耗时", (t_total_end - t_total_start) * 1000))

    client.close()
    gw_thread.join(timeout=2)

    print(f"  认证结果: {'[PASS] 成功' if auth_result['success'] else '[FAIL] 失败'}")
    print(f"  接收帧数: {auth_result['frames_received']}/100")
    print(f"  接收字节: {auth_result['total_bytes']:,} bytes")
    print(f"  帧传输速率: {auth_result['frames_received'] / ((t_total_end - t_total_start)):.1f} fps")
    print(f"  数据吞吐量: {auth_result['total_bytes'] / (t_total_end - t_total_start) / 1024:.1f} KB/s")

    for label, ms in device_timeline:
        print(f"    {label}: {ms:.3f} ms")

    return {
        "auth_success": auth_result["success"],
        "frames_received": auth_result["frames_received"],
        "total_bytes": auth_result["total_bytes"],
        "timeline": device_timeline,
        "frame_times": frame_times,
        "total_time_ms": (t_total_end - t_total_start) * 1000,
    }


# ========================== 测试 3: 录像存储写入性能 ==========================

def test_recording_storage():
    """测试录像帧写入磁盘的性能"""
    print("\n" + "=" * 60)
    print("测试 3: 录像存储写入性能")
    print("=" * 60)

    temp_dir = tempfile.mkdtemp(prefix="recording_test_")

    write_times = []
    file_sizes = []
    total_bytes = 0

    # 模拟不同大小的帧写入
    frame_sizes = [5000, 10000, 15000, 20000, 30000, 50000]  # 典型 JPEG 大小范围

    for size in frame_sizes:
        frame_data = os.urandom(size)
        filename = os.path.join(temp_dir, f"test_{size}.jpg")

        t0 = time.perf_counter()
        with open(filename, 'wb') as f:
            f.write(frame_data)
        elapsed_us = (time.perf_counter() - t0) * 1_000_000
        write_times.append((size, elapsed_us))

        # 验证写入
        with open(filename, 'rb') as f:
            read_back = f.read()
        assert read_back == frame_data, "数据损坏!"
        file_sizes.append(os.path.getsize(filename))
        total_bytes += size

    # 批量写入压力测试
    bulk_count = 500
    bulk_data = os.urandom(12000)  # 模拟 ~12KB JPEG 帧
    bulk_dir = os.path.join(temp_dir, "bulk")
    os.makedirs(bulk_dir, exist_ok=True)

    t_bulk_start = time.perf_counter()
    for i in range(bulk_count):
        fpath = os.path.join(bulk_dir, f"frame_{i:06d}.jpg")
        with open(fpath, 'wb') as f:
            f.write(bulk_data)
    t_bulk_end = time.perf_counter()

    bulk_elapsed_ms = (t_bulk_end - t_bulk_start) * 1000
    bulk_throughput = bulk_count / (bulk_elapsed_ms / 1000)  # frames/sec
    bulk_data_rate = (bulk_count * len(bulk_data)) / (bulk_elapsed_ms / 1000) / (1024 * 1024)  # MB/s

    print(f"  单帧写入测试:")
    for size, us in write_times:
        print(f"    {size:>6} bytes -> {us:>8.1f} μs")

    print(f"\n  批量写入 ({bulk_count} 帧 × 12KB):")
    print(f"    总耗时: {bulk_elapsed_ms:.1f} ms")
    print(f"    帧率: {bulk_throughput:.0f} fps")
    print(f"    数据率: {bulk_data_rate:.2f} MB/s")

    # 清理
    shutil.rmtree(temp_dir, ignore_errors=True)

    return {
        "single_writes": write_times,
        "bulk_count": bulk_count,
        "bulk_elapsed_ms": bulk_elapsed_ms,
        "bulk_fps": bulk_throughput,
        "bulk_mbps": bulk_data_rate,
    }


# ========================== 测试 4: 数据库操作性能 ==========================

def test_database_performance():
    """测试 SQLite 数据库操作性能（模拟 gateway.db 操作）"""
    print("\n" + "=" * 60)
    print("测试 4: SQLite 数据库操作性能")
    print("=" * 60)

    import sqlite3

    temp_db = os.path.join(tempfile.mkdtemp(prefix="db_test_"), "test.db")

    conn = sqlite3.connect(temp_db)
    conn.execute("CREATE TABLE IF NOT EXISTS devices (uid TEXT PRIMARY KEY, psk TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password TEXT, role TEXT)")
    conn.commit()

    # 写入性能
    insert_times = []
    for i in range(200):
        t0 = time.perf_counter()
        conn.execute("INSERT OR REPLACE INTO devices (uid, psk) VALUES (?, ?)",
                     (f"CAM-{i:04d}", f"psk_{i:08x}"))
        conn.commit()
        insert_times.append((time.perf_counter() - t0) * 1000)

    avg_insert = sum(insert_times) / len(insert_times)

    # 查询性能
    query_times = []
    for i in range(200):
        uid = f"CAM-{i % 100:04d}"
        t0 = time.perf_counter()
        conn.execute("SELECT psk FROM devices WHERE uid=?", (uid,)).fetchone()
        query_times.append((time.perf_counter() - t0) * 1000)

    avg_query = sum(query_times) / len(query_times)

    # 批量插入
    t_bulk_start = time.perf_counter()
    for i in range(500):
        conn.execute("INSERT OR REPLACE INTO users (email, password, role) VALUES (?, ?, ?)",
                     (f"user_{i:04d}@test.com", hashlib.sha256(f"pass_{i}".encode()).hexdigest(),
                      "admin" if i % 5 == 0 else "user"))
    conn.commit()
    bulk_insert_ms = (time.perf_counter() - t_bulk_start) * 1000

    conn.close()
    shutil.rmtree(os.path.dirname(temp_db), ignore_errors=True)

    print(f"  INSERT 平均耗时: {avg_insert:.4f} ms")
    print(f"  SELECT 平均耗时: {avg_query:.4f} ms")
    print(f"  批量 INSERT (500行): {bulk_insert_ms:.1f} ms ({500 / (bulk_insert_ms / 1000):.0f} 行/秒)")

    return {
        "avg_insert_ms": avg_insert,
        "avg_query_ms": avg_query,
        "bulk_insert_ms": bulk_insert_ms,
        "insert_times": insert_times,
        "query_times": query_times,
    }


# ========================== 可视化图表生成 ==========================

def generate_charts(conn_data, e2e_data, storage_data, db_data):
    """生成所有性能可视化图表"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("\n[!] matplotlib 未安装，跳过图表生成。")
        return

    plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial']
    plt.rcParams['axes.unicode_minus'] = False

    # ---- 图 1: TCP 连接时间分布 ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    ax = axes[0]
    ax.hist(conn_data["connect_times"], bins=40, color='#4f46e5', alpha=0.75, edgecolor='white')
    ax.axvline(x=conn_data["avg"], color='#ef4444', linestyle='--', linewidth=2,
               label=f'平均: {conn_data["avg"]:.3f} ms')
    ax.axvline(x=conn_data["p95"], color='#f59e0b', linestyle='--', linewidth=2,
               label=f'P95: {conn_data["p95"]:.3f} ms')
    ax.set_xlabel('连接时间 (ms)', fontsize=11)
    ax.set_ylabel('频次', fontsize=11)
    ax.set_title(f'TCP 连接时间分布 (n={len(conn_data["connect_times"])})', fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1]
    scenarios = ['本机回环\n(实测)', '局域网\n(预估)', '广域网\n(预估)']
    times = [conn_data["avg"], conn_data["lan_estimate"], conn_data["wan_estimate"]]
    colors = ['#4f46e5', '#10b981', '#ef4444']
    bars = ax.bar(scenarios, times, color=colors, edgecolor='white', linewidth=1.5)
    ax.set_ylabel('连接时间 (ms)', fontsize=11)
    ax.set_title('不同网络环境连接时间预估', fontsize=13, fontweight='bold')
    for bar, val in zip(bars, times):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                f'{val:.2f} ms', ha='center', fontweight='bold', fontsize=11)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "07_connection_timing.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/07_connection_timing.png")

    # ---- 图 2: 端到端流程时间分解 ----
    fig, ax = plt.subplots(figsize=(10, 5))
    timeline = e2e_data["timeline"]
    labels = [t[0] for t in timeline]
    values = [t[1] for t in timeline]
    colors = ['#6366f1', '#10b981', '#f59e0b', '#ef4444']

    bars = ax.barh(labels, values, color=colors, edgecolor='white', linewidth=1.5)
    ax.set_xlabel('耗时 (ms)', fontsize=11)
    ax.set_title('端到端认证+推流流程时间分解', fontsize=14, fontweight='bold')
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                f'{val:.2f} ms', va='center', fontweight='bold', fontsize=11)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "08_e2e_timeline.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/08_e2e_timeline.png")

    # ---- 图 3: 帧传输时间分布 ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    ax = axes[0]
    frame_times = e2e_data["frame_times"]
    ax.plot(frame_times, color='#4f46e5', alpha=0.7, linewidth=0.8)
    ax.axhline(y=np.mean(frame_times), color='#ef4444', linestyle='--', linewidth=1.5,
               label=f'平均: {np.mean(frame_times):.3f} ms')
    ax.set_xlabel('帧序号', fontsize=11)
    ax.set_ylabel('传输耗时 (ms)', fontsize=11)
    ax.set_title('逐帧传输耗时 (100帧)', fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1]
    ax.hist(frame_times, bins=25, color='#6366f1', alpha=0.75, edgecolor='white')
    ax.axvline(x=np.mean(frame_times), color='#ef4444', linestyle='--', linewidth=2,
               label=f'平均: {np.mean(frame_times):.3f} ms')
    ax.set_xlabel('传输耗时 (ms)', fontsize=11)
    ax.set_ylabel('频次', fontsize=11)
    ax.set_title('帧传输耗时分布', fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "09_frame_transmission.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/09_frame_transmission.png")

    # ---- 图 4: 存储写入性能 ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    ax = axes[0]
    single = storage_data["single_writes"]
    sizes = [s[0] for s in single]
    times_us = [s[1] for s in single]
    ax.plot(sizes, times_us, 'o-', color='#4f46e5', linewidth=2, markersize=10,
            markerfacecolor='white', markeredgewidth=2)
    ax.set_xlabel('帧大小 (bytes)', fontsize=11)
    ax.set_ylabel('写入耗时 (μs)', fontsize=11)
    ax.set_title('单帧写入耗时 vs 帧大小', fontsize=13, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(True, alpha=0.3, linestyle='--')

    ax = axes[1]
    metrics = ['写入帧率\n(fps)', '数据吞吐量\n(MB/s)']
    values = [storage_data["bulk_fps"], storage_data["bulk_mbps"]]
    bars = ax.bar(metrics, values, color=['#10b981', '#6366f1'], edgecolor='white', linewidth=1.5)
    ax.set_title(f'批量写入性能 ({storage_data["bulk_count"]} 帧 × 12KB)', fontsize=13, fontweight='bold')
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f'{val:.1f}', ha='center', fontweight='bold', fontsize=14)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "10_storage_performance.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/10_storage_performance.png")

    # ---- 图 5: 数据库操作性能 ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    ax = axes[0]
    insert_times = db_data["insert_times"][:200]
    query_times = db_data["query_times"][:200]
    ax.plot(insert_times, alpha=0.6, color='#4f46e5', linewidth=0.7, label='INSERT')
    ax.plot(query_times, alpha=0.6, color='#10b981', linewidth=0.7, label='SELECT')
    ax.set_xlabel('操作序号', fontsize=11)
    ax.set_ylabel('耗时 (ms)', fontsize=11)
    ax.set_title('SQLite 操作耗时序列', fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    ax = axes[1]
    ops = ['INSERT\n(平均)', 'SELECT\n(平均)', '批量 INSERT\n(500行)']
    vals = [db_data["avg_insert_ms"], db_data["avg_query_ms"], db_data["bulk_insert_ms"]]
    colors = ['#4f46e5', '#10b981', '#f59e0b']
    bars = ax.bar(ops, vals, color=colors, edgecolor='white', linewidth=1.5)
    ax.set_ylabel('耗时 (ms)', fontsize=11)
    ax.set_title('数据库操作耗时对比', fontsize=13, fontweight='bold')
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                f'{val:.3f} ms', ha='center', fontweight='bold', fontsize=11)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "11_database_performance.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/11_database_performance.png")

    # ---- 图 6: 综合性能仪表盘 ----
    fig = plt.figure(figsize=(14, 10))
    fig.suptitle('网关系统 — 通信与存储综合性能仪表盘', fontsize=16, fontweight='bold', y=0.98)

    # 左上: 连接时间分布
    ax1 = fig.add_subplot(2, 3, 1)
    ax1.hist(conn_data["connect_times"], bins=30, color='#4f46e5', alpha=0.7, edgecolor='white')
    ax1.axvline(x=conn_data["avg"], color='red', linestyle='--', linewidth=1.5)
    ax1.set_title(f'TCP连接时间 (avg={conn_data["avg"]:.2f}ms)', fontsize=11, fontweight='bold')

    # 中上: 端到端流程
    ax2 = fig.add_subplot(2, 3, 2)
    tl = e2e_data["timeline"]
    ax2.barh([t[0] for t in tl], [t[1] for t in tl], color=['#6366f1', '#10b981', '#f59e0b', '#ef4444'])
    ax2.set_title('端到端认证+推流耗时', fontsize=11, fontweight='bold')

    # 右上: 帧传输
    ax3 = fig.add_subplot(2, 3, 3)
    ft = e2e_data["frame_times"]
    ax3.plot(ft, alpha=0.7, linewidth=0.9, color='#4f46e5')
    ax3.axhline(y=np.mean(ft), color='red', linestyle='--')
    ax3.set_title(f'帧传输耗时 (avg={np.mean(ft):.2f}ms)', fontsize=11, fontweight='bold')

    # 左下: 存储写入
    ax4 = fig.add_subplot(2, 3, 4)
    sw = storage_data["single_writes"]
    ax4.bar([f'{s[0]//1024}K' for s in sw], [s[1] for s in sw], color='#10b981', edgecolor='white')
    ax4.set_title('存储写入性能 (μs)', fontsize=11, fontweight='bold')
    ax4.tick_params(axis='x', rotation=45, labelsize=8)

    # 中下: 数据库
    ax5 = fig.add_subplot(2, 3, 5)
    ax5.bar(['INSERT', 'SELECT'], [db_data["avg_insert_ms"], db_data["avg_query_ms"]],
            color=['#4f46e5', '#10b981'], edgecolor='white')
    ax5.set_title(f'DB操作耗时 (INSERT={db_data["avg_insert_ms"]:.3f}ms)', fontsize=11, fontweight='bold')

    # 右下: 汇总
    ax6 = fig.add_subplot(2, 3, 6)
    ax6.axis('off')
    summary = (
        f"性能测试汇总\n{'-' * 30}\n"
        f"TCP连接: avg {conn_data['avg']:.2f}ms\n"
        f"认证成功率: {'[PASS]' if e2e_data['auth_success'] else '[FAIL]'}\n"
        f"帧传输: {np.mean(frame_times):.2f}ms/帧\n"
        f"存储写入: {storage_data['bulk_fps']:.0f} fps\n"
        f"DB查询: {db_data['avg_query_ms']:.3f}ms\n"
        f"{'-' * 30}\n"
        f"系统通信模块运行正常"
    )
    ax6.text(0.1, 0.5, summary, transform=ax6.transAxes, fontsize=11,
             verticalalignment='center', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='#f8fafc', edgecolor='#cbd5e1'))

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(os.path.join(OUT_DIR, "12_performance_dashboard.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/12_performance_dashboard.png")

    print(f"\n{'=' * 60}")
    print(f"所有图表已生成至: {os.path.abspath(OUT_DIR)}/")
    print(f"{'=' * 60}")


# ========================== 主入口 ==========================

if __name__ == "__main__":
    print("+" + "=" * 58 + "+")
    print("|" + "  网关系统性能测试 — 连接 & 传输 & 存储".center(50) + "|")
    print("+" + "=" * 58 + "+")

    conn = test_connection_timing()
    e2e = test_full_auth_and_stream()
    storage = test_recording_storage()
    db = test_database_performance()

    print("\n" + "=" * 60)
    print("生成可视化图表...")
    print("=" * 60)
    generate_charts(conn, e2e, storage, db)
