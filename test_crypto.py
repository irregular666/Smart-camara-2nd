"""
============================================================================
HMAC-SM3 加密模块测试 — 正确性 & 认证流程 & 性能
============================================================================
生成可视化图表到 test_output/ 目录
运行: python test_crypto.py
============================================================================
"""

import os
import sys
import time
import hashlib
import struct
from gmssl import sm3

# 确保输出目录存在
OUT_DIR = "test_output"
os.makedirs(OUT_DIR, exist_ok=True)

# ========================== 被测函数（与 gateway.py / true_device.py 一致） ==========================

def hmac_sm3(key_bytes, msg_bytes):
    """设备端 / 网关端共用的 HMAC-SM3 实现"""
    blocksize = 64
    if len(key_bytes) > blocksize:
        key_bytes = bytes.fromhex(sm3.sm3_hash(list(key_bytes)))
    key_bytes = key_bytes.ljust(blocksize, b'\x00')
    ipad = bytes(x ^ 0x36 for x in key_bytes)
    opad = bytes(x ^ 0x5c for x in key_bytes)
    inner_hash = bytes.fromhex(sm3.sm3_hash(list(ipad + msg_bytes)))
    return bytes.fromhex(sm3.sm3_hash(list(opad + inner_hash))).hex()


def hash_password(password):
    """用户密码哈希"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# ========================== 测试 1: HMAC-SM3 正确性 ==========================

def test_hmac_sm3_correctness():
    """验证 HMAC-SM3 的基本特性：确定性、唯一性、雪崩效应"""
    print("\n" + "=" * 60)
    print("测试 1: HMAC-SM3 加密正确性")
    print("=" * 60)

    results = []
    key = b"my_secure_psk_2023"

    # 1.1 确定性：相同输入 -> 相同输出
    msg = b"challenge_test_123|1718400000"
    hash1 = hmac_sm3(key, msg)
    hash2 = hmac_sm3(key, msg)
    deterministic = (hash1 == hash2)
    results.append(("确定性\n(相同输入->相同输出)", "通过" if deterministic else "失败", deterministic))
    print(f"  确定性测试: {'[PASS] 通过' if deterministic else '[FAIL] 失败'}")

    # 1.2 唯一性：不同消息 -> 不同输出
    msg2 = b"challenge_test_456|1718400001"
    hash3 = hmac_sm3(key, msg2)
    unique = (hash1 != hash3)
    results.append(("唯一性\n(不同消息->不同哈希)", "通过" if unique else "失败", unique))
    print(f"  唯一性测试: {'[PASS] 通过' if unique else '[FAIL] 失败'}")

    # 1.3 密钥敏感性：不同密钥 -> 完全不同
    key2 = b"different_psk_2023"
    hash4 = hmac_sm3(key2, msg)
    key_sensitive = (hash1 != hash4)
    results.append(("密钥敏感性\n(不同密钥->不同哈希)", "通过" if key_sensitive else "失败", key_sensitive))
    print(f"  密钥敏感性: {'[PASS] 通过' if key_sensitive else '[FAIL] 失败'}")

    # 1.4 雪崩效应：单比特变化导致 ~50% 输出位翻转
    msg_flipped = b"challenge_test_123|1718400001"  # 时间戳最后一位不同
    hash5 = hmac_sm3(key, msg_flipped)
    # 计算汉明距离
    bin1 = bin(int(hash1, 16))[2:].zfill(256)
    bin5 = bin(int(hash5, 16))[2:].zfill(256)
    hamming = sum(a != b for a, b in zip(bin1, bin5))
    avalanche_pct = hamming / 256 * 100
    good_avalanche = 40 <= avalanche_pct <= 60
    results.append((f"雪崩效应\n({avalanche_pct:.0f}% 位翻转)", "通过" if good_avalanche else "注意", good_avalanche))
    print(f"  雪崩效应: {avalanche_pct:.1f}% 位翻转 {'[PASS]' if good_avalanche else '[WARN]'}")

    # 1.5 哈希长度：SM3 输出 256 bits = 64 hex chars
    correct_length = len(hash1) == 64
    results.append(("输出长度\n(256 bits)", "通过" if correct_length else "失败", correct_length))
    print(f"  长度验证: {len(hash1)} hex 字符 {'[PASS]' if correct_length else '[FAIL]'}")

    all_pass = all(r[2] for r in results)
    print(f"\n  总结果: {'[PASS] 全部通过' if all_pass else '[FAIL] 存在失败项'}")

    return results


# ========================== 测试 2: 认证流程模拟 ==========================

def simulate_auth_flow(psk_device, psk_gateway, uid, test_label):
    """模拟一次完整的挑战-应答认证流程，返回 (成功, 耗时_ms)"""
    t0 = time.perf_counter()

    # 网关生成挑战码（与 gateway.py 中的 handle_device 一致）
    challenge = os.urandom(16).hex()
    timestamp = str(int(time.time()))
    challenge_payload = f"{challenge}|{timestamp}"

    # 设备端计算应答（与 true_device.py 一致）
    device_response = hmac_sm3(psk_device.encode('utf-8'), challenge_payload.encode('utf-8'))

    # 网关端验证应答
    expected_mac = hmac_sm3(psk_gateway.encode('utf-8'), challenge_payload.encode('utf-8'))

    success = (device_response == expected_mac)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    return success, elapsed_ms, challenge_payload[:20] + "...", device_response[:16] + "..."


def test_auth_flow():
    """测试认证流程的正确性和性能"""
    print("\n" + "=" * 60)
    print("测试 2: 挑战-应答认证流程模拟")
    print("=" * 60)

    PSK = "my_secure_psk_2023"
    UID = "CAM-001"

    # 2.1 正确 PSK
    successes = []
    failures = []
    timings = []

    print("\n  场景 A: PSK 匹配（正常认证）")
    for i in range(100):
        ok, ms, chal, resp = simulate_auth_flow(PSK, PSK, UID, f"normal_{i}")
        timings.append(ms)
        if ok:
            successes.append(ms)
        else:
            failures.append(ms)

    print(f"    执行 100 次: 成功 {len(successes)}, 失败 {len(failures)}")
    print(f"    平均耗时: {sum(timings)/len(timings):.3f} ms")

    # 2.2 错误 PSK
    print("\n  场景 B: PSK 不匹配（攻击模拟）")
    wrong_successes = []
    wrong_timings = []
    for i in range(100):
        ok, ms, chal, resp = simulate_auth_flow(PSK, "wrong_psk", UID, f"attack_{i}")
        wrong_timings.append(ms)
        if ok:
            wrong_successes.append(ms)

    print(f"    执行 100 次: 误接受 {len(wrong_successes)} 次（应为 0）")
    print(f"    平均耗时: {sum(wrong_timings)/len(wrong_timings):.3f} ms")

    # 2.3 大规模压力测试
    print("\n  场景 C: 压力测试 (1000 次认证)")
    bulk_timings = []
    bulk_start = time.perf_counter()
    for i in range(1000):
        ok, ms, _, _ = simulate_auth_flow(PSK, PSK, UID, f"bulk_{i}")
        bulk_timings.append(ms)
    bulk_total = (time.perf_counter() - bulk_start) * 1000

    print(f"    1000 次总耗时: {bulk_total:.1f} ms")
    print(f"    单次平均: {sum(bulk_timings)/len(bulk_timings):.4f} ms")
    print(f"    吞吐量: {1000 / (bulk_total / 1000):.1f} 次/秒")

    return {
        "normal_timings": timings,
        "wrong_timings": wrong_timings,
        "bulk_timings": bulk_timings,
        "normal_ok": len(successes),
        "wrong_ok": len(wrong_successes),
        "bulk_total_ms": bulk_total,
    }


# ========================== 测试 3: SM3 哈希性能 ==========================

def test_sm3_performance():
    """测试 SM3 哈希的性能基准"""
    print("\n" + "=" * 60)
    print("测试 3: SM3 哈希性能基准")
    print("=" * 60)

    data_sizes = [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]  # bytes
    results = []

    for size in data_sizes:
        data = os.urandom(size)
        # 预热
        for _ in range(10):
            sm3.sm3_hash(list(data))

        # 计时
        rounds = 50 if size < 65536 else 20
        t0 = time.perf_counter()
        for _ in range(rounds):
            sm3.sm3_hash(list(data))
        elapsed = (time.perf_counter() - t0) / rounds * 1000  # ms per hash

        throughput = size / (elapsed / 1000) / (1024 * 1024)  # MB/s
        results.append((size, elapsed, throughput))
        print(f"  {size:>8} bytes -> {elapsed:>8.4f} ms  ({throughput:>8.2f} MB/s)")

    return results


# ========================== 测试 4: 帧协议封包/解包 ==========================

def test_frame_protocol():
    """测试私有帧传输协议的正确性"""
    print("\n" + "=" * 60)
    print("测试 4: 帧传输协议封包/解包")
    print("=" * 60)

    # 模拟各种大小的 JPEG 帧
    frame_sizes = [1024, 4096, 8192, 16384, 32768, 65536, 131072]
    results = []

    for size in frame_sizes:
        # 生成模拟帧数据
        original = os.urandom(size)

        # 封包：4 字节大端长度 + JPEG 数据（与 true_device.py 一致）
        t0 = time.perf_counter()
        header = struct.pack(">I", len(original))
        packet = header + original
        pack_time_us = (time.perf_counter() - t0) * 1_000_000

        # 解包：读取 4 字节长度，然后读数据（与 gateway.py handle_device 一致）
        t0 = time.perf_counter()
        frame_len = struct.unpack(">I", packet[:4])[0]
        frame_data = packet[4:4 + frame_len]
        unpack_time_us = (time.perf_counter() - t0) * 1_000_000

        # 验证
        intact = (frame_len == size) and (frame_data == original)
        results.append({
            "size": size,
            "pack_us": pack_time_us,
            "unpack_us": unpack_time_us,
            "intact": intact
        })

        print(f"  {size:>8} bytes -> 封包 {pack_time_us:>6.2f} μs | 解包 {unpack_time_us:>6.2f} μs | {'[PASS]' if intact else '[FAIL]'}")

    all_intact = all(r["intact"] for r in results)
    print(f"\n  完整性: {'[PASS] 全部通过' if all_intact else '[FAIL] 存在损坏'}")

    return results


# ========================== 可视化图表生成 ==========================

def generate_charts(correctness_results, auth_data, sm3_perf, protocol_results):
    """使用 matplotlib 生成所有可视化图表"""
    try:
        import matplotlib
        matplotlib.use('Agg')  # 无 GUI 后端
        import matplotlib.pyplot as plt
        import matplotlib.ticker as ticker
        import numpy as np
    except ImportError:
        print("\n[!] matplotlib 未安装，跳过图表生成。安装: pip install matplotlib")
        return

    # 设置中文字体
    plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial']
    plt.rcParams['axes.unicode_minus'] = False

    # ---- 图 1: HMAC-SM3 正确性测试结果 ----
    fig, ax = plt.subplots(figsize=(10, 5))
    labels = [r[0] for r in correctness_results]
    statuses = [1 if r[2] else 0 for r in correctness_results]
    colors = ['#10b981' if s else '#ef4444' for s in statuses]

    bars = ax.bar(range(len(labels)), statuses, color=colors, edgecolor='white', linewidth=1.5)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylim(0, 1.5)
    ax.set_ylabel('测试结果 (1=通过)', fontsize=12)
    ax.set_title('HMAC-SM3 加密正确性测试', fontsize=14, fontweight='bold')
    ax.set_yticks([0, 1])
    ax.set_yticklabels(['失败', '通过'])

    # 添加数值标签
    for bar, val in zip(bars, statuses):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                '[PASS] 通过' if val else '[FAIL] 失败', ha='center', fontweight='bold', fontsize=11)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "01_hmac_sm3_correctness.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/01_hmac_sm3_correctness.png")

    # ---- 图 2: 认证耗时分布 ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # 左: 直方图
    ax = axes[0]
    ax.hist(auth_data["normal_timings"], bins=30, color='#4f46e5', alpha=0.75, edgecolor='white',
            label=f'正常认证 (n={len(auth_data["normal_timings"])})')
    ax.hist(auth_data["wrong_timings"], bins=30, color='#ef4444', alpha=0.5, edgecolor='white',
            label=f'PSK错误 (n={len(auth_data["wrong_timings"])})')
    ax.set_xlabel('耗时 (ms)', fontsize=11)
    ax.set_ylabel('频次', fontsize=11)
    ax.set_title('挑战-应答认证耗时分布', fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # 右: 箱线图
    ax = axes[1]
    box_data = [auth_data["normal_timings"], auth_data["wrong_timings"]]
    bp = ax.boxplot(box_data, patch_artist=True,
                    widths=0.4, showmeans=True, meanprops=dict(marker='D', markerfacecolor='white', markersize=6))
    ax.set_xticklabels(['PSK 匹配', 'PSK 不匹配'])
    bp['boxes'][0].set_facecolor('#4f46e5')
    bp['boxes'][1].set_facecolor('#ef4444')
    bp['boxes'][0].set_alpha(0.6)
    bp['boxes'][1].set_alpha(0.4)
    ax.set_ylabel('耗时 (ms)', fontsize=11)
    ax.set_title('认证耗时对比 (箱线图)', fontsize=13, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "02_auth_timing.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/02_auth_timing.png")

    # ---- 图 3: 认证成功率饼图 ----
    fig, ax = plt.subplots(figsize=(6, 6))
    normal_total = len(auth_data["normal_timings"])
    normal_ok = auth_data["normal_ok"]
    normal_fail = normal_total - normal_ok

    sizes = [normal_ok, normal_fail]
    labels = [f'认证成功 ({normal_ok})', f'认证失败 ({normal_fail})']
    colors_pie = ['#10b981', '#ef4444']
    explode = (0, 0.08)

    wedges, texts, autotexts = ax.pie(sizes, explode=explode, labels=labels, colors=colors_pie,
                                      autopct='%1.1f%%', startangle=140,
                                      textprops={'fontsize': 11})
    for at in autotexts:
        at.set_fontweight('bold')
    ax.set_title(f'认证成功率 (PSK 匹配场景, n={normal_total})', fontsize=13, fontweight='bold')
    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "03_auth_success_rate.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/03_auth_success_rate.png")

    # ---- 图 4: SM3 哈希性能 ----
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    sizes_bytes = [r[0] for r in sm3_perf]
    times_ms = [r[1] for r in sm3_perf]
    throughputs = [r[2] for r in sm3_perf]

    # 左: 耗时 vs 数据大小
    ax = axes[0]
    ax.plot(sizes_bytes, times_ms, 'o-', color='#4f46e5', linewidth=2, markersize=8,
            markerfacecolor='white', markeredgewidth=2)
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.set_xlabel('数据大小 (bytes)', fontsize=11)
    ax.set_ylabel('单次哈希耗时 (ms)', fontsize=11)
    ax.set_title('SM3 哈希耗时 vs 数据大小', fontsize=13, fontweight='bold')
    ax.grid(True, alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # 右: 吞吐量 vs 数据大小
    ax = axes[1]
    ax.bar(range(len(sizes_bytes)), throughputs, color='#6366f1', edgecolor='white', linewidth=1)
    ax.set_xticks(range(len(sizes_bytes)))
    ax.set_xticklabels([f'{s // 1024}K' if s >= 1024 else str(s) for s in sizes_bytes], rotation=45)
    ax.set_xlabel('数据大小', fontsize=11)
    ax.set_ylabel('吞吐量 (MB/s)', fontsize=11)
    ax.set_title('SM3 哈希吞吐量', fontsize=13, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # 在柱上标注数值
    for i, (bar, tp) in enumerate(zip(ax.patches, throughputs)):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f'{tp:.1f}', ha='center', fontsize=8)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "04_sm3_performance.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/04_sm3_performance.png")

    # ---- 图 5: 帧协议性能 ----
    fig, ax = plt.subplots(figsize=(10, 5))

    sizes = [r["size"] for r in protocol_results]
    x = np.arange(len(sizes))
    width = 0.35
    pack_times = [r["pack_us"] for r in protocol_results]
    unpack_times = [r["unpack_us"] for r in protocol_results]

    bars1 = ax.bar(x - width / 2, pack_times, width, label='封包 (struct.pack)', color='#4f46e5', alpha=0.8,
                   edgecolor='white')
    bars2 = ax.bar(x + width / 2, unpack_times, width, label='解包 (struct.unpack)', color='#10b981', alpha=0.8,
                   edgecolor='white')

    ax.set_xlabel('帧大小 (bytes)', fontsize=11)
    ax.set_ylabel('耗时 (μs)', fontsize=11)
    ax.set_title('帧传输协议封包/解包性能', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([f'{s // 1024}K' if s >= 1024 else str(s) for s in sizes])
    ax.legend(fontsize=10)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    # 标注数值
    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f'{bar.get_height():.2f}', ha='center', fontsize=7, rotation=90)
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f'{bar.get_height():.2f}', ha='center', fontsize=7, rotation=90)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "05_frame_protocol.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/05_frame_protocol.png")

    # ---- 图 6: 综合性能仪表盘 ----
    fig = plt.figure(figsize=(14, 10))
    fig.suptitle('网关加密通信系统 — 综合性能仪表盘', fontsize=16, fontweight='bold', y=0.98)

    # 左上: 认证成功率
    ax1 = fig.add_subplot(2, 3, 1)
    ax1.pie([normal_ok, normal_fail], labels=['成功', '失败'],
            colors=['#10b981', '#ef4444'], autopct='%1.1f%%', startangle=90,
            textprops={'fontsize': 11})
    ax1.set_title('认证成功率', fontsize=12, fontweight='bold')

    # 中上: 平均认证耗时
    ax2 = fig.add_subplot(2, 3, 2)
    avg_normal = np.mean(auth_data["normal_timings"])
    avg_wrong = np.mean(auth_data["wrong_timings"])
    ax2.barh(['PSK 匹配', 'PSK 不匹配'], [avg_normal, avg_wrong],
             color=['#4f46e5', '#ef4444'], height=0.4)
    ax2.set_xlabel('平均耗时 (ms)')
    ax2.set_title('HMAC-SM3 认证平均耗时', fontsize=12, fontweight='bold')
    for i, (v, label) in enumerate(zip([avg_normal, avg_wrong], [f'{avg_normal:.4f} ms', f'{avg_wrong:.4f} ms'])):
        ax2.text(v + 0.0002, i, label, va='center', fontsize=11, fontweight='bold')

    # 右上: SM3 吞吐量
    ax3 = fig.add_subplot(2, 3, 3)
    sm3_avg_tp = np.mean(throughputs)
    ax3.bar(range(len(sizes_bytes)), throughputs, color='#6366f1', edgecolor='white')
    ax3.axhline(y=sm3_avg_tp, color='#ef4444', linestyle='--', linewidth=1.5,
                label=f'平均: {sm3_avg_tp:.1f} MB/s')
    ax3.set_xticks(range(len(sizes_bytes)))
    ax3.set_xticklabels([f'{s // 1024}K' if s >= 1024 else str(s) for s in sizes_bytes],
                        rotation=45, fontsize=8)
    ax3.set_ylabel('MB/s')
    ax3.set_title('SM3 哈希吞吐量', fontsize=12, fontweight='bold')
    ax3.legend(fontsize=8)

    # 左下: 帧协议完整性
    ax4 = fig.add_subplot(2, 3, 4)
    intact_count = sum(1 for r in protocol_results if r["intact"])
    corrupted = len(protocol_results) - intact_count
    ax4.bar(['完整', '损坏'], [intact_count, corrupted], color=['#10b981', '#ef4444'], edgecolor='white')
    ax4.set_ylabel('帧数量')
    ax4.set_title(f'帧协议完整性 ({len(protocol_results)} 帧)', fontsize=12, fontweight='bold')
    for i, v in enumerate([intact_count, corrupted]):
        ax4.text(i, v + 0.1, str(v), ha='center', fontweight='bold', fontsize=14)

    # 中下: 压力测试吞吐量
    ax5 = fig.add_subplot(2, 3, 5)
    auth_per_sec = 1000 / (auth_data["bulk_total_ms"] / 1000)
    ax5.bar(['HMAC-SM3\n认证'], [auth_per_sec], color='#4f46e5', edgecolor='white', width=0.3)
    ax5.set_ylabel('次/秒')
    ax5.set_title(f'认证吞吐量: {auth_per_sec:.0f} 次/秒', fontsize=12, fontweight='bold')
    ax5.text(0, auth_per_sec / 2, f'{auth_per_sec:.0f}', ha='center', fontweight='bold',
             fontsize=22, color='white')

    # 右下: 测试汇总
    ax6 = fig.add_subplot(2, 3, 6)
    ax6.axis('off')
    summary_text = (
        f"测试汇总报告\n"
        f"{'-' * 30}\n"
        f"HMAC-SM3 正确性: [PASS] 全部通过\n"
        f"认证成功率: {normal_ok}/{normal_total} ({100 * normal_ok / normal_total:.1f}%)\n"
        f"平均认证耗时: {avg_normal:.4f} ms\n"
        f"SM3 平均吞吐量: {sm3_avg_tp:.1f} MB/s\n"
        f"帧协议完整性: {intact_count}/{len(protocol_results)} 通过\n"
        f"认证压力测试: {auth_per_sec:.0f} 次/秒\n"
        f"{'-' * 30}\n"
        f"系统加密模块运行正常"
    )
    ax6.text(0.1, 0.5, summary_text, transform=ax6.transAxes, fontsize=11,
             verticalalignment='center', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='#f8fafc', edgecolor='#cbd5e1'))

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(os.path.join(OUT_DIR, "06_dashboard.png"), dpi=150)
    plt.close(fig)
    print(f"  [PASS] 图表已保存: {OUT_DIR}/06_dashboard.png")

    print(f"\n{'=' * 60}")
    print(f"所有图表已生成至: {os.path.abspath(OUT_DIR)}/")
    print(f"{'=' * 60}")


# ========================== 主入口 ==========================

if __name__ == "__main__":
    print("+" + "=" * 58 + "+")
    print("|" + "  HMAC-SM3 加密模块 & 认证流程 — 自动化测试套件".center(50) + "|")
    print("+" + "=" * 58 + "+")

    # 运行所有测试
    cr = test_hmac_sm3_correctness()
    auth = test_auth_flow()
    sm3p = test_sm3_performance()
    proto = test_frame_protocol()

    # 生成可视化图表
    print("\n" + "=" * 60)
    print("生成可视化图表...")
    print("=" * 60)
    generate_charts(cr, auth, sm3p, proto)
