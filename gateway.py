# import socket
# import threading
# import time
# import os
# import random
# import hashlib
# import smtplib
# import struct
# from email.mime.text import MIMEText
# from email.header import Header
# from flask import Flask, request, jsonify, Response
# from flask_cors import CORS
# from gmssl import sm3
#
# # ========================== 配置区 ==========================
# SENDER_EMAIL = "3884765272@qq.com"  # 发件QQ邮箱
# SENDER_AUTH_CODE = "letkdslihciwcegg"  # 发件QQ邮箱SMTP授权码
# ADMIN_SECRET_CODE = "admin888"  # 注册成为管理员的专属邀请码
# # -----------------------------------------------------------
#
# app = Flask(__name__)
# CORS(app)
#
# # -----SQLITE内存管理------------------------------------------
# # 用户: {"email": {"pwd": "hash", "role": "admin"|"user"}}
# users_db = {}
# # TOTP: {"email": {"code": "123", "exp": 12345}}
# totp_store = {}
# # 设备: {"uid": {"psk": "...", "status": "offline", "last_frame": b""}}
# devices_db = {}
# # -----------------------------------------------------------
#
# # --辅助函数 --------------------------
# def hash_password(password):
#     return hashlib.sha256(password.encode('utf-8')).hexdigest()
#
#
# def hmac_sm3(key_bytes, msg_bytes):
#     blocksize = 64
#     if len(key_bytes) > blocksize:
#         key_bytes = bytes.fromhex(sm3.sm3_hash(list(key_bytes)))
#     key_bytes = key_bytes.ljust(blocksize, b'\x00')
#     ipad = bytes(x ^ 0x36 for x in key_bytes)
#     opad = bytes(x ^ 0x5c for x in key_bytes)
#     inner_hash = bytes.fromhex(sm3.sm3_hash(list(ipad + msg_bytes)))
#     return bytes.fromhex(sm3.sm3_hash(list(opad + inner_hash))).hex()
#
#
# def send_totp_email(receiver_email, code):
#     try:
#         # 邮件内容
#         msg = MIMEText(f'您的网关登录动态验证码为：{code}。1分钟内有效。', 'plain', 'utf-8')
#
#         msg['From'] = SENDER_EMAIL  # 直接用你的邮箱，不要加昵称
#         msg['To'] = receiver_email
#         msg['Subject'] = '网关登录 TOTP 验证码'
#
#         # 发送
#         server = smtplib.SMTP_SSL("smtp.qq.com", 465)
#         server.login(SENDER_EMAIL, SENDER_AUTH_CODE)
#         server.sendmail(SENDER_EMAIL, [receiver_email], msg.as_string())
#         server.quit()
#         print(f"✅ 验证码邮件已发送至 {receiver_email}")
#     except Exception as e:
#         print(f"[错误] 邮件发送失败: {e}")
#
#
# # 用户 HTTP 接口 --------------------------
# # @app.route('/api/user/register', methods=['POST'])
# def user_register():
#     data = request.get_json()
#     email, password, invite_code = data.get('email'), data.get('password'), data.get('invite_code')
#     if not email or not password: return jsonify({"ok": False, "msg": "参数缺失"})
#     if email in users_db: return jsonify({"ok": False, "msg": "该邮箱已注册"})
#
#     role = "admin" if invite_code == ADMIN_SECRET_CODE else "user"
#     users_db[email] = {"pwd": hash_password(password), "role": role}
#     return jsonify({"ok": True, "msg": f"注册成功！您的身份是: {'管理员' if role == 'admin' else '普通用户'}"})
#
#
# @app.route('/api/user/login', methods=['POST'])
# def user_login():
#     data = request.get_json()
#     email, password = data.get('email'), data.get('password')
#     user = users_db.get(email)
#
#     if not user or user["pwd"] != hash_password(password):
#         return jsonify({"ok": False, "msg": "邮箱或密码错误"})
#
#     code = str(random.randint(100000, 999999))
#     totp_store[email] = {"code": code, "exp": time.time() + 60}
#     threading.Thread(target=send_totp_email, args=(email, code)).start()
#     return jsonify({"ok": True, "msg": "密码正确，验证码已发送至邮箱"})
#
#
# @app.route('/api/user/verify', methods=['POST'])
# def user_verify():
#     data = request.get_json()
#     email, code = data.get('email'), data.get('code')
#     totp_data = totp_store.get(email)
#
#     if not totp_data: return jsonify({"ok": False, "msg": "请先登录"})
#     if time.time() > totp_data["exp"]:
#         del totp_store[email]
#         return jsonify({"ok": False, "msg": "验证码已过期"})
#     if totp_data["code"] != code: return jsonify({"ok": False, "msg": "验证码错误"})
#
#     del totp_store[email]
#     return jsonify({"ok": True, "msg": "网关互认证成功！", "role": users_db[email]["role"], "email": email})
#
#
# # 网关管理与视频 HTTP 接口 --------------------------
# @app.route('/api/device/register', methods=['POST'])
# def register_device():
#     # 实际项目中这里应校验管理员 Token
#     data = request.get_json()
#     uid, psk = data.get('uid'), data.get('psk')
#     devices_db[uid] = {"psk": psk, "status": "offline", "last_frame": None}
#     return jsonify({"ok": True, "msg": "设备授权成功"})
#
#
# @app.route('/api/devices', methods=['GET'])
# def get_devices():
#     result = [{"uid": k, "status": v["status"]} for k, v in devices_db.items()]
#     return jsonify({"ok": True, "data": result})
#
#
# @app.route('/api/video/<uid>')
# def video_feed(uid):
#     """MJPEG 视频流端点"""
#
#     def generate():
#         while True:
#             dev = devices_db.get(uid)
#             if dev and dev["status"] == "online" and dev["last_frame"]:
#                 frame = dev["last_frame"]
#                 yield (b'--frame\r\n'
#                        b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
#             time.sleep(0.05)  # 约 20 fps
#
#     return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')
#
#
# # 设备 TCP Socket 服务 --------------------------
# def handle_device(conn, addr):
#     try:
#         conn.settimeout(10)
#         # 1.接收 UID
#         uid = conn.recv(1024).decode('utf-8').strip()
#         if uid not in devices_db:
#             conn.send(b"ERROR: UNREGISTERED")
#             return
#
#         # 2.发送挑战
#         psk = devices_db[uid]["psk"]
#         challenge = os.urandom(16).hex()
#         timestamp = str(int(time.time()))
#         challenge_payload = f"{challenge}|{timestamp}"
#         conn.send(challenge_payload.encode('utf-8'))
#
#         # 3.验证应答
#         device_response = conn.recv(1024).decode('utf-8').strip()
#         expected_mac = hmac_sm3(psk.encode('utf-8'), challenge_payload.encode('utf-8'))
#
#         if device_response == expected_mac:
#             conn.send(b"AUTH_SUCCESS")
#             devices_db[uid]["status"] = "online"
#             print(f"✅ 摄像头 {uid} 认证成功，准备接收视频流...")
#
#             # 4. 进入接收视频帧循环
#             conn.settimeout(None)  # 关闭超时，保持长连接
#             while True:
#                 # 接收帧长度 (4字节)
#                 length_bytes = conn.recv(4)
#                 if not length_bytes: break
#                 frame_len = struct.unpack(">I", length_bytes)[0]
#
#                 # 接收完整帧
#                 frame_data = b""
#                 while len(frame_data) < frame_len:
#                     packet = conn.recv(min(4096, frame_len - len(frame_data)))
#                     if not packet: break
#                     frame_data += packet
#
#                 # 更新最新帧供前端读取
#                 devices_db[uid]["last_frame"] = frame_data
#         else:
#             conn.send(b"AUTH_FAILED")
#     except Exception as e:
#         print(f"[断开] 摄像头连接异常: {e}")
#     finally:
#         if uid in devices_db: devices_db[uid]["status"] = "offline"
#         conn.close()
#
#
# def start_socket_server():
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind(('0.0.0.0', 8080))
#     server.listen(5)
#     while True:
#         conn, addr = server.accept()
#         threading.Thread(target=handle_device, args=(conn, addr), daemon=True).start()
#
#
# if __name__ == "__main__":
#     threading.Thread(target=start_socket_server, daemon=True).start()
#     app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

import socket
import threading
import time
import os
import random
import hashlib
import smtplib
import struct
import sqlite3
import shutil
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.header import Header
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from gmssl import sm3

# ========================== 配置区 ==========================
SENDER_EMAIL = "3884765272@qq.com"
SENDER_AUTH_CODE = "letkdslihciwcegg"
ADMIN_SECRET_CODE = "admin888"  # 注册成为管理员的专属邀请码
DB_FILE = "gateway.db"  # SQLite 数据库文件
RECORDINGS_DIR = "recordings"  # 录像存储根目录
RECORDING_RETENTION_DAYS = 180  # 录像保留天数（半年）
# ============================================================

app = Flask(__name__)
CORS(app)

# 内存状态（不持久化）
totp_store = {}  # {"email": {"code": "123", "exp": 12345}}
devices_status = {}  # {"uid": {"status": "online", "last_frame": b""}}
recording_enabled = {}  # {"uid": True/False} — 录像开关，默认新设备自动开启
recording_locks = {}  # {"uid": threading.Lock()} — 每个设备一个写锁


# -------------------------- 数据库初始化 --------------------------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users 
                      (email TEXT PRIMARY KEY, password TEXT, role TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS devices 
                      (uid TEXT PRIMARY KEY, psk TEXT)''')
        db.commit()
    print("SQLite 数据库初始化完成")


# -------------------------- 辅助函数 --------------------------
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def hmac_sm3(key_bytes, msg_bytes):
    blocksize = 64
    if len(key_bytes) > blocksize:
        key_bytes = bytes.fromhex(sm3.sm3_hash(list(key_bytes)))
    key_bytes = key_bytes.ljust(blocksize, b'\x00')
    ipad = bytes(x ^ 0x36 for x in key_bytes)
    opad = bytes(x ^ 0x5c for x in key_bytes)
    inner_hash = bytes.fromhex(sm3.sm3_hash(list(ipad + msg_bytes)))
    return bytes.fromhex(sm3.sm3_hash(list(opad + inner_hash))).hex()


def send_totp_email(receiver_email, code):
    try:
        msg = MIMEText(f'您的网关登录动态验证码为：{code}。1分钟内有效，请勿泄露给他人。', 'plain', 'utf-8')

        # ─── 核心修复位置 ───
        # 只对中文发件人昵称进行 RFC2047 编码，外部的 <邮箱> 保持原样字符串
        from email.header import Header
        display_name = Header('网关安全中心', 'utf-8').encode()
        msg['From'] = f"{display_name} <{SENDER_EMAIL}>"
        # ────────────────────

        msg['To'] = receiver_email
        msg['Subject'] = Header('网关登录 TOTP 验证码', 'utf-8')

        server = smtplib.SMTP_SSL("smtp.qq.com", 465)
        server.login(SENDER_EMAIL, SENDER_AUTH_CODE)
        server.sendmail(SENDER_EMAIL, [receiver_email], msg.as_string())
        server.quit()
        print(f"TOTP 邮件已成功发送至 {receiver_email}")
    except Exception as e:
        print(f"邮件发送失败: {e}")


# -------------------------- 录像存储辅助函数 --------------------------
def ensure_dir(path):
    """确保目录存在"""
    os.makedirs(path, exist_ok=True)


def save_frame(uid, frame_data):
    """将帧写入磁盘录像"""
    if not recording_enabled.get(uid, True):
        return  # 录像已关闭

    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    hour_str = now.strftime("%H")
    # 使用微秒时间戳避免同一秒内的文件名冲突
    filename = f"{int(now.timestamp() * 1_000_000)}.jpg"

    frame_dir = os.path.join(RECORDINGS_DIR, uid, date_str, hour_str)
    ensure_dir(frame_dir)

    # 使用设备专属锁避免并发写入冲突
    lock = recording_locks.setdefault(uid, threading.Lock())
    with lock:
        filepath = os.path.join(frame_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(frame_data)


def get_recording_dates(uid):
    """获取某设备所有有录像的日期列表（倒序）"""
    device_dir = os.path.join(RECORDINGS_DIR, uid)
    if not os.path.isdir(device_dir):
        return []
    dates = sorted(
        [d for d in os.listdir(device_dir) if os.path.isdir(os.path.join(device_dir, d))],
        reverse=True
    )
    return dates


def get_recording_hours(uid, date_str):
    """获取某设备某天所有有录像的小时列表"""
    date_dir = os.path.join(RECORDINGS_DIR, uid, date_str)
    if not os.path.isdir(date_dir):
        return []
    hours = sorted(
        [h for h in os.listdir(date_dir) if os.path.isdir(os.path.join(date_dir, h))],
        reverse=True
    )
    return hours


def get_storage_stats():
    """获取所有设备的存储统计"""
    stats = {"total_size_bytes": 0, "devices": {}}
    root = RECORDINGS_DIR
    if not os.path.isdir(root):
        return stats

    for uid in os.listdir(root):
        uid_path = os.path.join(root, uid)
        if not os.path.isdir(uid_path):
            continue
        device_size = 0
        file_count = 0
        oldest_date = None
        newest_date = None
        for date_str in os.listdir(uid_path):
            date_path = os.path.join(uid_path, date_str)
            if not os.path.isdir(date_path):
                continue
            if oldest_date is None or date_str < oldest_date:
                oldest_date = date_str
            if newest_date is None or date_str > newest_date:
                newest_date = date_str
            for hour_str in os.listdir(date_path):
                hour_path = os.path.join(date_path, hour_str)
                if not os.path.isdir(hour_path):
                    continue
                for fname in os.listdir(hour_path):
                    fpath = os.path.join(hour_path, fname)
                    if os.path.isfile(fpath):
                        try:
                            device_size += os.path.getsize(fpath)
                            file_count += 1
                        except OSError:
                            pass

        stats["devices"][uid] = {
            "size_bytes": device_size,
            "size_mb": round(device_size / (1024 * 1024), 2),
            "frame_count": file_count,
            "oldest_date": oldest_date,
            "newest_date": newest_date,
            "recording": recording_enabled.get(uid, True)
        }
        stats["total_size_bytes"] += device_size

    stats["total_size_mb"] = round(stats["total_size_bytes"] / (1024 * 1024), 2)
    return stats


def cleanup_old_recordings():
    """删除超过保留期的录像"""
    cutoff_date = datetime.now() - timedelta(days=RECORDING_RETENTION_DAYS)
    cutoff_str = cutoff_date.strftime("%Y-%m-%d")
    print(f"[清理] 开始清理 {cutoff_str} 之前的录像...")

    root = RECORDINGS_DIR
    if not os.path.isdir(root):
        return

    deleted_count = 0
    for uid in os.listdir(root):
        uid_path = os.path.join(root, uid)
        if not os.path.isdir(uid_path):
            continue
        for date_str in os.listdir(uid_path):
            if date_str < cutoff_str:
                date_path = os.path.join(uid_path, date_str)
                if os.path.isdir(date_path):
                    try:
                        shutil.rmtree(date_path)
                        deleted_count += 1
                        print(f"[清理] 已删除: {uid}/{date_str}")
                    except Exception as e:
                        print(f"[清理] 删除失败 {uid}/{date_str}: {e}")

        # 删除空设备目录
        try:
            remaining = [d for d in os.listdir(uid_path) if os.path.isdir(os.path.join(uid_path, d))]
            if not remaining:
                shutil.rmtree(uid_path)
        except Exception:
            pass

    # 删除空的录像根目录
    try:
        if os.path.isdir(root) and not os.listdir(root):
            os.rmdir(root)
    except Exception:
        pass

    if deleted_count > 0:
        print(f"[清理] 清理完成，共删除 {deleted_count} 个过期日期目录")
    else:
        print(f"[清理] 没有需要清理的过期录像")


def schedule_cleanup():
    """定期执行清理任务（每6小时）"""
    cleanup_old_recordings()
    # 6小时后再次执行
    threading.Timer(6 * 3600, schedule_cleanup).start()


# -------------------------- 用户 HTTP 接口 --------------------------
@app.route('/api/user/register', methods=['POST'])
def user_register():
    data = request.get_json()
    email, password, invite_code = data.get('email'), data.get('password'), data.get('invite_code')
    if not email or not password: return jsonify({"ok": False, "msg": "参数缺失"})

    role = "admin" if invite_code == ADMIN_SECRET_CODE else "user"
    pwd_hash = hash_password(password)

    try:
        with get_db() as db:
            db.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                       (email, pwd_hash, role))
            db.commit()
        return jsonify({"ok": True, "msg": f"注册成功！身份: {'管理员' if role == 'admin' else '普通用户'}"})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "msg": "该邮箱已注册"})


@app.route('/api/user/login', methods=['POST'])
def user_login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if not user or user["password"] != hash_password(password):
        return jsonify({"ok": False, "msg": "邮箱或密码错误"})

    code = str(random.randint(100000, 999999))
    totp_store[email] = {"code": code, "exp": time.time() + 60, "role": user["role"]}
    threading.Thread(target=send_totp_email, args=(email, code)).start()
    return jsonify({"ok": True, "msg": "密码正确，验证码已发送至邮箱"})


@app.route('/api/user/verify', methods=['POST'])
def user_verify():
    data = request.get_json()
    email, code = data.get('email'), data.get('code')
    totp_data = totp_store.get(email)

    if not totp_data: return jsonify({"ok": False, "msg": "请先登录"})
    if time.time() > totp_data["exp"]:
        del totp_store[email]
        return jsonify({"ok": False, "msg": "验证码已过期"})
    if totp_data["code"] != code: return jsonify({"ok": False, "msg": "验证码错误"})

    role = totp_data["role"]
    del totp_store[email]
    return jsonify({"ok": True, "msg": "网关互认证成功！", "role": role, "email": email})


# -------------------------- 网关管理与视频 HTTP 接口 --------------------------
@app.route('/api/device/register', methods=['POST'])
def register_device():
    data = request.get_json()
    uid, psk = data.get('uid'), data.get('psk')
    try:
        with get_db() as db:
            db.execute("INSERT OR REPLACE INTO devices (uid, psk) VALUES (?, ?)", (uid, psk))
            db.commit()
        return jsonify({"ok": True, "msg": "设备授权成功，已持久化写入"})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})


@app.route('/api/devices', methods=['GET'])
def get_devices():
    with get_db() as db:
        devices = db.execute("SELECT uid FROM devices").fetchall()

    result = []
    for d in devices:
        uid = d["uid"]
        status = devices_status.get(uid, {}).get("status", "offline")
        result.append({"uid": uid, "status": status})
    return jsonify({"ok": True, "data": result})


@app.route('/api/video/<uid>')
def video_feed(uid):
    def generate():
        while True:
            dev = devices_status.get(uid)
            if dev and dev["status"] == "online" and dev["last_frame"]:
                frame = dev["last_frame"]
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            time.sleep(0.05)

    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/api/snapshot/<uid>')
def snapshot(uid):
    """获取某设备的最新帧快照（单张 JPEG 下载）"""
    dev = devices_status.get(uid)
    if not dev or not dev.get("last_frame"):
        return jsonify({"ok": False, "msg": "设备无可用画面"}), 404

    from flask import make_response
    response = make_response(dev["last_frame"])
    response.headers["Content-Type"] = "image/jpeg"
    response.headers["Content-Disposition"] = \
        f'attachment; filename="snapshot_{uid}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.jpg"'
    return response


# -------------------------- 录像管理与回放 HTTP 接口 --------------------------
@app.route('/api/recordings/<uid>')
def list_recording_dates(uid):
    """列出某设备所有有录像的日期"""
    dates = get_recording_dates(uid)
    return jsonify({"ok": True, "data": dates})


@app.route('/api/recordings/<uid>/<date>')
def list_recording_hours(uid, date):
    """列出某设备某天所有有录像的小时"""
    hours = get_recording_hours(uid, date)
    return jsonify({"ok": True, "data": hours})


@app.route('/api/playback/<uid>/<date>/<hour>')
def playback_feed(uid, date, hour):
    """历史录像 MJPEG 回放流"""
    def generate_playback():
        hour_dir = os.path.join(RECORDINGS_DIR, uid, date, hour)
        if not os.path.isdir(hour_dir):
            yield b''
            return

        # 按文件名（时间戳）排序
        frames = sorted([
            f for f in os.listdir(hour_dir) if f.endswith('.jpg')
        ])

        for fname in frames:
            fpath = os.path.join(hour_dir, fname)
            try:
                with open(fpath, 'rb') as f:
                    frame = f.read()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
                time.sleep(0.04)  # ~25 fps 回放速度
            except Exception:
                continue

    return Response(
        generate_playback(),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )


@app.route('/api/recordings/stats')
def recording_stats():
    """获取录像存储统计"""
    stats = get_storage_stats()
    return jsonify({"ok": True, "data": stats})


@app.route('/api/recordings/toggle/<uid>', methods=['POST'])
def toggle_recording(uid):
    """切换某设备的录像开关"""
    current = recording_enabled.get(uid, True)
    recording_enabled[uid] = not current
    status = "已开启" if recording_enabled[uid] else "已关闭"
    return jsonify({
        "ok": True,
        "msg": f"设备 {uid} 录像{status}",
        "recording": recording_enabled[uid]
    })


# -------------------------- 设备 TCP Socket 服务 --------------------------
def handle_device(conn, addr):
    try:
        conn.settimeout(10)
        uid = conn.recv(1024).decode('utf-8').strip()

        with get_db() as db:
            device = db.execute("SELECT psk FROM devices WHERE uid=?", (uid,)).fetchone()

        if not device:
            conn.send(b"ERROR: UNREGISTERED")
            return

        psk = device["psk"]
        challenge = os.urandom(16).hex()
        timestamp = str(int(time.time()))
        challenge_payload = f"{challenge}|{timestamp}"
        conn.send(challenge_payload.encode('utf-8'))

        device_response = conn.recv(1024).decode('utf-8').strip()
        expected_mac = hmac_sm3(psk.encode('utf-8'), challenge_payload.encode('utf-8'))

        if device_response == expected_mac:
            conn.send(b"AUTH_SUCCESS")
            devices_status[uid] = {"status": "online", "last_frame": None}
            print(f"摄像头 {uid} 认证成功，开始接收视频流...")

            conn.settimeout(None)
            while True:
                length_bytes = conn.recv(4)
                if not length_bytes: break
                frame_len = struct.unpack(">I", length_bytes)[0]

                frame_data = b""
                while len(frame_data) < frame_len:
                    packet = conn.recv(min(4096, frame_len - len(frame_data)))
                    if not packet: break
                    frame_data += packet

                devices_status[uid]["last_frame"] = frame_data
                # 将帧写入磁盘录像
                threading.Thread(target=save_frame, args=(uid, frame_data), daemon=True).start()
        else:
            conn.send(b"AUTH_FAILED")
    except Exception as e:
        print(f"摄像头连接异常: {e}")
    finally:
        if uid in devices_status: devices_status[uid]["status"] = "offline"
        conn.close()


def start_socket_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 8080))
    server.listen(5)
    print("TCP 视频接收端口 8080 已启动")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_device, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    init_db()
    threading.Thread(target=start_socket_server, daemon=True).start()
    # 启动录像自动清理调度（启动后立即执行一次，之后每6小时执行）
    threading.Thread(target=schedule_cleanup, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)