import socket
import time
import struct
import signal
import sys
import cv2
from gmssl import sm3

# ========================== 设备参数配置 ==========================
# 网关连接参数（需与网关所在主机 IP 一致）
GATEWAY_IP = "10.228.212.185"
GATEWAY_PORT = 8080

# 设备凭证（必须在网关管理页面预先注册，PSK 须与网关数据库一致）
MY_UID = "CAM-001"
MY_PSK = "my_secure_psk_2023"

# 视频参数
FRAME_QUALITY = 65       # JPEG 压缩质量 (1-100)
TARGET_FPS = 20          # 目标帧率
FRAME_DELAY = 1.0 / TARGET_FPS

# 全局运行标志（用于优雅退出）
_running = True


def _signal_handler(signum, frame):
    """捕获 SIGINT / SIGTERM，安全释放硬件资源"""
    global _running
    print("\n[!] 收到退出信号，正在安全关闭...")
    _running = False


# ==================================================================

def hmac_sm3(key_bytes, msg_bytes):
    """设备端计算 HMAC-SM3 应答"""
    blocksize = 64
    if len(key_bytes) > blocksize:
        key_bytes = bytes.fromhex(sm3.sm3_hash(list(key_bytes)))
    key_bytes = key_bytes.ljust(blocksize, b'\x00')
    ipad = bytes(x ^ 0x36 for x in key_bytes)
    opad = bytes(x ^ 0x5c for x in key_bytes)
    inner_hash = bytes.fromhex(sm3.sm3_hash(list(ipad + msg_bytes)))
    return bytes.fromhex(sm3.sm3_hash(list(opad + inner_hash))).hex()


def start_camera_stream():
    global _running
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    picam = None

    try:
        print(f"[*] 正在尝试连接至网关 {GATEWAY_IP}:{GATEWAY_PORT}...")
        client.settimeout(5.0)  # 5秒连接超时防卡死
        client.connect((GATEWAY_IP, GATEWAY_PORT))
        client.settimeout(None)  # 连接成功后恢复长连接模式

        # 1. 提交 UID
        client.send(MY_UID.encode('utf-8'))

        # 2. 接收挑战码
        challenge_payload = client.recv(1024).decode('utf-8')
        if challenge_payload.startswith("ERROR"):
            print(f"[!] 被网关拒绝: {challenge_payload}")
            return

        print("[*] 收到网关质询，正在使用本地 PSK 计算 HMAC-SM3...")
        my_mac = hmac_sm3(MY_PSK.encode('utf-8'), challenge_payload.encode('utf-8'))
        client.send(my_mac.encode('utf-8'))

        # 3. 验证结果
        result = client.recv(1024).decode('utf-8')

        if result == "AUTH_SUCCESS":
            print("✅ 身份认证成功！链路已安全加密。")
            print("🔄 正在初始化 Picamera2 硬件引擎...")

            # 引入 Picamera2 并初始化
            from picamera2 import Picamera2
            picam = Picamera2()

            # 利用硬件 ISP 将 500 万像素直接压制并裁剪为 640x480 的流畅监控画幅
            config = picam.create_video_configuration(main={"size": (640, 480)})
            picam.configure(config)
            picam.start()

            print("📡 硬件开启成功！正在向网关推送【真实摄像头】视频流...")

            try:
                while _running:
                    # 极速抓取一帧真实画面 (返回 numpy 数组)
                    frame = picam.capture_array()

                    # Picamera2 默认是 RGB 格式，而 OpenCV 编码需要 BGR 格式，进行转换
                    frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)

                    # 打上防伪/实时时间戳水印
                    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S")
                    cv2.putText(frame, f"Pi4B {MY_UID}", (20, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                    cv2.putText(frame, timestamp_str, (20, 65), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)

                    # 压缩为 JPEG 格式以适应网络传输
                    _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), FRAME_QUALITY])
                    frame_bytes = buffer.tobytes()

                    # 按照私有协议：先发 4 字节数据长度，再发图像体（与网关 handle_device 解包逻辑一致）
                    client.sendall(struct.pack(">I", len(frame_bytes)))
                    client.sendall(frame_bytes)

                    # 控制帧率，防止局域网和网关拥堵
                    time.sleep(FRAME_DELAY)

            except BrokenPipeError:
                print("[!] 网关端主动断开了连接（可能是网关程序关闭了）")
            except Exception as e:
                print(f"[!] 视频传输中断: {e}")
            finally:
                if picam:
                    picam.stop()
                    print("🛑 摄像头硬件已安全释放。")
        else:
            print("❌ 认证失败！预共享密钥 (PSK) 不匹配。")

    except ConnectionRefusedError:
        print("[!] 无法连接到网关，请检查网关是否已启动，以及 8080 端口防火墙。")
    except socket.timeout:
        print("[!] 连接网关超时，请确认 IP 10.228.212.185 是否正确，两台设备是否在同一局域网。")
    except Exception as e:
        import traceback
        print(f"[!] 发生未知的严重网络异常:")
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    # 注册信号处理，确保 Ctrl+C 或系统关闭时安全释放 Pi 摄像头硬件
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    start_camera_stream()