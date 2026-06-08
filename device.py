import socket
import time
import struct
import cv2
import numpy as np
from gmssl import sm3


# sm3
def hmac_sm3(key_bytes, msg_bytes):
    blocksize = 64
    if len(key_bytes) > blocksize:
        key_bytes = bytes.fromhex(sm3.sm3_hash(list(key_bytes)))
    key_bytes = key_bytes.ljust(blocksize, b'\x00')
    ipad = bytes(x ^ 0x36 for x in key_bytes)
    opad = bytes(x ^ 0x5c for x in key_bytes)
    inner_hash = bytes.fromhex(sm3.sm3_hash(list(ipad + msg_bytes)))
    return bytes.fromhex(sm3.sm3_hash(list(opad + inner_hash))).hex()


# 配置
GATEWAY_IP = "127.0.0.1"
GATEWAY_PORT = 8080
MY_UID = "DEV-001"
MY_PSK = "123456"


def connect_and_stream():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[*] 连接网关 {GATEWAY_IP}:{GATEWAY_PORT}...")
        client.connect((GATEWAY_IP, GATEWAY_PORT))

        print(f"[*] 发送认证 UID: {MY_UID}")
        client.send(MY_UID.encode('utf-8'))

        challenge_payload = client.recv(1024).decode('utf-8')
        if challenge_payload.startswith("ERROR"):
            print(f"[!] 网关拒绝接入: {challenge_payload}")
            return

        print(f"[*] 收到网关质询，计算 HMAC-SM3...")
        my_mac = hmac_sm3(MY_PSK.encode('utf-8'), challenge_payload.encode('utf-8'))
        client.send(my_mac.encode('utf-8'))

        result = client.recv(1024).decode('utf-8')
        if result == "AUTH_SUCCESS":
            print("✅ 认证成功！开始推送视频流...")

            # 尝试打开真实摄像头，如果失败则使用虚拟画面
            cap = cv2.VideoCapture(0)

            while True:
                success, frame = cap.read()
                if not success:
                    # 虚拟画面：生成一个带时间戳的黑色图像
                    frame = np.zeros((480, 640, 3), dtype=np.uint8)
                    cv2.putText(frame, f"Simulated Camera: {MY_UID}", (50, 200), cv2.FONT_HERSHEY_SIMPLEX, 1,
                                (0, 255, 0), 2)
                    cv2.putText(frame, time.strftime("%Y-%m-%d %H:%M:%S"), (50, 250), cv2.FONT_HERSHEY_SIMPLEX, 1,
                                (255, 255, 255), 2)

                # 压缩为 JPEG 格式
                _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 60])
                frame_bytes = buffer.tobytes()

                # 网络封包：先发4字节长度，再发数据体，防止TCP粘包
                client.sendall(struct.pack(">I", len(frame_bytes)))
                client.sendall(frame_bytes)

                time.sleep(0.05)  # 控制推流帧率 ~20fps
        else:
            print("❌ 认证失败！预共享密钥错误。")

    except Exception as e:
        print(f"[!] 连接断开: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    connect_and_stream()