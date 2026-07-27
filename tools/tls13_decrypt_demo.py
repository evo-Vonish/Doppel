#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
R1 核心机制沙盒实证：SSLKEYLOGFILE + 旁路密文 → 恢复 TLS 1.3 明文。
拓扑：client ⇄ relay（无损 tee 双向密文）⇄ server（写 keylog）。
随后用 keylog 推流量密钥，AES-GCM 逐个记录解密，断言明文可恢复。
"""
import os, ssl, socket, threading, struct, time, hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.environ.get("TLS_DEMO_DIR", "/tmp/tlsdemo")
KEYLOG = f"{BASE}/sslkeys.log"
C2S, S2C = f"{BASE}/c2s.bin", f"{BASE}/s2c.bin"
REQ = b"GET /secret-report HTTP/1.1\r\nHost: localhost\r\nX-Marker: TISHEN_R1_PROOF\r\n\r\n"
BODY = "替身已启动：R1 明文恢复实证成功。\n".encode("utf-8")
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(BODY)).encode() + b"\r\n\r\n" + BODY

# ---------- 服务端 ----------
def run_server():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.keylog_filename = KEYLOG
    ctx.load_cert_chain(f"{BASE}/cert.pem", f"{BASE}/key.pem")
    lsock = socket.socket(); lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 19443)); lsock.listen(1)
    conn, _ = lsock.accept()
    with ctx.wrap_socket(conn, server_side=True) as s:
        s.recv(4096)
        s.sendall(RESP)
        time.sleep(0.2)

# ---------- 中继（tee 密文）----------
def relay():
    lsock = socket.socket(); lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 10443)); lsock.listen(1)
    c, _ = lsock.accept()
    s = socket.create_connection(("127.0.0.1", 19443))
    c.settimeout(3); s.settimeout(3)
    def pump(src, dst, fh):
        try:
            while True:
                data = src.recv(65535)
                if not data: break
                fh.write(data); fh.flush()
                dst.sendall(data)
        except (socket.timeout, OSError): pass
    with open(C2S, "wb") as f1, open(S2C, "wb") as f2:
        t = threading.Thread(target=pump, args=(c, s, f1))
        t.start(); pump(s, c, f2); t.join()
    c.close(); s.close()

# ---------- TLS1.3 记录解密 ----------
def hkdf_expand_label(secret: bytes, label: str, length: int, hash_name: str) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    H = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384()}[hash_name]
    return HKDFExpand(algorithm=H, length=length, info=info).derive(secret)

def parse_keylog(path):
    secrets = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3 and parts[0] in (
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"):
                secrets.setdefault(parts[0], bytes.fromhex(parts[2]))
    return secrets

def records(path):
    with open(path, "rb") as f:
        data = f.read()
    i = 0
    while i + 5 <= len(data):
        typ, ver, ln = data[i], data[i:i+3], struct.unpack(">H", data[i+3:i+5])[0]
        payload = data[i+5:i+5+ln]
        if len(payload) < ln: break
        yield data[i:i+5], typ, payload
        i += 5 + ln

def decrypt_stream(path, hs_secret, app_secret, hash_name, key_len, label):
    """逐记录尝试 handshake/app 两套密钥（GCM 标签自校验），返回应用数据明文。"""
    hs_key = hkdf_expand_label(hs_secret, "key", key_len, hash_name)
    hs_iv  = hkdf_expand_label(hs_secret, "iv", 12, hash_name)
    ap_key = hkdf_expand_label(app_secret, "key", key_len, hash_name)
    ap_iv  = hkdf_expand_label(app_secret, "iv", 12, hash_name)
    counters = {"hs": 0, "ap": 0}
    plain_app = []
    for header, typ, payload in records(path):
        if typ != 23:            # 非 application_data 记录（TLS1.3 中握手亦伪装为 23）
            continue
        ok = False
        for which, key, iv in (("hs", hs_key, hs_iv), ("ap", ap_key, ap_iv)):
            seq = counters[which]
            nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))
            try:
                pt = AESGCM(key).decrypt(nonce, payload, header)
            except Exception:
                continue
            counters[which] += 1
            ok = True
            inner = pt.rstrip(b"\x00")
            if inner and inner[-1] == 23:        # 内层类型=应用数据
                plain_app.append(inner[:-1])
            break
        # 记录无法解密：理论上是丢包/乱序，打印并继续（真实流水线中记 gap）
        if not ok:
            print(f"  [gap] {label} 有记录未能解密（seq hs={counters['hs']} ap={counters['ap']}）")
    return plain_app

def main():
    for f in (KEYLOG, C2S, S2C):
        if os.path.exists(f): os.remove(f)
    ts = threading.Thread(target=run_server); ts.start()
    time.sleep(0.3)
    tr = threading.Thread(target=relay); tr.start()
    time.sleep(0.3)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", 10443)) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as c:
            cipher = c.cipher()[0]
            c.sendall(REQ)
            c.recv(4096)
    ts.join(); tr.join()

    hash_name, key_len = {
        "TLS_AES_128_GCM_SHA256": ("sha256", 16),
        "TLS_AES_256_GCM_SHA384": ("sha384", 32),
    }[cipher]
    secrets = parse_keylog(KEYLOG)
    print(f"协商套件: {cipher}  keylog 标签: {sorted(secrets)}")

    c_plain = decrypt_stream(C2S, secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"],
                             secrets["CLIENT_TRAFFIC_SECRET_0"], hash_name, key_len, "C→S")
    s_plain = decrypt_stream(S2C, secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"],
                             secrets["SERVER_TRAFFIC_SECRET_0"], hash_name, key_len, "S→C")
    c_text = b"".join(c_plain); s_text = b"".join(s_plain)
    print("C→S 明文:", c_text[:80])
    print("S→C 明文:", s_text[:80])
    assert REQ in c_text, "客户端明文未恢复"
    assert RESP in s_text, "服务端明文未恢复"
    print("\n✅ R1 机制实证通过：keylog + 旁路密文 = 双向明文完整恢复")

if __name__ == "__main__":
    main()
