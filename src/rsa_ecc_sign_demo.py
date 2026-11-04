import hashlib
import time

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigdecode_string

'''
写另一个python脚本： 
实践非对称加密 RSA (ECC)
• 先生成一个公私钥对
• 用私钥对符合POW机制，在pow_demon中，'kerwin' + nonce 生成的hash，进行私钥签名
• 用公钥验证
'''

# ---------------------------------------------------------------- POW
def find_pow(prefix: str, zeros: int = 4):
    target = "0" * zeros
    nonce = 0
    start = time.perf_counter()
    while True:
        data = f"{prefix}{nonce}"
        digest = hashlib.sha256(data.encode()).hexdigest()
        if digest.startswith(target):
            return nonce, data, digest, time.perf_counter() - start
        nonce += 1


# ---------------------------------------------------------------- main
if __name__ == "__main__":
    nonce, data, digest, elapsed = find_pow("kerwin", 4)
    print("1) POW 结果")
    print(f"   data   = {data}")
    print(f"   sha256 = {digest}")
    print(f"   耗时   = {elapsed:.6f} 秒\n")

    digest_bytes = bytes.fromhex(digest)

    # ------------------------------- RSA (pycryptodome)
    print("2) RSA-2048（pycryptodome）")
    t0 = time.perf_counter()
    rsa_key = RSA.generate(2048)
    print(f"   生成密钥对耗时 = {time.perf_counter() - t0:.3f} 秒")
    rsa_pub = rsa_key.publickey()
    print(f"   公钥 n 位数 = {rsa_pub.n.bit_length()}, e = {rsa_pub.e}")
    print(f"   私钥 d 位数 = {rsa_key.d.bit_length()}")

    h = SHA256.new(digest_bytes)
    sig_rsa = pkcs1_15.new(rsa_key).sign(h)
    print(f"   签名长度 = {len(sig_rsa)} 字节")
    try:
        pkcs1_15.new(rsa_pub).verify(SHA256.new(digest_bytes), sig_rsa)
        print("   原始 POW hash 验签: True")
    except ValueError:
        print("   原始 POW hash 验签: False")

    fake_digest = bytes.fromhex(hashlib.sha256(f"kerwin{nonce + 1}".encode()).hexdigest())
    try:
        pkcs1_15.new(rsa_pub).verify(SHA256.new(fake_digest), sig_rsa)
        print("   篡改 hash 验签    : True\n")
    except ValueError:
        print("   篡改 hash 验签    : False\n")

    # ------------------------------- ECC (ecdsa)
    print("3) ECC secp256k1（ecdsa）")
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    print(f"   私钥 d = {sk.to_string().hex()[:32]}...")
    print(f"   公钥 Q = {vk.to_string().hex()[:32]}...")

    sig_ecc = sk.sign_digest_deterministic(digest_bytes, hashfunc=hashlib.sha256)
    print(f"   签名 (r,s) = {sig_ecc.hex()}")
    vk.verify_digest(sig_ecc, digest_bytes, sigdecode=sigdecode_string)
    print("   原始 POW hash 验签: True")

    try:
        vk.verify_digest(sig_ecc, fake_digest, sigdecode=sigdecode_string)
        print("   篡改 hash 验签    : True")
    except Exception:
        print("   篡改 hash 验签    : False")
