import hashlib
import time

'''
写一个python脚本： 
 实践 POW 用'kerwin' + nonce， nonce不断的变更，计算 sha256 Hash : 
 • 直到满足 4 个0 开头，打印出花费的时间 
 • 直到满足 5 个0 开头，打印出花费的时间


'''

def mine(prefix: str, zeros: int) -> None:
    target = "0" * zeros
    nonce = 0
    start = time.perf_counter()

    while True:
        data = f"{prefix}{nonce}"
        digest = hashlib.sha256(data.encode()).hexdigest()
        if digest.startswith(target):
            elapsed = time.perf_counter() - start
            print(f"难度 {zeros} 个 0:")
            print(f"  nonce    = {nonce}")
            print(f"  输入     = {data}")
            print(f"  sha256   = {digest}")
            print(f"  尝试次数 = {nonce + 1}")
            print(f"  耗时     = {elapsed:.6f} 秒")
            break
        nonce += 1


if __name__ == "__main__":
    mine("kerwin", 4)
    print()
    mine("kerwin", 5)
