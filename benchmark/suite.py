import time

print("--- Python Benchmark Suite ---")

# 1. Recursion: Fibonacci
def fib(n):
    if n < 2: return n
    return fib(n - 1) + fib(n - 2)

print("1. Recursion (Fib 28)...")
t0 = time.time()
print(fib(28))
t1 = time.time()
print(f"   Time: {t1 - t0}")

# 2. Iteration: Sum 1M
print("2. Iteration (Sum 1M)...")
t2 = time.time()
sum_val = 0
i = 0
while i < 1000000:
    sum_val = sum_val + i
    i = i + 1
t3 = time.time()
print(f"   Result: {sum_val}")
print(f"   Time: {t3 - t2}")

# 3. List Allocation: Push 100k
print("3. List Allocation (Push 100k)...")
lst = []
t4 = time.time()
j = 0
while j < 100000:
    lst.append(j)
    j = j + 1
t5 = time.time()
print(f"   Len: {len(lst)}")
print(f"   Time: {t5 - t4}")

# 4. Map Access: 100k Writes
print("4. Map Access (100k Overwrites)...")
map_obj = {}
t6 = time.time()
k = 0
while k < 100000:
    map_obj["key"] = k
    k = k + 1
t7 = time.time()
print(f"   Last Val: {map_obj['key']}")
print(f"   Time: {t7 - t6}")

print("--- END ---")
