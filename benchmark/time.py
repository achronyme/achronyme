import time
start = time.time()

i = 0
while i < 10000000:
    i = i + 1

print(i)
print(f"Tiempo: {time.time() - start}")