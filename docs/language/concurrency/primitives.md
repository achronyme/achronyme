---
title: "Concurrency Primitives"
description: "Tools for managing concurrent tasks: spawn, channels, and mutexes."
section: "concurrency"
order: 2
---

# Concurrency Primitives

Achronyme provides powerful primitives for concurrent programming, enabling you to run tasks in parallel, communicate between them safely, and synchronize shared state.

## Spawning Tasks

The `spawn` function launches a new lightweight task (green thread) that runs concurrently with the main program.

```javascript
spawn(async () => do {
    // This runs in the background
    await sleep(1000)
    print("Background task finished")
})

print("Main program continues...")
```

`spawn` returns a `Future` that resolves to the return value of the spawned function. You can `await` this future if you need to join the task later.

## Channels (Message Passing)

Channels allow safe communication between concurrent tasks. Achronyme uses unbounded multi-producer, single-consumer (mpsc) channels.

```javascript
// Create a channel
let [tx, rx] = channel()

// Producer task
spawn(async () => do {
    for (i in 1..5) {
        await tx.send(i) // Send data
        await sleep(100)
    }
    // Sending null signals end of stream (convention)
    await tx.send(null) 
})

// Consumer (Main thread)
while (true) {
    let msg = await rx.recv() // Wait for data
    if (msg == null) { break }
    print("Received: " + str(msg))
}
```

- `channel()` returns a pair `[Sender, Receiver]`.
- `sender.send(value)`: Sends a value to the channel. Returns a Future (currently resolves immediately but is awaitable).
- `receiver.recv()`: Waits for the next message. Returns a Future that resolves to the message.

## Shared State (AsyncMutex)

When multiple tasks need to access shared mutable state, `AsyncMutex` ensures exclusive access, preventing race conditions.

```javascript
// Initialize shared state
let counter = AsyncMutex(0)

// Worker task
let worker = async () => do {
    // Acquire lock (waits if busy)
    let guard = await counter.lock()
    
    // Critical section: only one task is here at a time
    let val = guard.get()
    guard.set(val + 1)
    
    // Lock is released automatically when 'guard' goes out of scope
}

// Run multiple workers
let t1 = spawn(worker)
let t2 = spawn(worker)

await t1
await t2

// Check final result
let final_guard = await counter.lock()
print("Final count: " + str(final_guard.get())) // 2
```

- `AsyncMutex(initial_value)`: Creates a new mutex.
- `mutex.lock()`: Returns a Future that resolves to a `MutexGuard` when the lock is acquired.
- `guard.get()`: Retrieves the value.
- `guard.set(new_value)`: Updates the value.
- The lock is released when the `MutexGuard` is dropped (garbage collected or goes out of scope).
