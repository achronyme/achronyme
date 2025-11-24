---
title: "Async/Await"
description: "Asynchronous programming in Achronyme using async functions and await expressions."
section: "concurrency"
order: 1
---

# Async/Await

Achronyme supports modern asynchronous programming through `async` functions and `await` expressions. This allows you to write non-blocking code that looks and behaves like synchronous code, making it easier to handle I/O operations, timers, and concurrent tasks.

## Async Functions

An asynchronous function is defined using the `async` keyword. It automatically returns a `Future` when called, which resolves to the function's return value.

```javascript
// Define an async function
let fetch_data = async (id) => do {
    print("Fetching data for " + str(id) + "...")
    await sleep(1000) // Simulate network delay
    "Data for " + str(id)
}

// Call it
let future = fetch_data(42)
// 'future' is now a Future object, the function is running (or scheduled)
```

### Async Blocks

You can also create anonymous async blocks, which are useful for inline concurrent tasks:

```javascript
let task = async do {
    await sleep(500)
    100 * 2
}
```

## Await Expression

The `await` keyword pauses the execution of the current `async` function until the awaited `Future` completes. While paused, the underlying event loop can execute other tasks, ensuring your application remains responsive.

```javascript
let main = async () => do {
    print("Start")
    
    // Wait for the result
    let result = await fetch_data(42)
    
    print("Result: " + result) // Runs after 1 second
}
```

## Non-Blocking Execution

Unlike synchronous code, `await` does not block the entire VM. It only suspends the current task.

```javascript
let task1 = async () => do {
    await sleep(1000)
    print("Task 1 done")
}

let task2 = async () => do {
    await sleep(500)
    print("Task 2 done")
}

// Both tasks start almost simultaneously
let f1 = task1()
let f2 = task2()

// Output order will be:
// "Task 2 done" (after 500ms)
// "Task 1 done" (after 1000ms)
```

## Top-Level Await

Achronyme allows `await` at the top level of a script or module, making it easy to write scripts that perform async operations without wrapping everything in a `main` function.

```javascript
// Top-level script
print("Downloading...")
let content = await read_file("data.txt")
print("File size: " + str(len(content)))
```
