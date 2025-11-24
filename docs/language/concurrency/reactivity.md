---
title: "Reactive System"
description: "Building reactive user interfaces and data flows with Signals and Effects."
section: "concurrency"
order: 3
---

# Reactive System

Achronyme includes a built-in reactive system inspired by fine-grained reactivity (like SolidJS or MobX). This allows you to define data relationships where updates propagate automatically, which is essential for building responsive User Interfaces (GUIs).

## Signals

A `Signal` is a wrapper around a value that tracks who is using it. When the value changes, it notifies all its subscribers.

```javascript
// Create a signal
let count = signal(0)

// Read value (subscribes if inside an effect)
print(count.value) 

// Write value (notifies subscribers)
count.set(5)
```

- `signal(initial_value)`: Creates a signal.
- `.value`: Getter property. Reads the value and tracks dependency.
- `.set(new_value)`: Updates the value and triggers effects.
- `.peek()`: Reads the value **without** tracking dependency (useful to avoid loops).

## Effects

An `Effect` is a function that runs immediately and then re-runs whenever any signal it accessed changes.

```javascript
let count = signal(0)
let doubled = signal(0)

// This effect depends on 'count' because it reads 'count.value'
effect(() => do {
    print("Count changed to: " + str(count.value))
    doubled.set(count.value * 2)
})

// Changing count will trigger the effect automatically
count.set(10) 
// Output: "Count changed to: 10"
```

### Automatic Dependency Tracking

You don't need to manually list dependencies. The system detects which signals are read during the execution of the effect. This handles conditional logic correctly:

```javascript
let show = signal(true)
let name = signal("Alice")

effect(() => do {
    if (show.value) {
        // If show is true, we depend on 'name'
        print("Hello " + name.value)
    } else {
        // If show is false, we DON'T depend on 'name'
        print("Hidden")
    }
})
```

## Derived State (Computed Values)

You can create computed values using effects that update other signals.

```javascript
let first = signal("John")
let last = signal("Doe")

let full_name = signal("")

// Keep full_name in sync
effect(() => do {
    full_name.set(first.value + " " + last.value)
})

print(full_name.value) // "John Doe"
first.set("Jane")
print(full_name.value) // "Jane Doe"
```

## Avoiding Cycles

Be careful not to create infinite loops where an effect updates a signal it depends on.

```javascript
// BAD: Infinite Loop
// effect(() => count.set(count.value + 1))

// GOOD: Use peek() to update based on current value without subscribing
effect(() => do {
    // ... trigger logic ...
    count.set(count.peek() + 1) 
})
```
