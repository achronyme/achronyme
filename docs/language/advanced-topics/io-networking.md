---
title: "I/O and Networking"
description: "File system operations, HTTP client, and data encoding (JSON/CSV) in Achronyme"
section: "advanced-topics"
order: 14
---

# I/O and Networking

Achronyme provides robust, asynchronous tools for interacting with the file system and the web, along with utilities for processing common data formats like JSON and CSV.

## File System

File operations in Achronyme are **asynchronous** to ensure non-blocking execution, making them suitable for high-performance applications.

### Reading Files

Use `read_file` to read the entire content of a file as a string.

```javascript
try {
    let content = await read_file("data.txt")
    print("File size: " + str(len(content)))
} catch (e) {
    print("Error reading file: " + e.message)
}
```

### Writing Files

Use `write_file` to overwrite a file with new content, or `append_file` to add to the end.

```javascript
// Overwrite (or create)
await write_file("output.txt", "Hello World\n")

// Append
await append_file("output.txt", "Another line\n")
```

### File Management

Check for existence or delete files.

```javascript
if (await exists("temp.dat")) {
    await delete_file("temp.dat")
    print("Temporary file cleaned up.")
}
```

| Function | Signature | Description |
|---|---|---|
| `read_file` | `(path: String) -> Future<String>` | Reads entire file content. |
| `write_file` | `(path: String, content: String) -> Future<Null>` | Writes content to file (overwrites). |
| `append_file` | `(path: String, content: String) -> Future<Null>` | Appends content to file. |
| `delete_file` | `(path: String) -> Future<Boolean>` | Deletes a file. Returns true if successful. |
| `exists` | `(path: String) -> Future<Boolean>` | Checks if a file exists. |

---

## Networking (HTTP)

Achronyme includes a built-in HTTP client for interacting with web APIs. These functions are also **asynchronous**.

### GET Requests

Fetch data from a URL.

```javascript
let url = "https://api.example.com/data"
let response = await http_get(url)
let data = json_parse(response)
print("Received: " + data.status)
```

### POST Requests

Send data to a server.

```javascript
let url = "https://api.example.com/submit"
let payload = { id: 123, value: 45.5 }

// Send JSON string
let body = json_stringify(payload)
let headers = { "Authorization": "Bearer token123" }

let response = await http_post(url, body, headers)
```

| Function | Signature | Description |
|---|---|---|
| `http_get` | `(url: String) -> Future<String>` | Performs HTTP GET request. |
| `http_post` | `(url: String, body: String, headers?: Record) -> Future<String>` | Performs HTTP POST request. |

---

## Data Encoding

To support I/O and Networking, Achronyme provides built-in parsing for JSON and CSV formats. These functions are **synchronous**.

### JSON

Convert between Achronyme types (`Record`, `Vector`, primitives) and JSON strings.

```javascript
// Parsing
let json_str = '{"name": "Alice", "scores": [10, 20]}'
let data = json_parse(json_str)
print(data.name) // "Alice"

// Stringifying
let obj = { x: 10, y: 20 }
let json = json_stringify(obj, true) // true = pretty print
print(json)
```

### CSV

Parse CSV strings into vectors or records.

```javascript
let csv_data = "name,age\nBob,30\nCharlie,25"

// Parse as Records (uses header row as keys)
let records = csv_parse(csv_data, true)
print(records[0].name) // "Bob"

// Parse as Vectors (raw rows)
let rows = csv_parse(csv_data, false)
print(rows[1][0]) // "Bob" (row 0 is header)
```

| Function | Signature | Description |
|---|---|---|
| `json_parse` | `(json: String) -> Value` | Parses JSON string into Achronyme value. |
| `json_stringify` | `(val: Value, pretty?: Boolean) -> String` | Converts value to JSON string. |
| `csv_parse` | `(csv: String, has_headers?: Boolean) -> Vector` | Parses CSV string. |

---

## Complete Example: Fetch, Process, and Save

```javascript
let main = async () => do {
    println("Fetching dataset...")
    
    // 1. Fetch Data
    try {
        let json_str = await http_get("https://api.example.com/users")
        let users = json_parse(json_str)
        
        // 2. Process Data (Filter active users)
        let active_users = filter(u => u.isActive, users)
        
        // 3. Save to CSV
        let csv_rows = map(u => '${u.id},${u.name}', active_users)
        let csv_content = "id,name\n" + join(csv_rows, "\n")
        
        await write_file("active_users.csv", csv_content)
        println("Saved " + str(len(active_users)) + " users to CSV.")
        
    } catch (e) {
        println("Operation failed: " + e.message)
    }
}

await main()
```
