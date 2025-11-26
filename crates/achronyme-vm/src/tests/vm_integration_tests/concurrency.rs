use super::helpers::execute_async;
use crate::value::Value;

#[test]
fn test_channel_communication() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let source = r#"
            let pair = channel()
            let tx = pair[0]
            let rx = pair[1]

            spawn(async () => do {
                await tx.send(42)
            })

            let val = await rx.recv()
            val
        "#;

        let result = execute_async(source).await.unwrap();
        assert_eq!(result, Value::Number(42.0));
    });
}

#[test]
fn test_async_mutex() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let source = r#"
            let counter = AsyncMutex(0)

            // Increment 100 times concurrently
            let tasks = []
            
            let worker = async () => do {
                let guard = await counter.lock()
                let val = guard.get()
                guard.set(val + 1)
                // guard unlocks when dropped (end of scope)
            }

            for(i in range(0, 100)) {
                push(tasks, spawn(worker))
            }

            // Wait for all (simple loop)
            for(t in tasks) {
                await t
            }

            let final_guard = await counter.lock()
            final_guard.get()
        "#;

        let result = execute_async(source).await.unwrap();
        assert_eq!(result, Value::Number(100.0));
    });
}
