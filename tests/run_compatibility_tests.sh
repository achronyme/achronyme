#!/bin/bash
# Run compatibility tests between tree-walker and VM

echo "Running compatibility tests..."
echo "================================"

cargo test --test compatibility -- --test-threads=1 --nocapture

if [ $? -eq 0 ]; then
    echo ""
    echo "All compatibility tests passed!"
    echo "VM is compatible with tree-walker"
else
    echo ""
    echo "Some compatibility tests failed"
    echo "VM has regressions compared to tree-walker"
    exit 1
fi
