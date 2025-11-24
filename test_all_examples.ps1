$ErrorActionPreference = "Stop"

Write-Host "Building achronyme-cli..."
cargo build -p achronyme-cli --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed!"
    exit 1
}

$cli_path = ".\target\debug\achronyme.exe"
if (-not (Test-Path $cli_path)) {
    Write-Error "Binary not found at $cli_path"
    exit 1
}

Write-Host "Running examples..."
$passed = 0
$failed = 0
$failed_tests = @()

$files = Get-ChildItem "examples\soc\*.soc"

foreach ($file in $files) {
    Write-Host -NoNewline "Testing $($file.Name)... "
    
    $output_file = [System.IO.Path]::GetTempFileName()
    $error_file = [System.IO.Path]::GetTempFileName()
    
    try {
        # Run the command using Start-Process
        # We must use different files for StdOut and StdErr
        $process = Start-Process -FilePath $cli_path -ArgumentList "`"$($file.FullName)`"" -NoNewWindow -PassThru -RedirectStandardOutput $output_file -RedirectStandardError $error_file -Wait
        
        if ($process.ExitCode -eq 0) {
            Write-Host "PASS" -ForegroundColor Green
            $passed++
        } else {
            Write-Host "FAIL" -ForegroundColor Red
            Write-Host "--- Output for $($file.Name) ---"
            if (Test-Path $output_file) { Get-Content $output_file }
            if (Test-Path $error_file) { Get-Content $error_file }
            Write-Host "---------------------------"
            $failed++
            $failed_tests += $file.Name
        }
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
        $failed++
        $failed_tests += $file.Name
    } finally {
        if (Test-Path $output_file) { Remove-Item $output_file }
        if (Test-Path $error_file) { Remove-Item $error_file }
    }
}

Write-Host ""
Write-Host "Summary:"
Write-Host "Passed: $passed"
Write-Host "Failed: $failed"

if ($failed -gt 0) {
    Write-Host "Failed tests:"
    foreach ($test in $failed_tests) {
        Write-Host " - $test"
    }
    exit 1
} else {
    exit 0
}
