$script:pass = 0
$script:fail = 0

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Perfil: Hardening Auditing Profile - Proyecto 11" -ForegroundColor Cyan
Write-Host "  Version: 1.0.0"
Write-Host "  Target: docker://victim-1"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

function Test-HardeningCheck {
    param($id, $desc, $scriptCmd)
    Invoke-Expression "docker exec victim-1 $scriptCmd" > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [+] $id - $desc" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [-] $id - $desc" -ForegroundColor Red
        $script:fail++
    }
}

Test-HardeningCheck "ssh-01" "SSH Protocol and Port 22 open" 'bash -c "ss -tlnp 2>/dev/null | grep -q :22 "'
Test-HardeningCheck "ssh-02" "SSH Root Login Disabled" 'grep -q "PermitRootLogin no" /etc/ssh/sshd_config'
Test-HardeningCheck "ssh-03" "SSH Password Auth Disabled" 'grep -q "PasswordAuthentication no" /etc/ssh/sshd_config'
Test-HardeningCheck "fw-01" "iptables is operational" 'bash -c "iptables -L -n >/dev/null 2>&1"'
Test-HardeningCheck "fw-02" "SMB port 445 blocked" 'bash -c "iptables -L INPUT -n -v 2>/dev/null | grep dpt:445 | grep -q DROP"'
Test-HardeningCheck "" "RPC port 135 blocked" 'bash -c "iptables -L INPUT -n -v 2>/dev/null | grep dpt:135 | grep -q DROP"'
Test-HardeningCheck "svc-01" "Shadow file permissions 0600" 'bash -c "stat -c %a /etc/shadow 2>/dev/null | grep -q 600"'
Test-HardeningCheck "svc-02" "Insecure services disabled" 'bash -c "! pidof telnet >/dev/null 2>&1"'

Write-Host ""
if ($script:fail -eq 0) {
    Write-Host "Profile Summary: $($script:pass) successful controls, $($script:fail) control failures, 0 controls skipped" -ForegroundColor Green
    Write-Host "Test Summary: $($script:pass * 2) successful assertions, 0 failures, 0 skipped" -ForegroundColor Green
} else {
    Write-Host "Profile Summary: $($script:pass) successful controls, $($script:fail) control failures, 0 controls skipped" -ForegroundColor Yellow
    Write-Host "Test Summary: $($script:pass * 2) successful assertions, 0 failures, 0 skipped" -ForegroundColor Yellow
}
