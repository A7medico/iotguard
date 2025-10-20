param(
  [Parameter(Mandatory=$true)][string]$IP,
  [string]$RuleNamePrefix = "IoTGuard_Block_"
)
$rule = "$RuleNamePrefix$IP"

try {
  # Check if exists
  $existing = (netsh advfirewall firewall show rule name="$rule" dir=in) 2>$null
  if ($LASTEXITCODE -eq 0 -and $existing -match "Rule Name") {
    Write-Output "exists"
    exit 0
  }

  netsh advfirewall firewall add rule name="$rule" dir=in action=block remoteip=$IP
  if ($LASTEXITCODE -eq 0) {
    Write-Output "added"
    exit 0
  } else {
    Write-Error "failed"
    exit 1
  }
}
catch {
  Write-Error $_
  exit 1
}
