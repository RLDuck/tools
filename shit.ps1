# Detect-Faker.ps1
# weighted structural detection for Faker/MITM proxy setups
# does NOT rely on SSID names or gateway IP conventions

$score = 0
$flags = @()
$info  = @()

# ─────────────────────────────────────────────
# 1. java.exe connected to private IP on :25565  [weight: 10]
# ─────────────────────────────────────────────
try {
    $javaPIDs = (Get-Process -Name "java" -ErrorAction SilentlyContinue).Id
    if ($javaPIDs) {
        $netstatLines = netstat -ano | Select-String "ESTABLISHED"
        foreach ($line in $netstatLines) {
            if ($line -match "\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+ESTABLISHED\s+(\d+)") {
                $remoteIP   = $matches[3]
                $remotePort = [int]$matches[4]
                $pid        = [int]$matches[5]

                if ($pid -in $javaPIDs -and $remotePort -eq 25565) {
                    $isPrivate = $remoteIP -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."
                    if ($isPrivate) {
                        $score += 10
                        $flags += "[CRITICAL] java.exe connected to private IP $remoteIP on :25565 — local proxy confirmed"
                    } else {
                        $info += "[OK] java.exe connected to public server IP $remoteIP on :25565"
                    }
                }
            }
        }
    } else {
        $info += "[INFO] no java.exe process found"
    }
} catch {
    $info += "[ERR] netstat/java check failed: $_"
}

# ─────────────────────────────────────────────
# 2. hosted network active on this machine  [weight: 6]
# ─────────────────────────────────────────────
try {
    $hostedOutput = netsh wlan show hostednetwork 2>&1
    $statusLine   = $hostedOutput | Select-String "Status\s+:\s+(.+)"
    if ($statusLine) {
        $hostedStatus = $statusLine.Matches[0].Groups[1].Value.Trim()
        if ($hostedStatus -match "^Started$") {
            $score += 6
            $flags += "[CRITICAL] hosted network is active on this machine — this is likely PC1"
        } else {
            $info += "[INFO] hosted network present but status: $hostedStatus"
        }
    }

    # also check for Wi-Fi Direct GO mode
    $interfacesOutput = netsh wlan show interfaces 2>&1
    $wdLines = $interfacesOutput | Select-String "Hosted Network|Wi-Fi Direct"
    foreach ($l in $wdLines) {
        $info += "[INFO] Wi-Fi interface entry: $($l.Line.Trim())"
    }
} catch {
    $info += "[ERR] hosted network check failed: $_"
}

# ─────────────────────────────────────────────
# 3. double-NAT traceroute (hop1 private, hop2 also private)  [weight: 5]
# ─────────────────────────────────────────────
try {
    $trace = Test-NetConnection -ComputerName "1.1.1.1" -Hops 5 -TraceRoute -WarningAction SilentlyContinue -ErrorAction Stop
    $hops  = $trace.TraceRoute | Where-Object { $_ -and $_ -ne "0.0.0.0" }

    if ($hops.Count -ge 2) {
        $hop1 = $hops[0].ToString()
        $hop2 = $hops[1].ToString()
        $isPrivate1 = $hop1 -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."
        $isPrivate2 = $hop2 -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."

        $info += "[INFO] traceroute hop1=$hop1 hop2=$hop2"

        if ($isPrivate1 -and $isPrivate2) {
            $score += 5
            $flags += "[WARN] double-NAT detected — two consecutive private hops before internet ($hop1 → $hop2)"
        } elseif ($isPrivate1 -and -not $isPrivate2) {
            $info += "[OK] single NAT — hop1 private ($hop1), hop2 public ($hop2) — normal home router"
        }
    } elseif ($hops.Count -eq 1) {
        $info += "[INFO] only one traceroute hop resolved"
    }
} catch {
    $info += "[ERR] traceroute failed: $_"
}

# ─────────────────────────────────────────────
# 4. all DNS servers are private LAN IPs  [weight: 4]
# ─────────────────────────────────────────────
try {
    $dnsServers = (Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop |
        Where-Object { $_.IPEnabled -and $_.DNSServerSearchOrder }) |
        ForEach-Object { $_.DNSServerSearchOrder } |
        Select-Object -Unique

    if ($dnsServers) {
        $privateDNS = $dnsServers | Where-Object { $_ -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\." }
        $publicDNS  = $dnsServers | Where-Object { $_ -notmatch "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\." }

        $info += "[INFO] DNS servers: $($dnsServers -join ', ')"

        if ($privateDNS -and -not $publicDNS) {
            $score += 4
            $flags += "[WARN] all DNS servers are private LAN IPs ($($privateDNS -join ', ')) — no public DNS fallback"
        }
    }
} catch {
    $info += "[ERR] DNS check failed: $_"
}

# ─────────────────────────────────────────────
# 5a. actual default gateway via route print  [weight: combined below]
# ─────────────────────────────────────────────
$gatewayIP = $null
try {
    $routeOutput  = route print 0.0.0.0 2>&1
    $defaultMatch = $routeOutput | Select-String "^\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)"
    if ($defaultMatch) {
        $gatewayIP = $defaultMatch.Matches[0].Groups[1].Value
        $info += "[INFO] default gateway (route print): $gatewayIP"
    }
} catch {
    $info += "[ERR] route print failed: $_"
}

# ─────────────────────────────────────────────
# 5b. gateway == DNS server  [weight: 2]
# ─────────────────────────────────────────────
if ($gatewayIP -and $dnsServers -contains $gatewayIP) {
    $score += 2
    $flags += "[INFO] default gateway ($gatewayIP) is also the DNS server — typical hotspot/Faker DHCP pattern"
}

# ─────────────────────────────────────────────
# 5c. Wi-Fi adapter present and connected  [weight: 1]
# ─────────────────────────────────────────────
try {
    $wifiAdapters = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match "Wi-Fi|Wireless|802\.11|WLAN" -and $_.Status -eq "Up" }
    if ($wifiAdapters) {
        $score += 1
        $info += "[INFO] Wi-Fi adapter connected: $($wifiAdapters.Name -join ', ')"
    }
} catch {
    $info += "[ERR] adapter check failed: $_"
}

# ─────────────────────────────────────────────
# result
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "===============================" -ForegroundColor Cyan
Write-Host "   FAKER DETECTION REPORT" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

foreach ($i in $info) { Write-Host $i -ForegroundColor DarkGray }
Write-Host ""

if ($flags.Count -gt 0) {
    foreach ($f in $flags) { Write-Host $f -ForegroundColor Yellow }
    Write-Host ""
}

Write-Host "Score: $score" -ForegroundColor White

if ($score -ge 10) {
    Write-Host "RESULT: FAKER DETECTED" -ForegroundColor Red
} elseif ($score -ge 5) {
    Write-Host "RESULT: SUSPICIOUS — manual review needed" -ForegroundColor Yellow
} else {
    Write-Host "RESULT: CLEAN" -ForegroundColor Green
}

Write-Host ""
