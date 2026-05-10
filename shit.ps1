<#
.SYNOPSIS
    Faker MITM proxy detector for Minecraft screenshares.

.DESCRIPTION
    Detects Faker by targeting structural artifacts the proxy MUST produce,
    not bypassable conventions like SSID names or common gateway IPs.

    Detection signals (weighted):
      [10pts] java.exe ESTABLISHED to private IP on port 25565 (allowDirectConnection mode)
      [6pts]  This machine is hosting a Wi-Fi network with active clients (PC2 is actually PC1)
      [5pts]  Double-NAT traceroute (two private hops before public internet)
      [4pts]  All DNS servers are private LAN IPs (Faker DHCP fingerprint)
      [3pts]  Default route gateway is private AND matches DNS server
      [2pts]  icssvc (Windows Mobile Hotspot) service is running
      [1pt]   Wi-Fi Direct / hosted network adapter present and active

    Score >= 10 : FAKER DETECTED
    Score >= 5  : SUSPICIOUS
    Score < 5   : CLEAN

.NOTES
    Run as the user being screenshared (no elevation required for most checks).
    Elevation improves traceroute accuracy but is not required.
#>

#region --- CONFIG ---
$OutputPath  = "$env:USERPROFILE\Desktop\FakerDetect_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$ScoreDetect = 10
$ScoreSuspect = 5
#endregion

#region --- INIT ---
$score  = 0
$flags  = [System.Collections.Generic.List[hashtable]]::new()
$info   = [System.Collections.Generic.List[string]]::new()

function Add-Flag {
    param([string]$Title, [string]$Detail, [int]$Weight, [string]$Severity)
    $script:score += $Weight
    $script:flags.Add(@{ Title = $Title; Detail = $Detail; Weight = $Weight; Severity = $Severity })
}

function Add-Info {
    param([string]$Msg)
    $script:info.Add($Msg)
}

$banner = @"
  _____     _             ____       _            _
 |  ___|_ _| | _____ _ __|  _ \  ___| |_ ___  ___| |_
 | |_ / _` | |/ / _ \ '__| | | |/ _ \ __/ _ \/ __| __|
 |  _| (_| |   <  __/ |  | |_| |  __/ ||  __/ (__| |_
 |_|  \__,_|_|\_\___|_|  |____/ \___|\__\___|\___|\__|
"@

Write-Host $banner -ForegroundColor Cyan
Write-Host "  Minecraft Faker MITM Detector" -ForegroundColor White
Write-Host "  Targeting structural artifacts, not conventions.`n" -ForegroundColor DarkGray
#endregion

#region --- SIGNAL 1: java.exe -> private IP on :25565 [10pts] ---
Write-Host "[1/6] Checking Minecraft connection destination..." -ForegroundColor Yellow

try {
    $javaPIDs = (Get-Process -Name "javaw" -ErrorAction SilentlyContinue).Id

    if ($javaPIDs) {
        # use netstat with -n (numeric) -o (PID) -p TCP
        $netstatRaw = netstat -nop TCP 2>$null

        foreach ($line in $netstatRaw) {
            # match: proto  local:port  remote:port  state  pid
            if ($line -match "TCP\s+\S+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+ESTABLISHED\s+(\d+)") {
                $remoteIP   = $matches[1]
                $remotePort = [int]$matches[2]
                $pid        = [int]$matches[3]

                if ($pid -in $javaPIDs -and $remotePort -eq 25565) {
                    Add-Info "Minecraft (PID $pid) connected to ${remoteIP}:${remotePort}"

                    $isPrivate = $remoteIP -match `
                        "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.|^127\."

                    if ($isPrivate) {
                        Add-Flag `
                            -Title    "Minecraft connected to private IP on :25565" `
                            -Detail   "java.exe (PID $pid) has ESTABLISHED connection to ${remoteIP}:25565 - this is a local proxy, not a real server." `
                            -Weight   10 `
                            -Severity "CRITICAL"
                        Write-Host "  [CRITICAL] java.exe -> ${remoteIP}:25565 (private IP)" -ForegroundColor Red
                    } else {
                        Write-Host "  java.exe -> ${remoteIP}:25565 (public - normal)" -ForegroundColor Green
                    }
                }
            }
        }

        if (-not ($flags | Where-Object { $_.Title -like "*Minecraft connected*" })) {
            Write-Host "  No suspicious Minecraft connections found." -ForegroundColor Green
        }
    } else {
        Add-Info "java.exe not running - Minecraft not open."
        Write-Host "  java.exe not running." -ForegroundColor DarkGray
    }
} catch {
    Add-Info "Signal 1 error: $_"
}
#endregion

#region --- SIGNAL 2: This machine is hosting a Wi-Fi network [6pts] ---
Write-Host "[2/6] Checking if this machine is a hotspot host..." -ForegroundColor Yellow

try {
    # Check legacy hosted network
    $hostedRaw    = netsh wlan show hostednetwork 2>$null
    $hostedStatus = ($hostedRaw | Select-String "Status\s*:\s*(.+)").Matches.Groups[1].Value.Trim()
    $clientMatch  = ($hostedRaw | Select-String "Number of clients\s*:\s*(\d+)")
    $clientCount  = if ($clientMatch) { [int]$clientMatch.Matches.Groups[1].Value } else { 0 }

    # Check ICS (Internet Connection Sharing) / Mobile Hotspot
    $icssvc = Get-Service -Name "icssvc" -ErrorAction SilentlyContinue

    # Check for Wi-Fi Direct GO (Group Owner) mode - this machine is the AP
    $ifaceRaw = netsh wlan show interfaces 2>$null

    # Multiple interface blocks = multiple Wi-Fi connections (client + hosting)
    $ifaceBlocks = ($ifaceRaw | Select-String "Name\s*:").Count

    $isHosting = $false

    if ($hostedStatus -eq "Started") {
        $isHosting = $true
        Add-Info "Legacy hosted network active, clients: $clientCount"
        Add-Flag `
            -Title    "This machine is hosting a Wi-Fi network" `
            -Detail   "netsh reports hosted network is Started with $clientCount client(s). The 'clean' PC should not be an AP." `
            -Weight   6 `
            -Severity "HIGH"
        Write-Host "  [HIGH] Hosted network ACTIVE ($clientCount clients)" -ForegroundColor Red
    }

    if ($icssvc -and $icssvc.Status -eq "Running") {
        $score += 2
        $flags.Add(@{
            Title    = "Mobile Hotspot service (icssvc) running"
            Detail   = "Windows Internet Connection Sharing service is active. Not definitive alone but supports other signals."
            Weight   = 2
            Severity = "MEDIUM"
        })
        Write-Host "  [MEDIUM] icssvc is running" -ForegroundColor Yellow
        Add-Info "icssvc status: Running"
    } else {
        Write-Host "  icssvc: not running" -ForegroundColor Green
    }

    if ($ifaceBlocks -ge 2 -and -not $isHosting) {
        Add-Info "Multiple Wi-Fi interfaces active ($ifaceBlocks)"
        Add-Flag `
            -Title    "Multiple active Wi-Fi interfaces" `
            -Detail   "Machine has $ifaceBlocks active Wi-Fi interface entries. Could indicate simultaneous client + AP mode (Faker PC1 topology)." `
            -Weight   1 `
            -Severity "LOW"
        Write-Host "  [LOW] $ifaceBlocks active Wi-Fi interfaces" -ForegroundColor Yellow
    }

    if (-not $isHosting -and (-not $icssvc -or $icssvc.Status -ne "Running")) {
        Write-Host "  Not hosting a network." -ForegroundColor Green
    }
} catch {
    Add-Info "Signal 2 error: $_"
}
#endregion

#region --- SIGNAL 3: Double-NAT traceroute [5pts] ---
Write-Host "[3/6] Running traceroute (first 3 hops)..." -ForegroundColor Yellow

try {
    # Use Test-NetConnection if available, fall back to tracert parsing
    $hops = @()

    # tracert -d -h 3 is fast (no DNS, max 3 hops)
    $tracertRaw = tracert -d -h 3 1.1.1.1 2>$null

    foreach ($line in $tracertRaw) {
        if ($line -match "^\s+(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)\s*$") {
            $hops += $matches[2]
        } elseif ($line -match "^\s+(\d+)\s+\*") {
            $hops += "timeout"
        }
    }

    Add-Info "Traceroute hops: $($hops -join ' -> ')"
    Write-Host "  Hops: $($hops -join ' -> ')" -ForegroundColor DarkGray

    if ($hops.Count -ge 2) {
        $hop1IsPrivate = $hops[0] -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."
        $hop2IsPrivate = $hops[1] -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."

        if ($hop1IsPrivate -and $hop2IsPrivate) {
            Add-Flag `
                -Title    "Double-NAT detected (two private hops)" `
                -Detail   "Hop 1: $($hops[0]) | Hop 2: $($hops[1]) - both private. Traffic routes through two NAT layers, consistent with Faker's PC1 hotspot topology." `
                -Weight   5 `
                -Severity "HIGH"
            Write-Host "  [HIGH] Double-NAT: $($hops[0]) -> $($hops[1])" -ForegroundColor Red
        } elseif ($hop1IsPrivate -and -not $hop2IsPrivate) {
            Write-Host "  Single NAT (normal home router): $($hops[0]) -> $($hops[1])" -ForegroundColor Green
        }
    } else {
        Add-Info "Not enough hops returned to evaluate."
        Write-Host "  Not enough hops returned." -ForegroundColor DarkGray
    }
} catch {
    Add-Info "Signal 3 error: $_"
}
#endregion

#region --- SIGNAL 4: All DNS servers are private LAN IPs [4pts] ---
Write-Host "[4/6] Checking DNS server configuration..." -ForegroundColor Yellow

try {
    $allDNS = (Get-WmiObject Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled -and $_.DNSServerSearchOrder }) |
        ForEach-Object { $_.DNSServerSearchOrder } |
        Where-Object { $_ -and $_ -notmatch "^127\." } |
        Select-Object -Unique

    Add-Info "DNS servers: $($allDNS -join ', ')"
    Write-Host "  DNS servers: $($allDNS -join ', ')" -ForegroundColor DarkGray

    $publicDNS = $allDNS | Where-Object {
        -not ($_ -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.")
    }

    $privateDNS = $allDNS | Where-Object {
        $_ -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."
    }

    if ($privateDNS -and -not $publicDNS) {
        Add-Flag `
            -Title    "All DNS servers are private LAN IPs" `
            -Detail   "DNS servers: $($privateDNS -join ', '). No public DNS configured. Consistent with Faker's DHCP assigning PC1's hotspot IP as DNS resolver." `
            -Weight   4 `
            -Severity "MEDIUM"
        Write-Host "  [MEDIUM] All DNS is LAN-local: $($privateDNS -join ', ')" -ForegroundColor Yellow
    } else {
        Write-Host "  Public DNS present - normal." -ForegroundColor Green
    }
} catch {
    Add-Info "Signal 4 error: $_"
}
#endregion

#region --- SIGNAL 5: Default route gateway == DNS server [3pts] ---
Write-Host "[5/6] Checking default route and gateway/DNS match..." -ForegroundColor Yellow

try {
    $routeRaw = route print 0.0.0.0 2>$null
    $defaultGW = $null

    foreach ($line in $routeRaw) {
        if ($line -match "0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)") {
            $defaultGW = $matches[1]
            break
        }
    }

    Add-Info "Default gateway: $defaultGW"
    Write-Host "  Default gateway: $defaultGW" -ForegroundColor DarkGray

    if ($defaultGW) {
        $gwIsPrivate = $defaultGW -match "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."

        $dnsMatchesGW = (Get-WmiObject Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPEnabled -and $_.DNSServerSearchOrder }) |
            ForEach-Object { $_.DNSServerSearchOrder } |
            Where-Object { $_ -eq $defaultGW }

        if ($gwIsPrivate -and $dnsMatchesGW) {
            Add-Flag `
                -Title    "Default gateway == DNS server (Faker DHCP fingerprint)" `
                -Detail   "Gateway $defaultGW is also the DNS server. Faker's DHCP assigns itself (PC1's hotspot IP) as both gateway and DNS for PC2." `
                -Weight   3 `
                -Severity "MEDIUM"
            Write-Host "  [MEDIUM] Gateway $defaultGW is also DNS server" -ForegroundColor Yellow
        } elseif ($gwIsPrivate) {
            Write-Host "  Gateway is private but DNS does not match - not flagged." -ForegroundColor DarkGray
        } else {
            Write-Host "  Gateway is public-facing - normal." -ForegroundColor Green
        }
    }
} catch {
    Add-Info "Signal 5 error: $_"
}
#endregion

#region --- SIGNAL 6: Saved hotspot profiles in Wi-Fi history [info only] ---
Write-Host "[6/6] Checking Wi-Fi profile history..." -ForegroundColor Yellow

try {
    $profileRaw   = netsh wlan show profiles 2>$null
    $profileNames = $profileRaw | Select-String "All User Profile\s*:\s*(.+)" |
        ForEach-Object { $_.Matches.Groups[1].Value.Trim() }

    $suspectPatterns = @(
        'Android','iPhone','iPad','Galaxy','Pixel','OnePlus','Xiaomi',
        'Huawei','Oppo','Vivo','Realme','Nokia','Redmi','Mi ',
        'DIRECT-',"'s iPhone","'s Galaxy","'s Android"
    )

    $hotspotProfiles = $profileNames | Where-Object {
        $name = $_
        $suspectPatterns | Where-Object { $name -match $_ }
    }

    if ($hotspotProfiles) {
        Add-Info "Historical hotspot profiles: $($hotspotProfiles -join ', ')"
        Write-Host "  Historical hotspot profiles: $($hotspotProfiles -join ', ')" -ForegroundColor Yellow
        Write-Host "  (informational only - not scored)" -ForegroundColor DarkGray
    } else {
        Write-Host "  No historical hotspot profiles found." -ForegroundColor Green
    }
} catch {
    Add-Info "Signal 6 error: $_"
}
#endregion

#region --- VERDICT ---
Write-Host ""
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "  SCORE: $score" -ForegroundColor White

if ($score -ge $ScoreDetect) {
    $verdict        = "FAKER DETECTED"
    $verdictColor   = "Red"
    $verdictClass   = "verdict-bad"
} elseif ($score -ge $ScoreSuspect) {
    $verdict        = "SUSPICIOUS"
    $verdictColor   = "Yellow"
    $verdictClass   = "verdict-warn"
} else {
    $verdict        = "CLEAN"
    $verdictColor   = "Green"
    $verdictClass   = "verdict-ok"
}

Write-Host "  VERDICT: $verdict" -ForegroundColor $verdictColor
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""
#endregion

#region --- HTML REPORT ---
$flagsHTML = ""
foreach ($f in $flags) {
    $cls = switch ($f.Severity) {
        "CRITICAL" { "flag-critical" }
        "HIGH"     { "flag-high" }
        "MEDIUM"   { "flag-medium" }
        default    { "flag-low" }
    }
    $flagsHTML += @"
<div class="flag $cls">
    <span class="flag-severity">[$($f.Severity)]</span>
    <span class="flag-title">$($f.Title)</span>
    <span class="flag-weight">+$($f.Weight) pts</span>
    <p class="flag-detail">$($f.Detail)</p>
</div>
"@
}

$infoHTML = ($info | ForEach-Object { "<li>$_</li>" }) -join ""

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FakerDetect Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0f0f13; color: #e0e0e0; padding: 30px; }
  h1 { font-size: 1.6rem; color: #7dd3fc; margin-bottom: 4px; }
  .subtitle { color: #6b7280; font-size: 0.85rem; margin-bottom: 28px; }
  .verdict-box { border-radius: 10px; padding: 20px 28px; margin-bottom: 28px; display:flex; align-items:center; gap: 20px; }
  .verdict-bad  { background: #2d0b0b; border: 1px solid #ef4444; }
  .verdict-warn { background: #2d1f00; border: 1px solid #f59e0b; }
  .verdict-ok   { background: #0b2d14; border: 1px solid #22c55e; }
  .verdict-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #9ca3af; }
  .verdict-text-bad  { font-size: 2rem; font-weight: 700; color: #ef4444; }
  .verdict-text-warn { font-size: 2rem; font-weight: 700; color: #f59e0b; }
  .verdict-text-ok   { font-size: 2rem; font-weight: 700; color: #22c55e; }
  .score { font-size: 1.1rem; color: #9ca3af; }
  h2 { font-size: 1rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin: 24px 0 12px; }
  .flag { border-radius: 8px; padding: 14px 18px; margin-bottom: 10px; }
  .flag-critical { background: #1e0505; border-left: 4px solid #ef4444; }
  .flag-high     { background: #1e1005; border-left: 4px solid #f97316; }
  .flag-medium   { background: #1a1a05; border-left: 4px solid #eab308; }
  .flag-low      { background: #0f1a1a; border-left: 4px solid #06b6d4; }
  .flag-severity { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #9ca3af; margin-right: 8px; }
  .flag-title    { font-weight: 600; color: #f1f5f9; }
  .flag-weight   { float: right; font-size: 0.8rem; color: #64748b; }
  .flag-detail   { font-size: 0.85rem; color: #94a3b8; margin-top: 6px; }
  .no-flags      { color: #22c55e; font-size: 0.9rem; }
  ul.info-list   { list-style: none; font-size: 0.8rem; color: #4b5563; margin-top: 8px; }
  ul.info-list li { padding: 2px 0; }
  ul.info-list li::before { content: "› "; color: #374151; }
  .ts { color: #374151; font-size: 0.75rem; margin-top: 40px; }
</style>
</head>
<body>

<h1>FakerDetect Report</h1>
<p class="subtitle">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME</p>

<div class="verdict-box $verdictClass">
  <div>
    <div class="verdict-label">Verdict</div>
    <div class="verdict-text-$($verdictClass.Replace('verdict-',''))">$verdict</div>
  </div>
  <div class="score">Score: <strong>$score pts</strong><br><span style="font-size:0.75rem;color:#6b7280">Faker &ge;10 | Suspicious &ge;5 | Clean &lt;5</span></div>
</div>

<h2>Detection Flags</h2>
$(if ($flags.Count -gt 0) { $flagsHTML } else { '<p class="no-flags">No flags raised.</p>' })

<h2>Diagnostic Info</h2>
<ul class="info-list">$infoHTML</ul>

<p class="ts">FakerDetect — structural signal detection. Not bypassable by SSID renaming or gateway IP changes.</p>
</body>
</html>
"@

try {
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "Report saved: $OutputPath" -ForegroundColor Cyan
    Start-Process $OutputPath
} catch {
    Write-Host "Could not save report: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
