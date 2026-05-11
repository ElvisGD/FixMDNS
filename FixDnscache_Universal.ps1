[CmdletBinding()]
param(
  [ValidateSet("Minimal","Full")]
  [string]$RightsMode = "Minimal",

  [switch]$RestoreDohTemplates,

  [switch]$NoSystemFallback
)

function Assert-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p=New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Exécuter en tant qu'Administrateur."
  }
}

function Enable-Privileges {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class AdjPriv {
  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  internal static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError=true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, out long pluid);
  [StructLayout(LayoutKind.Sequential, Pack=1)]
  internal struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }
  [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const uint TOKEN_QUERY = 0x00000008;
  internal const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static void EnablePrivilege(string priv) {
    IntPtr htok;
    if(!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out htok))
      throw new Exception("OpenProcessToken failed");
    TokPriv1Luid tp; tp.Count = 1; tp.Luid = 0; tp.Attr = SE_PRIVILEGE_ENABLED;
    if(!LookupPrivilegeValue(null, priv, out tp.Luid))
      throw new Exception("LookupPrivilegeValue failed: " + priv);
    if(!AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
      throw new Exception("AdjustTokenPrivileges failed: " + priv);
  }
}
"@ -ErrorAction SilentlyContinue | Out-Null

  foreach($priv in "SeTakeOwnershipPrivilege","SeRestorePrivilege","SeBackupPrivilege"){
    try { [AdjPriv]::EnablePrivilege($priv); Write-Host "OK privilege: $priv" -ForegroundColor DarkGreen }
    catch { Write-Host "WARN privilege: $priv -> $($_.Exception.Message)" -ForegroundColor Yellow }
  }
}

function Ensure-Key([string]$Path){
  if(-not (Test-Path $Path)){ New-Item -Path $Path -Force | Out-Null }
}

function Set-ExpandString([string]$Path,[string]$Name,[string]$Value){
  New-ItemProperty -Path $Path -Name $Name -PropertyType ExpandString -Value $Value -Force | Out-Null
}
function Set-Dword([string]$Path,[string]$Name,[int]$Value){
  New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Get-Rights([string]$mode){
  if($mode -eq "Full"){ return [System.Security.AccessControl.RegistryRights]::FullControl }
  # one-liner (pas de backticks / pas de bug -bor)
  return ([System.Security.AccessControl.RegistryRights]::QueryValues -bor
          [System.Security.AccessControl.RegistryRights]::SetValue -bor
          [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor
          [System.Security.AccessControl.RegistryRights]::EnumerateSubKeys -bor
          [System.Security.AccessControl.RegistryRights]::Notify -bor
          [System.Security.AccessControl.RegistryRights]::ReadPermissions)
}

function New-RegRuleBySid([string]$Sid,[System.Security.AccessControl.RegistryRights]$Rights){
  $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
  New-Object System.Security.AccessControl.RegistryAccessRule(
    $sidObj,$Rights,"ContainerInherit,ObjectInherit","None","Allow"
  )
}

function Fix-AclOwnerTree([string]$RootKey,[string]$mode){
  $ownerNt = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
  $nsRule  = New-RegRuleBySid -Sid "S-1-5-20" -Rights (Get-Rights $mode) # NetworkService SID

  $keys = @($RootKey)
  $keys += (Get-ChildItem -Path $RootKey -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSPath)

  $errors = 0
  foreach($k in $keys){
    try {
      $acl = Get-Acl $k
      $acl.SetOwner($ownerNt)
      $acl.SetAccessRuleProtection($false,$true) # inheritance ON
      $acl.SetAccessRule($nsRule)
      Set-Acl -Path $k -AclObject $acl
    } catch {
      $errors++
      Write-Warning "ACL fail sur $k : $($_.Exception.Message)"
    }
  }
  return $errors
}

function Restore-DoHTemplates([string]$dohKey){
  $tpl = @{
    "1.0.0.1"              = "https://cloudflare-dns.com/dns-query"
    "1.1.1.1"              = "https://cloudflare-dns.com/dns-query"
    "2606:4700:4700::1001" = "https://cloudflare-dns.com/dns-query"
    "2606:4700:4700::1111" = "https://cloudflare-dns.com/dns-query"
    "8.8.8.8"              = "https://dns.google/dns-query"
    "8.8.4.4"              = "https://dns.google/dns-query"
    "2001:4860:4860::8888" = "https://dns.google/dns-query"
    "2001:4860:4860::8844" = "https://dns.google/dns-query"
    "9.9.9.9"              = "https://dns.quad9.net/dns-query"
    "149.112.112.112"      = "https://dns.quad9.net/dns-query"
    "2620:fe::9"           = "https://dns.quad9.net/dns-query"
    "2620:fe::fe"          = "https://dns.quad9.net/dns-query"
  } # issus de l'export d'une machine saine

  Ensure-Key $dohKey
  foreach($ip in $tpl.Keys){
    $k = Join-Path $dohKey $ip
    Ensure-Key $k
    New-ItemProperty -Path $k -Name "Template" -PropertyType String -Value $tpl[$ip] -Force | Out-Null
  }
}

function Try-StartDnscache {
  try { Start-Service Dnscache -ErrorAction Stop; Write-Host "Start-Service: OK" -ForegroundColor Green; return $true }
  catch { Write-Host "Start-Service: FAIL -> $($_.Exception.Message)" -ForegroundColor Red; return $false }
}

# ---------------- MAIN ----------------
Assert-Admin
Enable-Privileges

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null
$log = "C:\Temp\FixDnscache_Universal_$stamp.log"
Start-Transcript -Path $log -Force | Out-Null

$svcKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache"
$params  = "$svcKey\Parameters"
$dohKey  = "$params\DohWellKnownServers"

Write-Host "=== BEFORE ===" -ForegroundColor Cyan
Get-Service Dnscache | Format-List Name,Status,StartType
sc.exe queryex Dnscache

# 0) Ensure keys exist
Ensure-Key $svcKey
Ensure-Key $params

# 1) PRIORITY: supprimer EnableMDNS si =0
try {
  $pp = Get-ItemProperty $params -ErrorAction SilentlyContinue
  if($pp -and ($pp.PSObject.Properties.Name -contains "EnableMDNS") -and ([int]$pp.EnableMDNS -eq 0)){
    Remove-ItemProperty -Path $params -Name "EnableMDNS" -ErrorAction SilentlyContinue
    Write-Host "EnableMDNS=0 supprimé (retour défaut)." -ForegroundColor Green
  }
} catch {}

# 2) Restaurer valeurs indispensables (cause de 0x2 si absentes) 
Set-ExpandString $params "ServiceDll" "%SystemRoot%\System32\dnsrslvr.dll"
Set-ExpandString $params "extension"  "%SystemRoot%\System32\dnsext.dll"
Set-Dword        $params "ServiceDllUnloadOnStop" 1

# 3) Recréer sous-clés attendues (au minimum) 
@(
  "$params\DnsActiveIfs",
  "$params\DnsConnections",
  "$params\DnsConnectionsProxies",
  "$params\DnsPolicyConfig",
  "$params\Probe",
  "$params\ZTDNS",
  $dohKey
) | ForEach-Object { Ensure-Key $_ }

# Optionnel: restaurer templates DoH 
if($RestoreDohTemplates){
  Restore-DoHTemplates $dohKey
  Write-Host "Templates DoH restaurés." -ForegroundColor Green
}

# 4) Fix ACL/Owner (cause de 0x5 si Owner/NSRule cassés)
Write-Host "=== FIX ACL/OWNER ($RightsMode) ===" -ForegroundColor Cyan
$err = Fix-AclOwnerTree -RootKey $params -mode $RightsMode
Write-Host "ACL errors: $err" -ForegroundColor Cyan

# 5) Try start
Write-Host "=== TRY START DNSCACHE ===" -ForegroundColor Cyan
$ok = Try-StartDnscache
Get-Service Dnscache | Format-List Name,Status,StartType
sc.exe queryex Dnscache

# 6) Fallback SYSTEM si encore KO (pour les cas où SetOwner est refusé en admin)
if(-not $ok -and -not $NoSystemFallback){
  Write-Host "=== FALLBACK SYSTEM (Scheduled Task) ===" -ForegroundColor Yellow

  $task = "FIX_DNSCACHE_SYSTEM_$stamp"
  $sysScript = "C:\Temp\FixDnscache_SYSTEM_$stamp.ps1"
  $sysLog = "C:\Temp\FixDnscache_SYSTEM_$stamp.out.txt"

  @"
`$ErrorActionPreference='Continue'
Start-Transcript -Path '$sysLog' -Force | Out-Null
try{
  'WHOAMI=' + (whoami)
  `$params='$params'
  function Get-Rights([string]`$mode){
    if(`$mode -eq 'Full'){ return [System.Security.AccessControl.RegistryRights]::FullControl }
    return ([System.Security.AccessControl.RegistryRights]::QueryValues -bor [System.Security.AccessControl.RegistryRights]::SetValue -bor [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor [System.Security.AccessControl.RegistryRights]::EnumerateSubKeys -bor [System.Security.AccessControl.RegistryRights]::Notify -bor [System.Security.AccessControl.RegistryRights]::ReadPermissions)
  }
  function New-RegRuleBySid([string]`$Sid,[System.Security.AccessControl.RegistryRights]`$Rights){
    `$sidObj = New-Object System.Security.Principal.SecurityIdentifier(`$Sid)
    New-Object System.Security.AccessControl.RegistryAccessRule(`$sidObj,`$Rights,'ContainerInherit,ObjectInherit','None','Allow')
  }
  # Assure valeurs essentielles 
  New-Item -Path `$params -Force | Out-Null
  New-ItemProperty -Path `$params -Name 'ServiceDll' -PropertyType ExpandString -Value '%SystemRoot%\System32\dnsrslvr.dll' -Force | Out-Null
  New-ItemProperty -Path `$params -Name 'extension' -PropertyType ExpandString -Value '%SystemRoot%\System32\dnsext.dll' -Force | Out-Null
  New-ItemProperty -Path `$params -Name 'ServiceDllUnloadOnStop' -PropertyType DWord -Value 1 -Force | Out-Null

  # ACL/Owner
  `$ownerNt = New-Object System.Security.Principal.NTAccount('NT AUTHORITY\SYSTEM')
  `$nsRule = New-RegRuleBySid -Sid 'S-1-5-20' -Rights (Get-Rights '$RightsMode')
  `$keys = @(`$params)
  `$keys += (Get-ChildItem -Path `$params -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSPath)
  foreach(`$k in `$keys){
    try{
      `$acl = Get-Acl `$k
      `$acl.SetOwner(`$ownerNt)
      `$acl.SetAccessRuleProtection(`$false,`$true)
      `$acl.SetAccessRule(`$nsRule)
      Set-Acl -Path `$k -AclObject `$acl
    } catch { 'WARN ' + `$k + ' -> ' + `$_.Exception.Message }
  }

  try{ Remove-ItemProperty -Path `$params -Name 'EnableMDNS' -ErrorAction SilentlyContinue } catch {}

  'TRY START'
  try{ Start-Service Dnscache -ErrorAction Stop; 'Start-Service OK' } catch { 'Start-Service FAIL -> ' + `$_.Exception.Message }
  Get-Service Dnscache | Format-List Name,Status,StartType
  sc.exe queryex Dnscache
} finally { Stop-Transcript | Out-Null }
"@ | Set-Content -Path $sysScript -Encoding UTF8

  $st = (Get-Date).AddMinutes(1).ToString('HH:mm')
  schtasks /create /tn $task /sc once /st $st /f /rl highest /ru "SYSTEM" /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$sysScript`"" | Out-Null
  schtasks /run /tn $task | Out-Null

  for($i=0;$i -lt 60;$i++){ if(Test-Path $sysLog){ break }; Start-Sleep 1 }
  Write-Host "=== SYSTEM LOG ===" -ForegroundColor Cyan
  if(Test-Path $sysLog){ Get-Content $sysLog } else { Write-Warning "Log SYSTEM introuvable: $sysLog" }

  schtasks /delete /tn $task /f | Out-Null
}

Write-Host "=== FINAL STATE ===" -ForegroundColor Cyan
Get-Service Dnscache | Format-List Name,Status,StartType
sc.exe queryex Dnscache

Stop-Transcript | Out-Null
Write-Host "Log: $log" -ForegroundColor Green
