#Requires -Modules ActiveDirectory
# =============================================================================
# CCDC AD Privilege Remediation Script
# Fixes the most dangerous automatically-remediable findings.
# Each section is controlled by a boolean parameter.
# =============================================================================

param(
    [string]$FixAsRepRoasting     = "true",
    [string]$FixUnconstrainedDeleg = "true",
    [string]$FixPreWin2kGroup     = "true",
    [string]$ClearShadowKeys      = "true",
    [string]$OutputPath           = "C:\Windows\Temp\ad_remediate_log.txt"
)

# Convert string args to booleans (handles "true"/"false"/"1"/"0" from Ansible)
$FixAsRepRoasting     = $FixAsRepRoasting     -in @("true","1","yes")
$FixUnconstrainedDeleg = $FixUnconstrainedDeleg -in @("true","1","yes")
$FixPreWin2kGroup     = $FixPreWin2kGroup     -in @("true","1","yes")
$ClearShadowKeys      = $ClearShadowKeys      -in @("true","1","yes")

Import-Module ActiveDirectory -ErrorAction Stop

$log = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Msg)
    $entry = "$(Get-Date -Format 'HH:mm:ss') $Msg"
    $log.Add($entry)
    Write-Output $entry
}

$domain   = Get-ADDomain
$dcAccounts = (Get-ADDomainController -Filter *).ComputerObjectDN

Write-Log "=== CCDC AD Remediation Started ==="
Write-Log "Domain: $($domain.DNSRoot)"

# =============================================================================
# FIX 1: AS-REP Roasting - enable Kerberos pre-authentication
# =============================================================================
if ($FixAsRepRoasting) {
    Write-Log "--- Fix 1: AS-REP Roasting ---"
    $targets = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $True -and Enabled -eq $True } `
        -Properties DoesNotRequirePreAuth -ErrorAction SilentlyContinue

    foreach ($u in $targets) {
        try {
            Set-ADAccountControl -Identity $u -DoesNotRequirePreAuth $false
            Write-Log "  FIXED: Enabled Kerberos pre-auth for $($u.SamAccountName)"
        } catch {
            Write-Log "  ERROR: Could not fix $($u.SamAccountName): $($_.Exception.Message)"
        }
    }
    if (-not $targets) { Write-Log "  SKIP: No AS-REP roastable accounts found" }
}

# =============================================================================
# FIX 2: Unconstrained delegation on non-DC computer accounts
# =============================================================================
if ($FixUnconstrainedDeleg) {
    Write-Log "--- Fix 2: Unconstrained Delegation (non-DCs) ---"
    $targets = Get-ADComputer -Filter { TrustedForDelegation -eq $True } `
        -Properties TrustedForDelegation -ErrorAction SilentlyContinue |
        Where-Object { $_.DistinguishedName -notin $dcAccounts }

    foreach ($c in $targets) {
        try {
            Set-ADComputer -Identity $c -TrustedForDelegation $false
            Write-Log "  FIXED: Removed unconstrained delegation from $($c.Name)"
        } catch {
            Write-Log "  ERROR: Could not fix $($c.Name): $($_.Exception.Message)"
        }
    }
    if (-not $targets) { Write-Log "  SKIP: No non-DC unconstrained delegation found" }

    # Also fix user accounts with unconstrained delegation
    $userTargets = Get-ADUser -Filter { TrustedForDelegation -eq $True } `
        -Properties TrustedForDelegation -ErrorAction SilentlyContinue
    foreach ($u in $userTargets) {
        try {
            Set-ADAccountControl -Identity $u -TrustedForDelegation $false
            Write-Log "  FIXED: Removed unconstrained delegation from user $($u.SamAccountName)"
        } catch {
            Write-Log "  ERROR: Could not fix user $($u.SamAccountName): $($_.Exception.Message)"
        }
    }
}

# =============================================================================
# FIX 3: Remove Everyone/Authenticated Users from Pre-Windows 2000 Compatible Access
# =============================================================================
if ($FixPreWin2kGroup) {
    Write-Log "--- Fix 3: Pre-Windows 2000 Compatible Access ---"
    $dangerousMembers = @('Everyone', 'Authenticated Users', 'Anonymous Logon')

    foreach ($memberName in $dangerousMembers) {
        try {
            $member = Get-ADObject -Filter { Name -eq $memberName } -ErrorAction SilentlyContinue
            if (-not $member) {
                # Try resolving as well-known SID
                $sidMap = @{
                    'Everyone'             = 'S-1-1-0'
                    'Authenticated Users'  = 'S-1-5-11'
                    'Anonymous Logon'      = 'S-1-5-7'
                }
                if ($sidMap[$memberName]) {
                    Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' `
                        -Members $sidMap[$memberName] -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Log "  FIXED: Attempted removal of '$memberName' from Pre-Win2k group (by SID)"
                }
            } else {
                Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' `
                    -Members $member -Confirm:$false -ErrorAction SilentlyContinue
                Write-Log "  FIXED: Removed '$memberName' from Pre-Win2k group"
            }
        } catch {
            Write-Log "  INFO: '$memberName' not in group or already removed"
        }
    }
}

# =============================================================================
# FIX 4: Clear shadow credentials (msDS-KeyCredentialLink) from non-DC accounts
# =============================================================================
if ($ClearShadowKeys) {
    Write-Log "--- Fix 4: Shadow Credentials ---"
    $shadowUsers = Get-ADUser -Filter * -Properties 'msDS-KeyCredentialLink' -ErrorAction SilentlyContinue |
        Where-Object { $_.'msDS-KeyCredentialLink'.Count -gt 0 }

    $shadowComps = Get-ADComputer -Filter * -Properties 'msDS-KeyCredentialLink' -ErrorAction SilentlyContinue |
        Where-Object { $_.'msDS-KeyCredentialLink'.Count -gt 0 -and $_.DistinguishedName -notin $dcAccounts }

    foreach ($obj in @($shadowUsers) + @($shadowComps) | Where-Object { $_ }) {
        try {
            Set-ADObject -Identity $obj -Clear 'msDS-KeyCredentialLink'
            Write-Log "  FIXED: Cleared shadow credentials from $($obj.SamAccountName)"
        } catch {
            Write-Log "  ERROR: Could not clear shadow creds from $($obj.SamAccountName): $($_.Exception.Message)"
        }
    }
    if (-not ($shadowUsers -or $shadowComps)) { Write-Log "  SKIP: No shadow credentials found" }
}

Write-Log "=== Remediation Complete ==="
$log | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-Output "REMEDIATION_DONE"
