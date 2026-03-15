#Requires -Modules ActiveDirectory
# =============================================================================
# CCDC AD Privilege Audit Script
# Enumerates all privilege escalation paths an attacker could abuse.
# Output: structured text report at $OutputPath
# =============================================================================

param(
    [string]$OutputPath = "C:\Windows\Temp\ad_audit_report.txt"
)

Import-Module ActiveDirectory -ErrorAction Stop

$report  = [System.Collections.Generic.List[string]]::new()
$DIVIDER = "=" * 70

function Write-Section {
    param([string]$Title)
    $report.Add("")
    $report.Add($DIVIDER)
    $report.Add("  $Title")
    $report.Add($DIVIDER)
}

function Write-Finding {
    param([string]$Severity, [string]$Text)
    $report.Add("  [$Severity] $Text")
}

function Write-Detail {
    param([string]$Text)
    $report.Add("        $Text")
}

$domain     = Get-ADDomain
$domainDN   = $domain.DistinguishedName
$domainSID  = $domain.DomainSID.Value
$dcAccounts = (Get-ADDomainController -Filter *).ComputerObjectDN

$report.Add("CCDC Active Directory Privilege Audit Report")
$report.Add("Domain : $($domain.DNSRoot)  ($domainDN)")
$report.Add("Run at : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$report.Add("")

# =============================================================================
# 1. Privileged Group Membership
# =============================================================================
Write-Section "1. PRIVILEGED GROUP MEMBERSHIP"

$privGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Backup Operators',
    'Account Operators',
    'Server Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
    'Remote Management Users',
    'Cert Publishers',
    'Exchange Windows Permissions',      # Gives DCSync rights via Exchange
    'Exchange Trusted Subsystem'
)

foreach ($groupName in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop
        if ($members.Count -gt 0) {
            $severity = if ($groupName -in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')) { "HIGH" } else { "MED" }
            Write-Finding $severity "$groupName ($($members.Count) members):"
            foreach ($m in $members) {
                $details = @()
                if ($m.objectClass -eq 'user') {
                    $u = Get-ADUser -Identity $m.SamAccountName -Properties Enabled, PasswordLastSet, LastLogonDate, PasswordNeverExpires -ErrorAction SilentlyContinue
                    if ($u) {
                        $status  = if ($u.Enabled) { "ENABLED" } else { "DISABLED" }
                        $pwAge   = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays)d ago" } else { "NEVER SET" }
                        $lastLog = if ($u.LastLogonDate) { "$([int]((Get-Date) - $u.LastLogonDate).TotalDays)d ago" } else { "NEVER" }
                        $pwNE    = if ($u.PasswordNeverExpires) { " [PW-NEVER-EXPIRES]" } else { "" }
                        Write-Detail "$($m.SamAccountName) [$status] pw:$pwAge lastlogon:$lastLog$pwNE"
                    }
                } else {
                    Write-Detail "$($m.SamAccountName) [$($m.objectClass)]"
                }
            }
        } else {
            Write-Finding "INFO" "$groupName - empty"
        }
    } catch {
        Write-Finding "INFO" "$groupName - not found or error: $($_.Exception.Message)"
    }
}

# =============================================================================
# 2. AS-REP Roastable Accounts (no Kerberos pre-auth required)
# =============================================================================
Write-Section "2. AS-REP ROASTABLE ACCOUNTS (DONT_REQ_PREAUTH)"

$asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $True -and Enabled -eq $True } `
    -Properties DoesNotRequirePreAuth, PasswordLastSet, MemberOf -ErrorAction SilentlyContinue

if ($asrepUsers) {
    Write-Finding "CRITICAL" "$($asrepUsers.Count) account(s) have pre-auth disabled - AS-REP roast target:"
    foreach ($u in $asrepUsers) {
        $pwAge = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays)d ago" } else { "NEVER" }
        Write-Detail "$($u.SamAccountName) - pw set: $pwAge"
    }
} else {
    Write-Finding "OK" "No AS-REP roastable accounts found"
}

# =============================================================================
# 3. Kerberoastable Accounts (user accounts with SPNs)
# =============================================================================
Write-Section "3. KERBEROASTABLE USER ACCOUNTS (SPN on user objects)"

$kerbUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" -and Enabled -eq $True } `
    -Properties ServicePrincipalName, PasswordLastSet, AdminCount, 'msDS-SupportedEncryptionTypes' -ErrorAction SilentlyContinue

if ($kerbUsers) {
    Write-Finding "HIGH" "$($kerbUsers.Count) user account(s) have SPNs - Kerberoast targets:"
    foreach ($u in $kerbUsers) {
        $pwAge   = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays)d ago" } else { "NEVER" }
        $encType = $u.'msDS-SupportedEncryptionTypes'
        $rc4     = if (-not $encType -or ($encType -band 4)) { " [RC4-VULNERABLE]" } else { "" }
        $admin   = if ($u.AdminCount -eq 1) { " [AdminCount=1]" } else { "" }
        Write-Finding "HIGH" "$($u.SamAccountName) - pw:$pwAge$rc4$admin"
        $u.ServicePrincipalName | ForEach-Object { Write-Detail "  SPN: $_" }
    }
} else {
    Write-Finding "OK" "No user accounts with SPNs found"
}

# =============================================================================
# 4. Unconstrained Delegation (non-DCs)
# =============================================================================
Write-Section "4. UNCONSTRAINED DELEGATION (non-Domain Controllers)"

$unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $True } `
    -Properties TrustedForDelegation, OperatingSystem, DNSHostName -ErrorAction SilentlyContinue |
    Where-Object { $_.DistinguishedName -notin $dcAccounts }

if ($unconstrained) {
    Write-Finding "CRITICAL" "$($unconstrained.Count) non-DC computer(s) with unconstrained delegation:"
    foreach ($c in $unconstrained) {
        Write-Detail "$($c.Name) ($($c.OperatingSystem)) - $($c.DNSHostName)"
    }
} else {
    Write-Finding "OK" "No non-DC computers with unconstrained delegation"
}

# Also check users with unconstrained delegation (unusual)
$unconstrainedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $True } `
    -Properties TrustedForDelegation -ErrorAction SilentlyContinue
if ($unconstrainedUsers) {
    Write-Finding "CRITICAL" "$($unconstrainedUsers.Count) user account(s) with unconstrained delegation:"
    foreach ($u in $unconstrainedUsers) { Write-Detail $u.SamAccountName }
}

# =============================================================================
# 5. Constrained Delegation with Protocol Transition (T2A4 - can impersonate any user)
# =============================================================================
Write-Section "5. CONSTRAINED DELEGATION WITH PROTOCOL TRANSITION (TrustedToAuthForDelegation)"

$t2a4Users = Get-ADUser -Filter { TrustedToAuthForDelegation -eq $True } `
    -Properties TrustedToAuthForDelegation, 'msDS-AllowedToDelegateTo' -ErrorAction SilentlyContinue
$t2a4Comps = Get-ADComputer -Filter { TrustedToAuthForDelegation -eq $True } `
    -Properties TrustedToAuthForDelegation, 'msDS-AllowedToDelegateTo' -ErrorAction SilentlyContinue

$t2a4All = @($t2a4Users) + @($t2a4Comps) | Where-Object { $_ }
if ($t2a4All.Count -gt 0) {
    Write-Finding "HIGH" "$($t2a4All.Count) object(s) with protocol transition delegation:"
    foreach ($obj in $t2a4All) {
        Write-Detail "$($obj.Name) can impersonate ANY user to:"
        $obj.'msDS-AllowedToDelegateTo' | ForEach-Object { Write-Detail "  -> $_" }
    }
} else {
    Write-Finding "OK" "No protocol transition delegation found"
}

# =============================================================================
# 6. Resource-Based Constrained Delegation (RBCD) - msDS-AllowedToActOnBehalfOfOtherIdentity
# =============================================================================
Write-Section "6. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)"

$rbcdObjects = Get-ADObject -Filter { 'msDS-AllowedToActOnBehalfOfOtherIdentity' -like '*' } `
    -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity', DistinguishedName -SearchBase $domainDN -ErrorAction SilentlyContinue

if ($rbcdObjects) {
    Write-Finding "HIGH" "$($rbcdObjects.Count) object(s) have RBCD configured:"
    foreach ($obj in $rbcdObjects) {
        try {
            $sd  = New-Object Security.AccessControl.RawSecurityDescriptor(
                $obj.'msDS-AllowedToActOnBehalfOfOtherIdentity', 0)
            $who = $sd.DiscretionaryAcl | ForEach-Object {
                try { (New-Object Security.Principal.SecurityIdentifier($_.SecurityIdentifier)).Translate([Security.Principal.NTAccount]).Value } catch { $_.SecurityIdentifier.ToString() }
            }
            Write-Detail "$($obj.DistinguishedName)"
            Write-Detail "  Trusted actors: $($who -join ', ')"
        } catch {
            Write-Detail "$($obj.DistinguishedName) - error parsing SD"
        }
    }
} else {
    Write-Finding "OK" "No RBCD configurations found"
}

# =============================================================================
# 7. DCSync Rights (Replication permissions on domain NC root)
# =============================================================================
Write-Section "7. DCSYNC RIGHTS (Replication ACEs on domain root)"

# DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
$replicaGUID    = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$replicaAllGUID = [Guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'

try {
    $acl = Get-ACL "AD:\$domainDN" -ErrorAction Stop
    $syncACEs = $acl.Access | Where-Object {
        ($_.ObjectType -eq $replicaGUID -or $_.ObjectType -eq $replicaAllGUID) -and
        $_.AccessControlType -eq 'Allow'
    }

    # Exclude well-known safe principals
    $safeSIDs = @(
        'S-1-5-18',          # SYSTEM
        "$domainSID-498",    # Enterprise Read-Only Domain Controllers
        "$domainSID-516",    # Domain Controllers
        "$domainSID-521",    # Read-Only Domain Controllers
        'S-1-5-32-544'       # Builtin\Administrators
    )

    $dangerousACEs = $syncACEs | Where-Object {
        $sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $sid -notin $safeSIDs -and
        -not ($sid -match "$domainSID-(5[0-1][0-9]|5[2-9][0-9]|[6-9][0-9]{2})")  # Exclude high domain-SID RIDs (Cert Publishers etc.)
    }

    # Always show EA, DA for reference
    Write-Finding "INFO" "All replication ACEs ($(($syncACEs).Count) total):"
    $syncACEs | ForEach-Object {
        $typeLabel = if ($_.ObjectType -eq $replicaAllGUID) { "Get-Changes-ALL" } else { "Get-Changes" }
        Write-Detail "$($_.IdentityReference) [$typeLabel]"
    }

    if ($dangerousACEs) {
        Write-Finding "CRITICAL" "$($dangerousACEs.Count) unexpected principal(s) with DCSync rights:"
        $dangerousACEs | ForEach-Object {
            $typeLabel = if ($_.ObjectType -eq $replicaAllGUID) { "Get-Changes-ALL" } else { "Get-Changes" }
            Write-Detail "$($_.IdentityReference) [$typeLabel]"
        }
    } else {
        Write-Finding "OK" "No unexpected DCSync rights found"
    }
} catch {
    Write-Finding "ERR" "Could not read domain ACL: $($_.Exception.Message)"
}

# =============================================================================
# 8. AdminSDHolder ACE Audit
#    Non-standard ACEs here propagate to all AdminCount=1 accounts
# =============================================================================
Write-Section "8. ADMINSDHOLDER OBJECT - CUSTOM ACES"

try {
    $sdHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    $acl = Get-ACL "AD:\$sdHolderDN" -ErrorAction Stop

    $safeIdentities = @(
        'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT AUTHORITY\SELF',
        'Everyone', 'NT AUTHORITY\Authenticated Users',
        "$($domain.NetBIOSName)\Domain Admins",
        "$($domain.NetBIOSName)\Enterprise Admins",
        "$($domain.NetBIOSName)\Administrators"
    )

    $customACEs = $acl.Access | Where-Object {
        $_.IdentityReference.Value -notin $safeIdentities -and
        $_.AccessControlType -eq 'Allow'
    }

    if ($customACEs) {
        Write-Finding "CRITICAL" "$($customACEs.Count) non-standard ACE(s) on AdminSDHolder (propagates to all protected accounts):"
        $customACEs | ForEach-Object {
            Write-Detail "$($_.IdentityReference) - $($_.ActiveDirectoryRights)"
        }
    } else {
        Write-Finding "OK" "AdminSDHolder has no unexpected ACEs"
    }
} catch {
    Write-Finding "ERR" "Could not read AdminSDHolder ACL: $($_.Exception.Message)"
}

# =============================================================================
# 9. AdminCount=1 Orphan Accounts (protected but not currently in privileged group)
# =============================================================================
Write-Section "9. ORPHAN ADMINCOUNT=1 ACCOUNTS"

$adminCountAccounts = Get-ADUser -Filter { AdminCount -eq 1 } `
    -Properties AdminCount, Enabled, MemberOf, PasswordLastSet -ErrorAction SilentlyContinue

$allPrivGroupDNs = foreach ($gName in $privGroups) {
    try { (Get-ADGroup -Identity $gName -ErrorAction SilentlyContinue).DistinguishedName } catch {}
}

$orphans = $adminCountAccounts | Where-Object {
    $memberOfDNs = $_.MemberOf
    -not ($memberOfDNs | Where-Object { $_ -in $allPrivGroupDNs })
}

if ($orphans) {
    Write-Finding "HIGH" "$($orphans.Count) account(s) with AdminCount=1 not in any privileged group (inherited permissions may linger):"
    foreach ($u in $orphans) {
        $status = if ($u.Enabled) { "ENABLED" } else { "DISABLED" }
        Write-Detail "$($u.SamAccountName) [$status]"
    }
} else {
    Write-Finding "OK" "No orphan AdminCount=1 accounts"
}

# Also list ALL AdminCount=1 accounts for reference
Write-Finding "INFO" "All AdminCount=1 accounts ($($adminCountAccounts.Count) total):"
foreach ($u in $adminCountAccounts) {
    $status = if ($u.Enabled) { "ENABLED" } else { "DISABLED" }
    Write-Detail "$($u.SamAccountName) [$status]"
}

# =============================================================================
# 10. SID History
# =============================================================================
Write-Section "10. SID HISTORY (potential privilege escalation via legacy SIDs)"

$sidHistoryObjects = Get-ADUser -Filter * -Properties SIDHistory -ErrorAction SilentlyContinue |
    Where-Object { $_.SIDHistory.Count -gt 0 }

$sidHistoryObjects += Get-ADGroup -Filter * -Properties SIDHistory -ErrorAction SilentlyContinue |
    Where-Object { $_.SIDHistory.Count -gt 0 }

if ($sidHistoryObjects) {
    Write-Finding "HIGH" "$($sidHistoryObjects.Count) object(s) with SID history:"
    foreach ($obj in $sidHistoryObjects) {
        Write-Detail "$($obj.SamAccountName):"
        foreach ($sid in $obj.SIDHistory) {
            # Flag DA/EA-equivalent SIDs
            $ridStr = ($sid -split '-')[-1]
            $dangerous = $ridStr -in @('500','512','518','519','544')
            $label = if ($dangerous) { " [DANGEROUS - DA/EA/ADMIN-EQUIVALENT]" } else { "" }
            Write-Detail "  SID: $sid$label"
        }
    }
} else {
    Write-Finding "OK" "No objects with SID history found"
}

# =============================================================================
# 11. Shadow Credentials (msDS-KeyCredentialLink)
# =============================================================================
Write-Section "11. SHADOW CREDENTIALS (msDS-KeyCredentialLink)"

$shadowUsers = Get-ADUser -Filter * -Properties 'msDS-KeyCredentialLink' -ErrorAction SilentlyContinue |
    Where-Object { $_.'msDS-KeyCredentialLink'.Count -gt 0 }

$shadowComps = Get-ADComputer -Filter * -Properties 'msDS-KeyCredentialLink' -ErrorAction SilentlyContinue |
    Where-Object { $_.'msDS-KeyCredentialLink'.Count -gt 0 }

$shadowAll = @($shadowUsers) + @($shadowComps) | Where-Object { $_ }
if ($shadowAll.Count -gt 0) {
    Write-Finding "CRITICAL" "$($shadowAll.Count) object(s) have shadow credentials set (backdoor cert-based auth):"
    foreach ($obj in $shadowAll) {
        Write-Detail "$($obj.SamAccountName) ($($obj.ObjectClass)) - $($_.'msDS-KeyCredentialLink'.Count) credential(s)"
    }
} else {
    Write-Finding "OK" "No shadow credentials found"
}

# =============================================================================
# 12. Pre-Windows 2000 Compatible Access Group
# =============================================================================
Write-Section "12. PRE-WINDOWS 2000 COMPATIBLE ACCESS GROUP"

try {
    $preWin2k = Get-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -ErrorAction Stop
    if ($preWin2k) {
        $dangerous = $preWin2k | Where-Object { $_.Name -in @('Everyone', 'Authenticated Users', 'Anonymous Logon') }
        if ($dangerous) {
            Write-Finding "CRITICAL" "Dangerous members in Pre-Windows 2000 Compatible Access (allows unauthenticated LDAP enumeration):"
            $dangerous | ForEach-Object { Write-Detail $_.Name }
        } else {
            Write-Finding "MED" "$($preWin2k.Count) member(s) in Pre-Windows 2000 Compatible Access:"
            $preWin2k | ForEach-Object { Write-Detail $_.Name }
        }
    } else {
        Write-Finding "OK" "Pre-Windows 2000 Compatible Access group is empty"
    }
} catch {
    Write-Finding "INFO" "Pre-Windows 2000 Compatible Access group not found or empty"
}

# =============================================================================
# 13. Accounts with Password Never Expires (in privileged context)
# =============================================================================
Write-Section "13. PRIVILEGED ACCOUNTS WITH PASSWORD NEVER EXPIRES"

$pwNeverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $True -and Enabled -eq $True } `
    -Properties PasswordNeverExpires, AdminCount, PasswordLastSet, MemberOf -ErrorAction SilentlyContinue |
    Where-Object { $_.AdminCount -eq 1 -or ($_.MemberOf | Where-Object { $_ -in $allPrivGroupDNs }) }

if ($pwNeverExpires) {
    Write-Finding "HIGH" "$($pwNeverExpires.Count) privileged account(s) with password never expires:"
    foreach ($u in $pwNeverExpires) {
        $pwAge = if ($u.PasswordLastSet) { "$([int]((Get-Date) - $u.PasswordLastSet).TotalDays)d ago" } else { "NEVER" }
        Write-Detail "$($u.SamAccountName) - pw set: $pwAge"
    }
} else {
    Write-Finding "OK" "No privileged accounts with password never expires"
}

# =============================================================================
# 14. Stale Privileged Accounts (not logged in recently)
# =============================================================================
Write-Section "14. STALE PRIVILEGED ACCOUNTS (logon > 90 days)"

$staleCutoff = (Get-Date).AddDays(-90)
$stalePriv = Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $True } `
    -Properties LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue |
    Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt $staleCutoff }

if ($stalePriv) {
    Write-Finding "MED" "$($stalePriv.Count) privileged account(s) with no recent logon (>90 days or never):"
    foreach ($u in $stalePriv) {
        $lastLog = if ($u.LastLogonDate) { "$([int]((Get-Date) - $u.LastLogonDate).TotalDays)d ago" } else { "NEVER" }
        Write-Detail "$($u.SamAccountName) - last logon: $lastLog"
    }
} else {
    Write-Finding "OK" "No stale privileged accounts"
}

# =============================================================================
# 15. Disabled Privileged Accounts (could be re-enabled by attacker)
# =============================================================================
Write-Section "15. DISABLED PRIVILEGED ACCOUNTS"

$disabledPriv = Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $False } `
    -Properties AdminCount, PasswordLastSet -ErrorAction SilentlyContinue

if ($disabledPriv) {
    Write-Finding "MED" "$($disabledPriv.Count) disabled account(s) with AdminCount=1 (attacker could re-enable):"
    foreach ($u in $disabledPriv) { Write-Detail $u.SamAccountName }
} else {
    Write-Finding "OK" "No disabled privileged accounts found"
}

# =============================================================================
# 16. GPO Write Permissions (non-admin accounts that can modify GPOs)
# =============================================================================
Write-Section "16. GPO WRITE ACCESS BY NON-ADMINS"

try {
    $gpos = Get-GPO -All -ErrorAction Stop
    $gpoFindings = @()

    foreach ($gpo in $gpos) {
        try {
            $gpoPath = "AD:\CN=\{$($gpo.Id)\},CN=Policies,CN=System,$domainDN"
            $acl = Get-ACL $gpoPath -ErrorAction SilentlyContinue
            if (-not $acl) { continue }

            $writePerm = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor
                         [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor
                         [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor
                         [System.DirectoryServices.ActiveDirectoryRights]::GenericAll

            $dangerousGPOACEs = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                ($_.ActiveDirectoryRights -band $writePerm) -and
                $_.IdentityReference.Value -notin @(
                    'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators',
                    'CREATOR OWNER',
                    "$($domain.NetBIOSName)\Domain Admins",
                    "$($domain.NetBIOSName)\Enterprise Admins",
                    "$($domain.NetBIOSName)\Group Policy Creator Owners",
                    "NT AUTHORITY\Authenticated Users"  # Read-only on most GPOs
                )
            }

            if ($dangerousGPOACEs) {
                $gpoFindings += "  GPO: '$($gpo.DisplayName)' [$($gpo.Id)]"
                $dangerousGPOACEs | ForEach-Object {
                    $gpoFindings += "      $($_.IdentityReference) - $($_.ActiveDirectoryRights)"
                }
            }
        } catch {}
    }

    if ($gpoFindings.Count -gt 0) {
        Write-Finding "HIGH" "GPOs writable by non-admin accounts:"
        $gpoFindings | ForEach-Object { $report.Add($_) }
    } else {
        Write-Finding "OK" "No GPOs writable by non-admin accounts"
    }
} catch {
    Write-Finding "INFO" "GroupPolicy module not available or error: $($_.Exception.Message)"
}

# =============================================================================
# 17. High-Privilege Accounts NOT in Protected Users Group
# =============================================================================
Write-Section "17. DA/EA ACCOUNTS NOT IN 'PROTECTED USERS' GROUP"

try {
    $protectedUsers = Get-ADGroupMember -Identity 'Protected Users' -ErrorAction Stop |
        ForEach-Object { $_.SamAccountName }

    $daMembers = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction SilentlyContinue |
        Where-Object { $_.objectClass -eq 'user' }

    $notProtected = $daMembers | Where-Object { $_.SamAccountName -notin $protectedUsers }

    if ($notProtected) {
        Write-Finding "MED" "$($notProtected.Count) Domain Admin(s) NOT in Protected Users group (vulnerable to credential theft):"
        $notProtected | ForEach-Object { Write-Detail $_.SamAccountName }
    } else {
        Write-Finding "OK" "All Domain Admins are in Protected Users group"
    }
} catch {
    Write-Finding "INFO" "Protected Users group not found: $($_.Exception.Message)"
}

# =============================================================================
# 18. Accounts with WriteDACL/GenericAll on Privileged Objects
# =============================================================================
Write-Section "18. UNEXPECTED WRITE PERMISSIONS ON HIGH-VALUE AD OBJECTS"

$highValueObjects = @(
    "CN=Domain Admins,CN=Users,$domainDN",
    "CN=Administrators,CN=Builtin,$domainDN",
    "CN=Enterprise Admins,CN=Users,$domainDN",
    "CN=Schema Admins,CN=Users,$domainDN",
    "CN=Group Policy Creator Owners,CN=Users,$domainDN",
    "CN=DnsAdmins,CN=Users,$domainDN",
    $domainDN
)

$writePerm = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor
             [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor
             [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor
             [System.DirectoryServices.ActiveDirectoryRights]::GenericAll

$safeWriteIdentities = @(
    'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'CREATOR OWNER',
    "$($domain.NetBIOSName)\Domain Admins",
    "$($domain.NetBIOSName)\Enterprise Admins"
)

foreach ($objDN in $highValueObjects) {
    try {
        $acl = Get-ACL "AD:\$objDN" -ErrorAction SilentlyContinue
        if (-not $acl) { continue }

        $dangerous = $acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            ($_.ActiveDirectoryRights -band $writePerm) -and
            $_.IdentityReference.Value -notin $safeWriteIdentities -and
            $_.IdentityReference.Value -notmatch 'S-1-5-18'
        }

        if ($dangerous) {
            $shortName = ($objDN -split ',')[0] -replace 'CN=',''
            Write-Finding "CRITICAL" "Non-admin write access on '$shortName':"
            $dangerous | ForEach-Object {
                Write-Detail "$($_.IdentityReference) - $($_.ActiveDirectoryRights)"
            }
        }
    } catch {}
}

Write-Finding "OK" "High-value object ACL check complete (CRITICAL findings above if any)"

# =============================================================================
# 19. DnsAdmins Members (can load arbitrary DLL via DNS service)
# =============================================================================
Write-Section "19. DNSADMINS MEMBERSHIP (DLL injection via DNS service)"

try {
    $dnsAdmins = Get-ADGroupMember -Identity 'DnsAdmins' -Recursive -ErrorAction Stop
    if ($dnsAdmins) {
        Write-Finding "HIGH" "$($dnsAdmins.Count) member(s) in DnsAdmins (can load malicious DLL via DNS service restart):"
        $dnsAdmins | ForEach-Object {
            $u = Get-ADUser -Identity $_.SamAccountName -Properties Enabled -ErrorAction SilentlyContinue
            $status = if ($u -and $u.Enabled) { "ENABLED" } elseif ($u) { "DISABLED" } else { "N/A" }
            Write-Detail "$($_.SamAccountName) [$($_.objectClass)] [$status]"
        }
    } else {
        Write-Finding "OK" "DnsAdmins group is empty"
    }
} catch {
    Write-Finding "INFO" "DnsAdmins group not found"
}

# =============================================================================
# 20. Foreign Security Principals in Privileged Groups
# =============================================================================
Write-Section "20. FOREIGN SECURITY PRINCIPALS IN PRIVILEGED GROUPS"

$fspContainer = "CN=ForeignSecurityPrincipals,$domainDN"
try {
    $fsps = Get-ADObject -SearchBase $fspContainer -Filter { ObjectClass -eq 'foreignSecurityPrincipal' } `
        -Properties MemberOf -ErrorAction SilentlyContinue

    $privGroupDNSet = $allPrivGroupDNs -as [System.Collections.Generic.HashSet[string]]
    $dangerousFSPs  = $fsps | Where-Object { $_.MemberOf | Where-Object { $_ -in $privGroupDNSet } }

    if ($dangerousFSPs) {
        Write-Finding "CRITICAL" "$($dangerousFSPs.Count) foreign security principal(s) in privileged groups:"
        foreach ($fsp in $dangerousFSPs) {
            $groups = $fsp.MemberOf | Where-Object { $_ -in $privGroupDNSet } | ForEach-Object {
                ($_ -split ',')[0] -replace 'CN=',''
            }
            Write-Detail "$($fsp.Name) - member of: $($groups -join ', ')"
        }
    } else {
        Write-Finding "OK" "No foreign security principals in privileged groups"
    }
} catch {
    Write-Finding "INFO" "Could not enumerate foreign security principals: $($_.Exception.Message)"
}

# =============================================================================
# Summary
# =============================================================================
Write-Section "SUMMARY"

$criticalCount = ($report | Where-Object { $_ -match '\[CRITICAL\]' }).Count
$highCount     = ($report | Where-Object { $_ -match '\[HIGH\]'     }).Count
$medCount      = ($report | Where-Object { $_ -match '\[MED\]'      }).Count

$report.Add("  CRITICAL : $criticalCount finding(s)")
$report.Add("  HIGH     : $highCount finding(s)")
$report.Add("  MEDIUM   : $medCount finding(s)")
$report.Add("")
$report.Add("  Report saved to: $OutputPath")

$report | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-Output "DONE:$criticalCount critical,$highCount high,$medCount medium"
