<#
.SYNOPSIS
    Finds where (if) an Entra ID group is referenced across the tenant.

.DESCRIPTION
    READ-ONLY. Makes no changes to the tenant or Azure:
      - Every Graph call goes through one wrapper that hard-codes -Method GET and rejects any non-Graph URI.
      - The script does NOT call Connect-MgGraph or Connect-AzAccount, so it can never trigger a consent prompt
        (consenting would create an oauth2PermissionGrant, which changes the tenant). You connect first, using scopes that are already consented.
      - Azure RBAC uses Search-AzGraph (Resource Graph query), which is read-only.
      - The only writes are the two CSV files in -OutputPath on the local machine.
    Every check runs on its own. A 403 or an unavailable endpoint marks that check Skipped instead of
    stopping the run, so "no findings" can be read against the list of checks that actually ran.

    Surfaces checked:
      Entra      - group nesting (direct + transitive), administrative units, directory roles (active + PIM eligible),
                   PIM for Groups (as target and as principal), enterprise app / app role assignments,
                   group-based licensing, Conditional Access, authentication methods policy + registration campaign,
                   staged rollout (feature rollout policies), cross-tenant access policy, dynamic group rules (memberOf)
      Governance - Entitlement Management (catalog resources, access packages, assignment policies),
                   access reviews, lifecycle workflows
      Intune     - device configs, settings catalog, admin templates, compliance, scripts (Win/macOS/custom attributes),
                   remediations, apps, app config (device + MAM), app protection (iOS/Android/Windows), enrollment configs,
                   Autopilot profiles, feature/quality/driver update profiles, legacy endpoint security intents,
                   terms and conditions, Intune RBAC role assignments, Windows 365 provisioning/user settings
      Optional   - directory audit log (last 50 events targeting the group), Azure RBAC via Resource Graph

    NOT covered (no Graph surface or separate stack): Exchange Online (mail-enabled permissions, transport rules),
    SharePoint/Teams site permissions, Purview (DLP, retention, label policies), Defender XDR, Power Platform,
    on-prem AD (GPO filtering, ACLs) for synced groups.

.EXAMPLE
    .\Get-EntraGroupUsage.ps1 -GroupId 1b2c3d4e-....
.EXAMPLE
    .\Get-EntraGroupUsage.ps1 -GroupName 'SG-Intune-Pilot' -IncludeAuditLog -IncludeAzureRbac -OutputPath C:\Temp
#>
[CmdletBinding(DefaultParameterSetName = 'ById')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ById')]   [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string]$GroupId,
    [Parameter(Mandatory, ParameterSetName = 'ByName')] [string]$GroupName,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$SkipIntune,
    [switch]$SkipGovernance,
    [switch]$IncludeAuditLog,
    [switch]$IncludeAzureRbac
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$v1   = 'https://graph.microsoft.com/v1.0'
$beta = 'https://graph.microsoft.com/beta'

#region Connection check (no connect / no consent)
$scopes = @(
    'Group.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'Policy.Read.All',
    'Application.Read.All', 'PrivilegedAccess.Read.AzureADGroup', 'EntitlementManagement.Read.All',
    'AccessReview.Read.All', 'LifecycleWorkflows.Read.All', 'AuditLog.Read.All',
    'DeviceManagementConfiguration.Read.All', 'DeviceManagementApps.Read.All',
    'DeviceManagementServiceConfig.Read.All', 'DeviceManagementRBAC.Read.All',
    'DeviceManagementManagedDevices.Read.All', 'CloudPC.Read.All'
)
$ctx = Get-MgContext
if (-not $ctx) {
    throw @"
Not connected to Microsoft Graph. This script will not connect for you, so no consent prompt can happen.
Connect first with scopes that are already consented, e.g.:
  Connect-MgGraph -Scopes $($scopes -join ',') -NoWelcome
Any scope not granted just means that check is reported as Skipped (403).
"@
}
if ($ctx.AuthType -eq 'Delegated' -and $ctx.Scopes) {
    $missing = @($scopes | Where-Object { $ctx.Scopes -notcontains $_ })
    if ($missing.Count) { Write-Warning "Scopes missing from this session (related checks will be Skipped): $($missing -join ', ')" }
}
#endregion

#region Helpers
function Get-HttpStatus {
    param($ErrorRecord)
    try {
        $ex = $ErrorRecord.Exception
        if ($ex.PSObject.Properties['Response'] -and $ex.Response) { return [int]$ex.Response.StatusCode }
    } catch { }
    if ($ErrorRecord.ToString() -match '\b(400|401|403|404|429|5\d\d)\b') { return [int]$Matches[1] }
    return $null
}

function Invoke-GraphWithRetry {
    param([string]$Uri, [hashtable]$Headers = @{}, [int]$MaxRetries = 6)
    # Read-only guard: Graph only, GET only (method is hard-coded below and not parameterised).
    if ($Uri -notmatch '^https://graph\.microsoft\.com/(v1\.0|beta)/') { throw "Blocked non-Graph URI: $Uri" }
    $attempt = 0
    while ($true) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
        } catch {
            $status = Get-HttpStatus $_
            if ($status -in 429, 500, 502, 503, 504 -and $attempt -lt $MaxRetries) {
                $attempt++
                $delay = [math]::Min(60, [math]::Pow(2, $attempt))
                try {
                    $ra = $_.Exception.Response.Headers.RetryAfter
                    if ($ra -and $ra.Delta) { $delay = [math]::Ceiling($ra.Delta.TotalSeconds) }
                } catch { }
                Write-Verbose "HTTP $status on $Uri - retry $attempt in ${delay}s"
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

# Returns all items for a collection (follows nextLink), or the single object for a non-collection response.
function Get-Graph {
    param([string]$Uri, [hashtable]$Headers = @{})
    $out  = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $resp = Invoke-GraphWithRetry -Uri $next -Headers $Headers
        if ($resp -is [System.Collections.IDictionary] -and $resp.Contains('value')) {
            foreach ($v in @($resp['value'])) { $out.Add($v) }
            $next = $resp['@odata.nextLink']
        } else {
            return $resp
        }
    }
    return $out.ToArray()
}

# Null-safe nested property access for hashtables / PSObjects under StrictMode.
function Get-Val {
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$p] }
        elseif ($cur.PSObject.Properties[$p])          { $cur = $cur.$p }
        else                                           { return $null }
    }
    return $cur
}

function Get-Name { param($o) $n = Get-Val $o 'displayName'; if (-not $n) { $n = Get-Val $o 'name' }; if (-not $n) { $n = Get-Val $o 'id' }; $n }

# Catch-all: does the group ID appear anywhere in the object?
function Test-Ref { param($o) if ($null -eq $o) { return $false }; (ConvertTo-Json -InputObject $o -Depth 30 -Compress) -match [regex]::Escape($script:gid) }

$Findings = [System.Collections.Generic.List[object]]::new()
$Checks   = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param([string]$Area, [string]$Category, [string]$Item, [string]$ItemId, [string]$Usage, [string]$Detail = '')
    $Findings.Add([pscustomobject]@{ Area = $Area; Category = $Category; Item = $Item; ItemId = $ItemId; Usage = $Usage; Detail = $Detail })
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Script)
    Write-Host "  Checking: $Name" -ForegroundColor DarkGray
    $before = $Findings.Count
    try {
        & $Script
        $Checks.Add([pscustomobject]@{ Check = $Name; Status = 'OK'; Hits = $Findings.Count - $before; Note = '' })
    } catch {
        $err    = $_
        $status = Get-HttpStatus $err
        $state  = switch ($status) {
            403     { 'Skipped (403 - permission/licence)' }
            401     { 'Skipped (401)' }
            { $_ -in 400, 404 } { "Skipped ($status - not available)" }
            default { 'Error' }
        }
        $msg = ($err.ToString() -split "`n")[0]
        $Checks.Add([pscustomobject]@{ Check = $Name; Status = $state; Hits = $Findings.Count - $before; Note = $msg })
        Write-Warning "$Name : $state"
    }
}

# Generic Intune assignment scan for endpoints that support $expand=assignments.
function Find-IntuneAssignments {
    param([string]$Category, [string]$Uri)
    foreach ($i in @(Get-Graph $Uri)) {
        foreach ($a in @(Get-Val $i 'assignments')) {
            if ($null -eq $a) { continue }
            $t = Get-Val $a 'target'
            if ((Get-Val $t 'groupId') -ne $script:gid) { continue }
            $type   = [string](Get-Val $t '@odata.type')
            $usage  = if ($type -match 'exclusion') { 'Exclude' } else { 'Include' }
            $detail = @()
            $intent = Get-Val $a 'intent'
            if ($intent) { $detail += "intent=$intent" }
            $fType = Get-Val $t 'deviceAndAppManagementAssignmentFilterType'
            if ($fType -and $fType -ne 'none') { $detail += "filter=$fType/$(Get-Val $t 'deviceAndAppManagementAssignmentFilterId')" }
            Add-Finding 'Intune' $Category (Get-Name $i) (Get-Val $i 'id') $usage ($detail -join '; ')
        }
    }
}
#endregion

#region Resolve group
if ($PSCmdlet.ParameterSetName -eq 'ByName') {
    $safe    = $GroupName.Replace("'", "''")
    $matches_ = @(Get-Graph "$v1/groups?`$filter=displayName eq '$safe'&`$select=id,displayName")
    if ($matches_.Count -eq 0) { throw "No group found named '$GroupName'." }
    if ($matches_.Count -gt 1) {
        $matches_ | ForEach-Object { Write-Host "  $($_.id)  $($_.displayName)" }
        throw "Multiple groups named '$GroupName'. Re-run with -GroupId."
    }
    $GroupId = $matches_[0].id
}
$script:gid = $GroupId.ToLower()

$sel = 'id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,membershipRule,membershipRuleProcessingState,' +
       'onPremisesSyncEnabled,isAssignableToRole,createdDateTime,renewedDateTime,visibility,resourceProvisioningOptions,assignedLicenses'
$grp = Get-Graph "$v1/groups/$($script:gid)?`$select=$sel"
$ev  = @{ ConsistencyLevel = 'eventual' }

$directCount = $transCount = 'n/a'
try { $directCount = Invoke-GraphWithRetry "$v1/groups/$($script:gid)/members/`$count" $ev } catch { }
try { $transCount  = Invoke-GraphWithRetry "$v1/groups/$($script:gid)/transitiveMembers/`$count" $ev } catch { }
$owners = @()
try { $owners = @(Get-Graph "$v1/groups/$($script:gid)/owners?`$select=id,displayName,userPrincipalName") } catch { }

$groupTypes = @(Get-Val $grp 'groupTypes')
$kind = if ($groupTypes -contains 'Unified') { 'Microsoft 365' } elseif ($grp.securityEnabled -and $grp.mailEnabled) { 'Mail-enabled security' } elseif ($grp.securityEnabled) { 'Security' } else { 'Distribution' }

Write-Host "`nGroup: $($grp.displayName) ($($script:gid))" -ForegroundColor Cyan
[pscustomobject]@{
    Type             = $kind
    Dynamic          = ($groupTypes -contains 'DynamicMembership')
    MembershipRule   = Get-Val $grp 'membershipRule'
    Synced           = [bool](Get-Val $grp 'onPremisesSyncEnabled')
    RoleAssignable   = [bool](Get-Val $grp 'isAssignableToRole')
    Team             = (@(Get-Val $grp 'resourceProvisioningOptions') -contains 'Team')
    DirectMembers    = $directCount
    TransitiveMembers= $transCount
    Owners           = ($owners | ForEach-Object { Get-Name $_ }) -join '; '
    Created          = Get-Val $grp 'createdDateTime'
} | Format-List
#endregion

Write-Host 'Entra ID' -ForegroundColor Cyan

Invoke-Check 'Group nesting (direct memberOf)' {
    foreach ($m in @(Get-Graph "$v1/groups/$($script:gid)/memberOf?`$select=id,displayName")) {
        $type = [string](Get-Val $m '@odata.type')
        if ($type -match 'administrativeUnit') { Add-Finding 'Entra' 'Administrative unit' (Get-Name $m) $m.id 'Member' }
        else                                   { Add-Finding 'Entra' 'Nested in group (direct)' (Get-Name $m) $m.id 'Member' }
    }
}

Invoke-Check 'Group nesting (transitive memberOf)' {
    $direct = @($Findings | Where-Object Category -eq 'Nested in group (direct)' | ForEach-Object ItemId)
    foreach ($m in @(Get-Graph "$v1/groups/$($script:gid)/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName")) {
        if ($direct -notcontains $m.id) { Add-Finding 'Entra' 'Nested in group (inherited)' (Get-Name $m) $m.id 'Member (transitive)' }
    }
}

Invoke-Check 'Directory roles (active)' {
    foreach ($r in @(Get-Graph "$v1/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($script:gid)'&`$expand=roleDefinition")) {
        Add-Finding 'Entra' 'Directory role (active)' (Get-Val $r 'roleDefinition','displayName') $r.roleDefinitionId 'Assigned' "scope=$($r.directoryScopeId)"
    }
}

Invoke-Check 'Directory roles (PIM eligible)' {
    foreach ($r in @(Get-Graph "$v1/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($script:gid)'&`$expand=roleDefinition")) {
        Add-Finding 'Entra' 'Directory role (eligible)' (Get-Val $r 'roleDefinition','displayName') $r.roleDefinitionId 'Eligible' "scope=$($r.directoryScopeId); end=$(Get-Val $r 'scheduleInfo','expiration','endDateTime')"
    }
}

Invoke-Check 'PIM for Groups (this group as target)' {
    $e = @(Get-Graph "$v1/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($script:gid)'")
    $a = @(Get-Graph "$v1/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($script:gid)'")
    if ($e.Count -or $a.Count) {
        Add-Finding 'Entra' 'PIM for Groups (target)' $grp.displayName $script:gid 'PIM-managed' "eligibleSchedules=$($e.Count); activeSchedules=$($a.Count)"
    }
}

Invoke-Check 'PIM for Groups (this group as principal)' {
    foreach ($s in @(Get-Graph "$v1/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$($script:gid)'")) {
        Add-Finding 'Entra' 'PIM for Groups (principal)' $s.groupId $s.groupId 'Eligible' "accessId=$($s.accessId)"
    }
    foreach ($s in @(Get-Graph "$v1/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=principalId eq '$($script:gid)'")) {
        Add-Finding 'Entra' 'PIM for Groups (principal)' $s.groupId $s.groupId 'Assigned' "accessId=$($s.accessId)"
    }
}

Invoke-Check 'Enterprise app assignments (app roles)' {
    foreach ($a in @(Get-Graph "$v1/groups/$($script:gid)/appRoleAssignments")) {
        $role = if ($a.appRoleId -eq '00000000-0000-0000-0000-000000000000') { 'Default access' } else { "appRoleId=$($a.appRoleId)" }
        Add-Finding 'Entra' 'Enterprise app assignment' $a.resourceDisplayName $a.resourceId 'Assigned' $role
    }
}

Invoke-Check 'Group-based licensing' {
    $lic = @(Get-Val $grp 'assignedLicenses')
    if ($lic.Count -and $null -ne $lic[0]) {
        $skus = @{}
        foreach ($s in @(Get-Graph "$v1/subscribedSkus?`$select=skuId,skuPartNumber")) { $skus[$s.skuId] = $s.skuPartNumber }
        foreach ($l in $lic) {
            $name = if ($skus.ContainsKey($l.skuId)) { $skus[$l.skuId] } else { $l.skuId }
            Add-Finding 'Entra' 'Group-based licence' $name $l.skuId 'Assigned' "disabledPlans=$(@($l.disabledPlans).Count)"
        }
    }
}

Invoke-Check 'Conditional Access' {
    foreach ($p in @(Get-Graph "$v1/identity/conditionalAccess/policies")) {
        $inc = @(Get-Val $p 'conditions','users','includeGroups')
        $exc = @(Get-Val $p 'conditions','users','excludeGroups')
        if ($inc -contains $script:gid) { Add-Finding 'Entra' 'Conditional Access' $p.displayName $p.id 'Include' "state=$($p.state)" }
        if ($exc -contains $script:gid) { Add-Finding 'Entra' 'Conditional Access' $p.displayName $p.id 'Exclude' "state=$($p.state)" }
        if (-not ($inc -contains $script:gid -or $exc -contains $script:gid) -and (Test-Ref $p)) {
            Add-Finding 'Entra' 'Conditional Access' $p.displayName $p.id 'Referenced (other)' "state=$($p.state)"
        }
    }
}

Invoke-Check 'Authentication methods policy' {
    $amp = Get-Graph "$v1/policies/authenticationMethodsPolicy"
    foreach ($c in @(Get-Val $amp 'authenticationMethodConfigurations')) {
        if ($null -eq $c) { continue }
        if (Test-Ref $c) {
            $usage = if (Test-Ref (Get-Val $c 'excludeTargets')) { 'Exclude' } elseif (Test-Ref (Get-Val $c 'includeTargets')) { 'Include' } else { 'Referenced' }
            Add-Finding 'Entra' 'Auth method' $c.id $c.id $usage "state=$($c.state)"
        }
    }
    $campaign = Get-Val $amp 'registrationEnforcement','authenticationMethodsRegistrationCampaign'
    if (Test-Ref $campaign) {
        $usage = if (Test-Ref (Get-Val $campaign 'excludeTargets')) { 'Exclude' } else { 'Include' }
        Add-Finding 'Entra' 'Auth method registration campaign' 'Registration campaign' '' $usage
    }
    if (Test-Ref (Get-Val $amp 'systemCredentialPreferences')) { Add-Finding 'Entra' 'System-preferred MFA' 'systemCredentialPreferences' '' 'Referenced' }
}

Invoke-Check 'Staged rollout (feature rollout policies)' {
    foreach ($f in @(Get-Graph "$v1/policies/featureRolloutPolicies?`$expand=appliesTo")) {
        if (@(Get-Val $f 'appliesTo') | Where-Object { $_ -and $_.id -eq $script:gid }) {
            Add-Finding 'Entra' 'Staged rollout' $f.displayName $f.id 'Applies to' "feature=$($f.feature); enabled=$($f.isEnabled)"
        }
    }
}

Invoke-Check 'Cross-tenant access policy' {
    $d = Get-Graph "$v1/policies/crossTenantAccessPolicy/default"
    if (Test-Ref $d) { Add-Finding 'Entra' 'Cross-tenant access' 'Default settings' '' 'Referenced' }
    foreach ($p in @(Get-Graph "$v1/policies/crossTenantAccessPolicy/partners")) {
        if (Test-Ref $p) { Add-Finding 'Entra' 'Cross-tenant access' "Partner $($p.tenantId)" $p.tenantId 'Referenced' }
    }
}

Invoke-Check 'Dynamic group rules (memberOf)' {
    foreach ($g in @(Get-Graph "$v1/groups?`$filter=groupTypes/any(c:c eq 'DynamicMembership')&`$select=id,displayName,membershipRule&`$top=999")) {
        if ([string](Get-Val $g 'membershipRule') -match [regex]::Escape($script:gid)) {
            Add-Finding 'Entra' 'Dynamic group rule' $g.displayName $g.id 'Referenced in rule'
        }
    }
}

if (-not $SkipGovernance) {
    Write-Host 'Identity Governance' -ForegroundColor Cyan

    Invoke-Check 'Entitlement Mgmt - catalog resources' {
        foreach ($c in @(Get-Graph "$v1/identityGovernance/entitlementManagement/catalogs?`$select=id,displayName")) {
            foreach ($r in @(Get-Graph "$v1/identityGovernance/entitlementManagement/catalogs/$($c.id)/resources?`$filter=originId eq '$($script:gid)'")) {
                Add-Finding 'Governance' 'EM catalog resource' $c.displayName $c.id 'Resource in catalog'
            }
        }
    }

    Invoke-Check 'Entitlement Mgmt - access packages' {
        foreach ($ap in @(Get-Graph "$v1/identityGovernance/entitlementManagement/accessPackages?`$expand=resourceRoleScopes(`$expand=role,scope)")) {
            foreach ($rrs in @(Get-Val $ap 'resourceRoleScopes')) {
                if ($rrs -and (Get-Val $rrs 'scope','originId') -eq $script:gid) {
                    Add-Finding 'Governance' 'Access package resource' $ap.displayName $ap.id 'Grants membership' "role=$(Get-Val $rrs 'role','displayName')"
                }
            }
        }
    }

    Invoke-Check 'Entitlement Mgmt - assignment policies' {
        foreach ($p in @(Get-Graph "$v1/identityGovernance/entitlementManagement/assignmentPolicies?`$expand=accessPackage")) {
            if (Test-Ref $p) {
                Add-Finding 'Governance' 'Access package policy' "$(Get-Val $p 'accessPackage','displayName') / $($p.displayName)" $p.id 'Requestor/approver/reviewer scope'
            }
        }
    }

    Invoke-Check 'Access reviews' {
        foreach ($d in @(Get-Graph "$v1/identityGovernance/accessReviews/definitions")) {
            if (Test-Ref $d) {
                $usage = if (Test-Ref (Get-Val $d 'scope')) { 'Review scope' } elseif (Test-Ref (Get-Val $d 'reviewers')) { 'Reviewers' } else { 'Referenced' }
                Add-Finding 'Governance' 'Access review' $d.displayName $d.id $usage "status=$($d.status)"
            }
        }
    }

    Invoke-Check 'Lifecycle workflows' {
        foreach ($w in @(Get-Graph "$v1/identityGovernance/lifecycleWorkflows/workflows")) {
            $full = Get-Graph "$v1/identityGovernance/lifecycleWorkflows/workflows/$($w.id)?`$expand=tasks"
            if (Test-Ref $full) { Add-Finding 'Governance' 'Lifecycle workflow' $w.displayName $w.id 'Referenced (scope/tasks)' }
        }
    }
}

if (-not $SkipIntune) {
    Write-Host 'Intune' -ForegroundColor Cyan

    $intuneExpand = [ordered]@{
        'Device configuration'          = "$beta/deviceManagement/deviceConfigurations?`$expand=assignments"
        'Settings catalog / ES'         = "$beta/deviceManagement/configurationPolicies?`$expand=assignments"
        'Administrative templates'      = "$beta/deviceManagement/groupPolicyConfigurations?`$expand=assignments"
        'Compliance policy'             = "$beta/deviceManagement/deviceCompliancePolicies?`$expand=assignments"
        'Platform script (Windows)'     = "$beta/deviceManagement/deviceManagementScripts?`$expand=assignments"
        'Shell script (macOS)'          = "$beta/deviceManagement/deviceShellScripts?`$expand=assignments"
        'Custom attribute (macOS)'      = "$beta/deviceManagement/deviceCustomAttributeShellScripts?`$expand=assignments"
        'Remediation'                   = "$beta/deviceManagement/deviceHealthScripts?`$expand=assignments"
        'Enrollment configuration'      = "$beta/deviceManagement/deviceEnrollmentConfigurations?`$expand=assignments"
        'Autopilot profile'             = "$beta/deviceManagement/windowsAutopilotDeploymentProfiles?`$expand=assignments"
        'Feature update profile'        = "$beta/deviceManagement/windowsFeatureUpdateProfiles?`$expand=assignments"
        'Quality update profile'        = "$beta/deviceManagement/windowsQualityUpdateProfiles?`$expand=assignments"
        'Driver update profile'         = "$beta/deviceManagement/windowsDriverUpdateProfiles?`$expand=assignments"
        'Terms and conditions'          = "$beta/deviceManagement/termsAndConditions?`$expand=assignments"
        'App'                           = "$beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true&`$expand=assignments"
        'App config (managed devices)'  = "$beta/deviceAppManagement/mobileAppConfigurations?`$expand=assignments"
        'App config (managed apps)'     = "$beta/deviceAppManagement/targetedManagedAppConfigurations?`$expand=assignments"
        'App protection (iOS)'          = "$beta/deviceAppManagement/iosManagedAppProtections?`$expand=assignments"
        'App protection (Android)'      = "$beta/deviceAppManagement/androidManagedAppProtections?`$expand=assignments"
        'App protection (Windows)'      = "$beta/deviceAppManagement/windowsManagedAppProtections?`$expand=assignments"
        'W365 provisioning policy'      = "$beta/deviceManagement/virtualEndpoint/provisioningPolicies?`$expand=assignments"
        'W365 user setting'             = "$beta/deviceManagement/virtualEndpoint/userSettings?`$expand=assignments"
    }
    foreach ($k in $intuneExpand.Keys) {
        $uri = $intuneExpand[$k]
        Invoke-Check "Intune - $k" { Find-IntuneAssignments -Category $k -Uri $uri }
    }

    Invoke-Check 'Intune - Endpoint security (legacy intents)' {
        foreach ($i in @(Get-Graph "$beta/deviceManagement/intents?`$select=id,displayName")) {
            foreach ($a in @(Get-Graph "$beta/deviceManagement/intents/$($i.id)/assignments")) {
                if ((Get-Val $a 'target','groupId') -eq $script:gid) {
                    $usage = if ([string](Get-Val $a 'target','@odata.type') -match 'exclusion') { 'Exclude' } else { 'Include' }
                    Add-Finding 'Intune' 'Endpoint security (intent)' $i.displayName $i.id $usage
                }
            }
        }
    }

    Invoke-Check 'Intune - RBAC role assignments' {
        foreach ($ra in @(Get-Graph "$beta/deviceManagement/roleAssignments?`$select=id,displayName")) {
            $full = Get-Graph "$beta/deviceManagement/roleAssignments/$($ra.id)?`$expand=roleDefinition"
            if (Test-Ref (Get-Val $full 'members')) {
                Add-Finding 'Intune' 'Intune RBAC' $full.displayName $full.id 'Admin group (members)' "role=$(Get-Val $full 'roleDefinition','displayName')"
            }
            if ((Test-Ref (Get-Val $full 'scopeMembers')) -or (Test-Ref (Get-Val $full 'resourceScopes'))) {
                Add-Finding 'Intune' 'Intune RBAC' $full.displayName $full.id 'Scope group' "role=$(Get-Val $full 'roleDefinition','displayName')"
            }
        }
    }
}

if ($IncludeAuditLog) {
    Write-Host 'Audit' -ForegroundColor Cyan
    Invoke-Check 'Directory audit (last 50, 30-day retention)' {
        $r = Invoke-GraphWithRetry "$v1/auditLogs/directoryAudits?`$filter=targetResources/any(t:t/id eq '$($script:gid)')&`$top=50"
        foreach ($e in @($r['value'])) {
            $actor = Get-Val $e 'initiatedBy','user','userPrincipalName'
            if (-not $actor) { $actor = Get-Val $e 'initiatedBy','app','displayName' }
            Add-Finding 'Audit' 'Recent activity' $e.activityDisplayName $e.id 'Event' "$($e.activityDateTime) by $actor"
        }
    }
}

if ($IncludeAzureRbac) {
    Write-Host 'Azure RBAC' -ForegroundColor Cyan
    Invoke-Check 'Azure RBAC (Resource Graph, active assignments)' {
        Import-Module Az.ResourceGraph -ErrorAction Stop
        if (-not (Get-AzContext)) { throw 'Not connected to Azure. Run Connect-AzAccount first (the script will not connect for you).' }
        $q = @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| where tolower(tostring(properties.principalId)) == '$($script:gid)'
| extend roleGuid = tolower(extract(@'([0-9a-fA-F-]{36})$', 1, tostring(properties.roleDefinitionId))), scope = tostring(properties.scope)
| join kind=leftouter (
    authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | extend roleGuid = tolower(extract(@'([0-9a-fA-F-]{36})$', 1, id)), roleName = tostring(properties.roleName)
    | summarize roleName = any(roleName) by roleGuid
  ) on roleGuid
| project scope, roleName, id
"@
        foreach ($r in @(Search-AzGraph -Query $q -UseTenantScope -First 1000)) {
            Add-Finding 'Azure' 'Azure RBAC' $r.roleName $r.id 'Assigned' "scope=$($r.scope)"
        }
    }
}

#region Output
$stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeName = ($grp.displayName -replace '[^\w\-]', '_')
$fPath    = Join-Path $OutputPath "GroupUsage_${safeName}_$stamp.csv"
$cPath    = Join-Path $OutputPath "GroupUsage_${safeName}_${stamp}_checks.csv"
$Findings | Export-Csv $fPath -NoTypeInformation -Encoding UTF8
$Checks   | Export-Csv $cPath -NoTypeInformation -Encoding UTF8

Write-Host "`n=== Findings ===" -ForegroundColor Cyan
if ($Findings.Count) { $Findings | Sort-Object Area, Category, Item | Format-Table Area, Category, Item, Usage, Detail -AutoSize -Wrap }
else { Write-Host 'No references found in the surfaces that were checked.' -ForegroundColor Yellow }

$notOk = @($Checks | Where-Object Status -ne 'OK')
if ($notOk.Count) {
    Write-Host "`n=== Checks not completed ($($notOk.Count)) - absence of findings is NOT conclusive for these ===" -ForegroundColor Yellow
    $notOk | Format-Table Check, Status, Note -AutoSize -Wrap
}

$usageHits = @($Findings | Where-Object Area -ne 'Audit').Count
$verdict = if ($usageHits) { "IN USE - $usageHits reference(s)" } elseif ($notOk.Count) { 'No references found, but some checks did not run' } else { 'No references found in any checked surface' }
Write-Host "`nVerdict: $verdict" -ForegroundColor $(if ($usageHits) { 'Green' } else { 'Yellow' })
Write-Host "Findings: $fPath`nChecks:   $cPath"
#endregion
