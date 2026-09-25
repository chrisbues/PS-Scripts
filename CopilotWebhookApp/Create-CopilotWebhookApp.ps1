<#
.SYNOPSIS
Creates a Microsoft Entra app registration with a Federated Identity Credential (FIC) for Copilot Studio's security webhook.

.DESCRIPTION
Signs in to Microsoft Graph interactively, then ensures the app registration, its service principal,
and the FIC exist. If an app with the given display name already exists, you are asked before it is reused.
Use -WhatIf to see what would be created; lookups still run against the tenant.

.PARAMETER TenantId
The Entra tenant ID (GUID).

.PARAMETER Endpoint
Webhook endpoint URL. Must be HTTPS and exactly match what Copilot Studio uses.

.PARAMETER DisplayName
Display name for the app registration.

.PARAMETER FICName
Name of the Federated Identity Credential to create.

.PARAMETER Force
Reuse an existing app with the same display name without asking.

.PARAMETER UseBeta
Use the Microsoft Graph beta SDK (Microsoft.Graph.Beta.Applications). Without this switch the v1.0 SDK
is used if installed, falling back to beta if only that is installed.

.EXAMPLE
.\Create-CopilotWebhookApp.ps1 -TenantId 12345678-1234-1234-1234-123456789012 -Endpoint https://your.webhook/endpoint -DisplayName "My Copilot App" -FICName WebhookFIC

.EXAMPLE
.\Create-CopilotWebhookApp.ps1 -TenantId 12345678-1234-1234-1234-123456789012 -Endpoint https://your.webhook/endpoint -DisplayName "My Copilot App" -FICName WebhookFIC -WhatIf

.NOTES
Requires either the v1.0 or beta Microsoft Graph Applications module:
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser
    Install-Module Microsoft.Graph.Beta.Applications -Scope CurrentUser
The signed-in user needs rights to create app registrations (e.g. Application Developer or Application Administrator).
#>

#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [guid]$TenantId,

    [Parameter(Mandatory)]
    [ValidateScript({ ([uri]$_).IsAbsoluteUri -and ([uri]$_).Scheme -eq 'https' })]
    [string]$Endpoint,

    [Parameter(Mandatory)]
    [ValidateLength(1, 120)]
    [string]$DisplayName,

    [Parameter(Mandatory)]
    [ValidateLength(1, 120)]
    [string]$FICName,

    [switch]$Force,

    [switch]$UseBeta
)

$ErrorActionPreference = 'Stop'

# Pick the v1.0 or beta SDK. Cmdlet names differ only by prefix (Get-MgApplication vs Get-MgBetaApplication).
if (-not $UseBeta -and -not (Get-Module -ListAvailable Microsoft.Graph.Applications) -and
    (Get-Module -ListAvailable Microsoft.Graph.Beta.Applications)) {
    $UseBeta = $true
}
$module, $prefix = if ($UseBeta) { 'Microsoft.Graph.Beta.Applications', 'MgBeta' } else { 'Microsoft.Graph.Applications', 'Mg' }
if (-not (Get-Module -ListAvailable $module)) {
    throw "Module $module is not installed. Run: Install-Module $module -Scope CurrentUser"
}
Import-Module $module
Write-Verbose "Using $module"

$Graph = @{}
foreach ($noun in 'Application', 'ServicePrincipal', 'ApplicationFederatedIdentityCredential') {
    foreach ($verb in 'Get', 'New') {
        $Graph["$verb$noun"] = Get-Command "$verb-$prefix$noun" -Module $module
    }
}

# App ID that Copilot Studio places in the FIC subject claim.
$CopilotSubjectAppId = [guid]'9d8f559b-5984-46a4-902a-ad4271e83efa'

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-CopilotFicSubject {
    param([guid]$TenantId, [string]$Endpoint)
    $tenant = ConvertTo-Base64Url $TenantId.ToByteArray()
    $app = ConvertTo-Base64Url $CopilotSubjectAppId.ToByteArray()
    $endpointEncoded = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($Endpoint))
    "/eid1/c/pub/t/$tenant/a/$app/$endpointEncoded"
}

Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All' -NoWelcome

# App registration: reuse only with confirmation, since display names aren't unique in Entra.
$escapedName = $DisplayName -replace "'", "''"
$app = @(& $Graph.GetApplication -Filter "displayName eq '$escapedName'" -All)

if ($app.Count -gt 1) {
    throw "Found $($app.Count) applications named '$DisplayName'. Choose a unique display name."
}
elseif ($app.Count -eq 1) {
    $app = $app[0]
    $question = "Application '$DisplayName' already exists (App ID $($app.AppId)). Add the FIC to it?"
    if (-not ($Force -or $PSCmdlet.ShouldContinue($question, 'Existing application'))) {
        throw 'Cancelled. Choose a different display name or remove the existing app.'
    }
}
else {
    $app = $null
    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create app registration')) {
        $app = & $Graph.NewApplication -DisplayName $DisplayName -SignInAudience AzureADMyOrg
        Write-Verbose "Created application $($app.AppId)"
    }
}

# Nothing more can be checked or created until the app exists (i.e. -WhatIf on a new app).
if (-not $app) { return }

# Service principal
$sp = & $Graph.GetServicePrincipal -Filter "appId eq '$($app.AppId)'"
if (-not $sp -and $PSCmdlet.ShouldProcess($DisplayName, 'Create service principal')) {
    $sp = & $Graph.NewServicePrincipal -AppId $app.AppId
    Write-Verbose "Created service principal $($sp.Id)"
}

# Federated Identity Credential
$existingFic = & $Graph.GetApplicationFederatedIdentityCredential -ApplicationId $app.Id -All |
    Where-Object Name -eq $FICName
if ($existingFic) {
    throw "Federated Identity Credential '$FICName' already exists on '$DisplayName'. Choose a different FIC name."
}

$ficParams = @{
    ApplicationId = $app.Id
    Name          = $FICName
    Issuer        = "https://login.microsoftonline.com/$TenantId/v2.0"
    Subject       = Get-CopilotFicSubject -TenantId $TenantId -Endpoint $Endpoint
    Audiences     = @('api://AzureADTokenExchange')
    Description   = 'Federated Identity Credential for Copilot Studio webhook authentication'
}
if ($PSCmdlet.ShouldProcess($DisplayName, "Create federated identity credential '$FICName'")) {
    $null = & $Graph.NewApplicationFederatedIdentityCredential @ficParams
}

[pscustomobject]@{
    DisplayName        = $app.DisplayName
    AppId              = $app.AppId
    ObjectId           = $app.Id
    ServicePrincipalId = $sp.Id
    FICName            = $FICName
    Subject            = $ficParams.Subject
}
