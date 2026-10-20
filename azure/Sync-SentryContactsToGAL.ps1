<#
  Sentry's Card Scanner -> Outlook Global Address List
  Azure Automation runbook (PowerShell 7.2). Started by its webhook from the
  scanner's Cloudflare worker with JSON like:
    { "upsert": [ { "id", "name", "title", "company", "phone", "mobile", "email",
                    "website", "address", "notes", "addedBy" } ],
      "remove": [ "contactId", ... ] }
  Creates or updates Exchange Online mail contacts. Contacts it creates are tagged
  CustomAttribute1 = "SentryCardScanner" and CustomAttribute2 = <scanner id>, and
  it only ever changes or removes contacts carrying that tag. Mailboxes and
  contacts created by hand are never touched.

  To test from your own PC first (signs in as you, no Azure needed):
    Install-Module ExchangeOnlineManagement -Scope CurrentUser
    .\Sync-SentryContactsToGAL.ps1 -UseMyLogin -TestJson '{"upsert":[{"id":"test0001","name":"Test Contact", ...}]}'
#>
param(
    [object]$WebhookData,
    [string]$TestJson,      # run by hand with this JSON instead of a webhook
    [switch]$UseMyLogin     # sign in interactively instead of the managed identity
)

$ErrorActionPreference = 'Stop'
# Your tenant's onmicrosoft.com domain (Microsoft 365 admin centre > Settings > Domains).
$Organization = 'CHANGE-ME.onmicrosoft.com'
$Tag = 'SentryCardScanner'

if ($TestJson) { $body = $TestJson | ConvertFrom-Json }
elseif ($WebhookData -and $WebhookData.RequestBody) { $body = $WebhookData.RequestBody | ConvertFrom-Json }
else { throw 'Start this runbook from its webhook, or run it by hand with -TestJson.' }

if ($UseMyLogin) { Connect-ExchangeOnline -ShowBanner:$false }
else { Connect-ExchangeOnline -ManagedIdentity -Organization $Organization -ShowBanner:$false }

function Clean([object]$value, [int]$max) {
    if ($null -eq $value) { return $null }
    $t = ([string]$value).Trim() -replace '\s+', ' '
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max) }
    if (-not $t) { return $null }   # $null clears a field in Exchange
    return $t
}
function Q([string]$s) { return $s -replace "'", "''" }   # escape for OPATH filters

$made = 0; $updated = 0; $skipped = 0; $removed = 0

foreach ($c in @($body.upsert)) {
    if (-not $c) { continue }
    try {
        $id = [string]$c.id
        $email = Clean $c.email 254
        if ($id -notmatch '^[A-Za-z0-9_-]{4,64}$' -or $email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $skipped++; continue }

        $display = Clean $c.name 256
        if (-not $display) { $display = Clean $c.company 256 }
        if (-not $display) { $display = $email }
        $parts = @($display -split ' ' | Where-Object { $_ })
        $first = if ($parts.Count -gt 1) { ($parts[0..($parts.Count - 2)] -join ' ') } else { '' }
        $last  = if ($parts.Count -gt 1) { $parts[-1] } else { $display }

        # Ours already? (matched by scanner id, then by email)
        $mc = Get-MailContact -Filter "CustomAttribute1 -eq '$Tag' -and CustomAttribute2 -eq '$(Q $id)'" -ResultSize 1 -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $mc) {
            $other = Get-Recipient -Filter "EmailAddresses -eq 'SMTP:$(Q $email)'" -ResultSize 1 -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($other) {
                if ($other.RecipientType -eq 'MailContact' -and $other.CustomAttribute1 -eq $Tag) { $mc = Get-MailContact -Identity $other.Identity }
                else { Write-Output "Skipped ${email}: already in the address list (not added by the scanner)."; $skipped++; continue }
            }
        }

        if (-not $mc) {
            $uniqueName = Clean "$display ($email)" 64
            $mc = New-MailContact -Name $uniqueName -DisplayName $display -ExternalEmailAddress $email -FirstName $first -LastName $last
            $made++
        } else { $updated++ }

        Set-MailContact -Identity $mc.Identity -DisplayName $display -CustomAttribute1 $Tag -CustomAttribute2 $id -HiddenFromAddressListsEnabled $false

        $notes = (Clean $c.notes 900)
        $by = Clean $c.addedBy 80
        $notes = (@($notes, $(if ($by) { "Added by $by via Sentry's Card Scanner" } else { "Added via Sentry's Card Scanner" })) | Where-Object { $_ }) -join ' | '
        Set-Contact -Identity $mc.Identity -FirstName $first -LastName $last `
            -Company (Clean $c.company 64) -Title (Clean $c.title 64) `
            -Phone (Clean $c.phone 64) -MobilePhone (Clean $c.mobile 64) `
            -WebPage (Clean $c.website 256) -StreetAddress (Clean $c.address 1024) `
            -Notes (Clean $notes 1024)
    } catch {
        Write-Warning "Couldn't add or update $($c.email): $($_.Exception.Message)"
        $skipped++
    }
}

foreach ($id in @($body.remove)) {
    if ([string]$id -notmatch '^[A-Za-z0-9_-]{4,64}$') { continue }
    try {
        Get-MailContact -Filter "CustomAttribute1 -eq '$Tag' -and CustomAttribute2 -eq '$(Q $id)'" -ErrorAction SilentlyContinue |
            ForEach-Object { Remove-MailContact -Identity $_.Identity -Confirm:$false; $removed++ }
    } catch { Write-Warning "Couldn't remove ${id}: $($_.Exception.Message)" }
}

Disconnect-ExchangeOnline -Confirm:$false
Write-Output "Done. Created $made, updated $updated, removed $removed, skipped $skipped."
