# Outlook Global Address List sync: one-off setup

When a contact is saved to the **shared** list (and has an email address), the scanner's
Cloudflare worker calls an Azure Automation webhook. The runbook then creates or updates it
as an Exchange Online mail contact, so it shows in Outlook's Global Address List.
Standalone users' private contacts are never sent. Deleting a shared contact in the scanner
removes it from the GAL. The runbook only changes contacts it created itself, which are
tagged `CustomAttribute1 = SentryCardScanner`. Mailboxes and contacts made by hand are left alone.

You need Global Administrator (or Privileged Role Administrator plus Azure subscription
Contributor) for steps 3 and 4.

## 1. Create the Automation account
Azure portal → **Automation Accounts** → **Create**.
- Name: `sentry-gal-sync`, Region: UK South (or your usual region)
- **Advanced** tab: leave **System assigned** managed identity **on**
- Create

## 2. Add the Exchange Online module
Automation account → **Modules** → **Add a module** → **Browse from gallery** →
`ExchangeOnlineManagement` → Runtime version **7.2** → Import.
Wait until its status shows **Available** (a few minutes).

## 3. Let the account manage Exchange (PowerShell, run once)
```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"

$mi   = Get-MgServicePrincipal -Filter "displayName eq 'sentry-gal-sync'"
$exo  = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'"
$role = $exo.AppRoles | Where-Object Value -eq 'Exchange.ManageAsApp'
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id -PrincipalId $mi.Id -ResourceId $exo.Id -AppRoleId $role.Id
```

## 4. Give it the Exchange Recipient Administrator role
Microsoft Entra admin centre → **Roles & admins** → **Exchange Recipient Administrator** →
**Add assignments** → search `sentry-gal-sync` → Add.

## 5. Create the runbook
Automation account → **Runbooks** → **Create a runbook**.
- Name: `Sync-SentryContactsToGAL`, Type: **PowerShell**, Runtime: **7.2**
- Paste in [`Sync-SentryContactsToGAL.ps1`](Sync-SentryContactsToGAL.ps1)
- Change `CHANGE-ME.onmicrosoft.com` to your tenant's onmicrosoft.com domain
  (Microsoft 365 admin centre → Settings → Domains)
- **Save**, then **Publish**

## 6. Create the webhook
Runbook → **Webhooks** → **Add webhook** → **Create new webhook**.
- Name: `Sentry scanner`, choose a long expiry (note the date somewhere, because it stops working after it)
- **Copy the URL now**, because it's only shown once
- **Parameters and run settings** → OK → **Create**

## 7. Give the URL to the scanner
Cloudflare → `sentrycardscanner` worker → **Settings** → **Variables and secrets** → **Add**:
- Key `GAL_WEBHOOK_URL`, Value = the webhook URL, tick **Secret** → **Deploy**

## 8. Send the existing contacts
Admin centre → **Send shared contacts to Outlook**. From then on, new and edited shared
contacts go across automatically.

## Checking it worked
- Automation account → **Jobs** shows every run, with "Created / updated / removed / skipped" in its Output.
- Outlook on the web and online-mode Outlook see new contacts within minutes. Outlook desktop in
  cached mode uses the Offline Address Book, which refreshes about once a day.

## Notes
- Contacts without an email address can't go in the GAL and are skipped.
- If an email is already in the GAL (a staff mailbox or a contact you made by hand), the scanner leaves it alone.
- Azure Automation includes 500 free job minutes a month. Each save is a short job, so normal use costs little or nothing.
