param(
    [ValidateSet('mailbox', 'relay', 'both')]
    [string]$Mode = 'both',
    [string]$MailboxConfig = "$PSScriptRoot\akrat-mailbox.toml",
    [string]$RelayConfig = "$PSScriptRoot\iroh-relay.toml",
    [string]$IdentityKey = $(if ($env:AKRAT_RELAY_IDENTITY_KEY) { $env:AKRAT_RELAY_IDENTITY_KEY } else { "$env:ProgramData\AKRAT\akrat-relay-identity.key" }),
    [string]$AdvertiseUrl = $env:AKRAT_RELAY_URL
)

$children = @()
try {
    if ($Mode -in @('relay', 'both') -and [string]::IsNullOrWhiteSpace($AdvertiseUrl)) {
        throw 'Pass -AdvertiseUrl or set AKRAT_RELAY_URL to this relay public HTTPS URL.'
    }
    if ($Mode -in @('mailbox', 'both')) {
        $children += Start-Process -FilePath "$PSScriptRoot\akrat-mailbox.exe" -ArgumentList @('--config', $MailboxConfig, 'serve') -NoNewWindow -PassThru
    }
    if ($Mode -in @('relay', 'both')) {
        $identityDirectory = Split-Path -Parent $IdentityKey
        New-Item -ItemType Directory -Path $identityDirectory -Force | Out-Null
        $children += Start-Process -FilePath "$PSScriptRoot\akrat-relay.exe" -ArgumentList @('--config-path', $RelayConfig, '--advertise-url', $AdvertiseUrl, '--identity-key', $IdentityKey) -WorkingDirectory $PSScriptRoot -NoNewWindow -PassThru
    }
    while ($true) {
        foreach ($child in $children) {
            $child.Refresh()
            if ($child.HasExited) {
                exit $child.ExitCode
            }
        }
        Start-Sleep -Milliseconds 500
    }
}
finally {
    foreach ($child in $children) {
        $child.Refresh()
        if (-not $child.HasExited) {
            Stop-Process -Id $child.Id -Force
            $child.WaitForExit()
        }
    }
}
