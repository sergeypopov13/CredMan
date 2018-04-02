# CredMan

PowerShell Module: Low-level Credentials Management Cmdlets.

## Example

``` PowerShell
$ErrorActionPreference = "Stop"

Import-Module -ErrorAction Stop .\CredMan.psd1

$secret = ConvertTo-SecureString 'masterkey' -AsPlainText -Force
Set-GenericCredential -Name 'StorageAccount:test' -UserName 'AccountKey' -Secret $secret

$allCreds = Get-GenericCredential -Filter 'StorageAccount:*'

foreach ($cred in $allCreds)
{
    Write-Host "Name = $($cred.TargetName)"
    Write-Host "UserName = $($cred.UserName)"
    Write-Host "---"
}

$cred = Get-GenericCredential -Name 'StorageAccount:test'
$plainSecret = [System.Net.NetworkCredential]::new('', $cred.Secret).Password
Write-Host "Name = $($cred.TargetName)"
Write-Host "UserName = $($cred.UserName)"
Write-Host "Secret = $($plainSecret)"
Write-Host "---"

Remove-GenericCredential -Name 'StorageAccount:test'
```

## More Info

See [this article](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374731(v=vs.85).aspx#low_level_credentials_management_functions) for more information.
