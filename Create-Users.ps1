Import-Module ActiveDirectory
$csv = Import-Csv -Path "C:\Lab\users.csv"
$baseOU = "OU=Standard_Users,OU=_CORP_INFRASTRUCTURE,DC=corp,DC=local"

foreach ($user in $csv) {
    $targetOU = "OU=$($user.Department),$baseOU"
    
    # Auto-create department OU if it doesn't exist yet
    try {
        [void](Get-ADOrganizationalUnit -Identity $targetOU)
    } catch {
        New-ADOrganizationalUnit -Name $user.Department -Path $baseOU
    }

    $securePassword = ConvertTo-SecureString "InitialSecure2026!" -AsPlainText -Force
    $userParams = @{
        Name                  = "$($user.Firstname) $($user.Lastname)"
        GivenName             = $user.Firstname
        Surname               = $user.Lastname
        SamAccountName        = $user.Username
        UserPrincipalName     = "$($user.Username)@corp.local"
        Department            = $user.Department
        Title                 = $user.Title
        Path                  = $targetOU
        AccountPassword       = $securePassword
        Enabled               = $true
        ChangePasswordAtLogon = $true
    }

    New-ADUser @userParams
    Write-Host "[SUCCESS] Created user $($user.Username) in $($user.Department)" -ForegroundColor Green
}
