<#
.SYNOPSIS
    Automated Active Directory Inactive Account Auditing Script
.AUTHOR
    Chukwubuzor Perazim
#>

param(
    [int]$DaysInactive = 90,
    [string]$OutputPath = "C:\Lab\Inactive_Accounts_Report.csv"
)

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " ACTIVE DIRECTORY INACTIVE ACCOUNT AUDIT (Threshold: $DaysInactive Days)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$cutoffDate = (Get-Date).AddDays(-$DaysInactive)

# Query enabled accounts whose LastLogonDate is older than cutoff date or never logged on
$staleUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate, Department, Title, Created |
    Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt $cutoffDate } |
    Select-Object Name,
                  SamAccountName,
                  UserPrincipalName,
                  Department,
                  Title,
                  @{Name="LastLogonDate"; Expression={if ($_.LastLogonDate) {$_.LastLogonDate} else {"Never Logged On"}}},
                  Created

if ($staleUsers) {
    $staleUsers | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "[ALERT] Identified $($staleUsers.Count) stale/inactive enabled account(s)." -ForegroundColor Yellow
    Write-Host "[SUCCESS] Audit report exported to: $OutputPath`n" -ForegroundColor Green
    
    # Display table summary to console
    $staleUsers | Format-Table Name, SamAccountName, Department, LastLogonDate -AutoSize
} else {
    Write-Host "[OK] Zero stale accounts detected." -ForegroundColor Green
}
