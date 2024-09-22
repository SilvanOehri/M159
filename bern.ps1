<#
Author:     Silvan Öhri
Date:       2024-09-22
Version:    1.0.1
#>

# import Active Directory module
Import-Module ActiveDirectory

################### vars ##############################

$childDomainBern = "be.nibbia.local"

# create ou Employees first
$childBaseOU = "OU=Employees,DC=be,DC=nibbia,DC=local"

#######################
# create OUs for bern (be.nibbia.local) 
#######################
New-ADOrganizationalUnit -Name "Entwicklung" -Path $childBaseOU
New-ADOrganizationalUnit -Name "Kundenservice" -Path $childBaseOU 
New-ADOrganizationalUnit -Name "Beratung" -Path "OU=Kundenservice,$childBaseOU" 
New-ADOrganizationalUnit -Name "Support" -Path "OU=Kundenservice,$childBaseOU" 

#######################
# defining users for bern (be.nibbia.local)
#######################
$bernUsers = @(
    @{UserPrincipalName = "WolfH@$childDomainBern"; Name = "Heinz Wolf"; Department = "Entwicklung"},
    @{UserPrincipalName = "MeierP@$childDomainBern"; Name = "Peter Meier"; Department = "Entwicklung"},
    @{UserPrincipalName = "WirthH@$childDomainBern"; Name = "Heidi Wirth"; Department = "Support"},
    @{UserPrincipalName = "KellerH@$childDomainBern"; Name = "Hans Keller"; Department = "Beratung"}
)

#######################
# add bern users to be.nibbia.local child domain
#######################
foreach ($user in $bernUsers) {
    switch ($user.Department) {
        "Entwicklung" { $ouPath = "OU=Entwicklung,$childBaseOU" }
        "Support" { $ouPath = "OU=Support,OU=Kundenservice,$childBaseOU" }
        "Beratung" { $ouPath = "OU=Beratung,OU=Kundenservice,$childBaseOU" }
    }
    New-ADUser -DisplayName $user.Name -Name $user.Name -SamAccountName $user.UserPrincipalName.Split("@")[0] -Path $ouPath -AccountPassword (ConvertTo-SecureString "SUPERSECUREPASSWORD???" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false 
}

Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName | Format-Table Name, DistinguishedName