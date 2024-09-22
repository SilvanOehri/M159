<#
Author:     Silvan Öhri
Date:       2024-09-22
Version:    1.0.2
#>

# import Active Directory module
Import-Module ActiveDirectory

################### vars ##############################

$parentDomain = "nibbia.local"

# create ou Employees first
$parentBaseOU = "OU=Employees,DC=nibbia,DC=local"

#######################################################
# create OUs for zurich (nibbia.local) 
#######################################################

New-ADOrganizationalUnit -Name "Verwaltung" -Path $parentBaseOU
New-ADOrganizationalUnit -Name "Vertrieb" -Path $parentBaseOU
New-ADOrganizationalUnit -Name "Entwicklung" -Path $parentBaseOU
New-ADOrganizationalUnit -Name "Kundenservice" -Path $parentBaseOU
New-ADOrganizationalUnit -Name "Beratung" -Path "OU=Kundenservice,$parentBaseOU"
New-ADOrganizationalUnit -Name "Support" -Path "OU=Kundenservice,$parentBaseOU"

#######################
# defining users for zurich (nibbia.local)
#######################
$zurichUsers = @(
    @{UserPrincipalName = "BaumannA@$parentDomain"; Name = "Andrea Baumann"; Department = "Verwaltung"},
    @{UserPrincipalName = "BeckC@$parentDomain"; Name = "Claudio Beck"; Department = "Verwaltung"},
    @{UserPrincipalName = "BetzB@$parentDomain"; Name = "Bernhard Betz"; Department = "Vertrieb"},
    @{UserPrincipalName = "KemperA@$parentDomain"; Name = "Andrea Kemper"; Department = "Entwicklung"},
    @{UserPrincipalName = "KaiserB@$parentDomain"; Name = "Bruno Kaiser"; Department = "Entwicklung"},
    @{UserPrincipalName = "KuhlC@$parentDomain"; Name = "Claudia Kuhl"; Department = "Support"},
    @{UserPrincipalName = "DauschM@$parentDomain"; Name = "Martin Dausch"; Department = "Beratung"}
)

#######################
# add zurich users to nibbia.local domain
#######################
foreach ($user in $zurichUsers) {
    switch ($user.Department) {
        "Verwaltung" { $ouPath = "OU=Verwaltung,$parentBaseOU" }
        "Vertrieb" { $ouPath = "OU=Vertrieb,$parentBaseOU" }
        "Entwicklung" { $ouPath = "OU=Entwicklung,$parentBaseOU" }
        "Support" { $ouPath = "OU=Support,OU=Kundenservice,$parentBaseOU" }
        "Beratung" { $ouPath = "OU=Beratung,OU=Kundenservice,$parentBaseOU" }
    }
 
    New-ADUser -DisplayName $user.Name -Name $user.Name -SamAccountName $user.UserPrincipalName.Split("@")[0] -Path $ouPath -AccountPassword (ConvertTo-SecureString "SUPERSECUREPASSWORD???" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false 
}

Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName | Format-Table Name, DistinguishedName