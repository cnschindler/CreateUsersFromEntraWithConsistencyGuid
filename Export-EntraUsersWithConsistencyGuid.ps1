Import-Module Microsoft.Entra
Connect-Entra -Scopes User.Read.All
$users = Get-EntraUser -Filter "userType eq 'Member'" -All | Where-Object onPremisesSamAccountName -ne $null | Select-Object onPremisesSamAccountName,ImmutableID,UserPrincipalName,givenname,surname,displayname,mail,proxyaddresses

$users | Export-Clixml -Path C:\Temp\user.xml
