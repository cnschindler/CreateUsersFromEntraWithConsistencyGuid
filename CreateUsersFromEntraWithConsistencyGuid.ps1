[cmdletbinding()]

Param(
    [Parameter(Mandatory = $true)]
    [string]$XMlFile,
    [string]$BasePath = 'C:\Temp'
)

# Logfile path and logging
[string]$LogFileNamePrefix = 'Create_Users'
[string]$LogfileFullPath = Join-Path -Path $BasePath (Join-Path 'Logs' ($LogFileNamePrefix + '_{0:yyyyMMdd-HHmmss}.log' -f [DateTime]::Now))
$Script:NoLogging

#File with user passwords
[string]$UserPasswordsFile = Join-Path -Path $BasePath (Join-Path 'Passwords' ('UserPasswords_{0:yyyyMMdd-HHmmss}.txt' -f [DateTime]::Now))
# Domain Controller to use
$dc = "srvad01.brucha.com"
# End Variable definition
#

function ConvertFrom-ImmutableIdToConsistencyGuid {
    <#
    .SYNOPSIS
        Immutable ID to Consistency GUID
    .DESCRIPTION
    #>
    [CmdletBinding()]
    [OutputType([GUID])]
    param
    (
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ImmutableId
    )
    process {
        [GUID][System.Convert]::FromBase64String($ImmutableID)
    }
}
function Write-LogFile {
    # Logging function, used for progress and error logging...
    # Uses the globally (script scoped) configured LogfileFullPath variable to identify the logfile and NoLogging to disable it.
    #
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$LogPrefix,
        [System.Management.Automation.ErrorRecord]$ErrorInfo = $null
    )
    # Prefix the string to write with the current Date and Time, add error message if present...

    if ($ErrorInfo) {
        $logLine = '{0:d.M.y H:mm:ss} : {1}: {2} Error: {3}' -f [DateTime]::Now, $LogPrefix, $Message, $ErrorInfo.Exception.Message
    }

    else {
        $logLine = '{0:d.M.y H:mm:ss} : {1}: {2}' -f [DateTime]::Now, $LogPrefix, $Message
    }

    if (!$Script:NoLogging) {
        # Create the Script:Logfile and folder structure if it doesn't exist
        if (-not (Test-Path $Script:LogfileFullPath -PathType Leaf)) {
            New-Item -ItemType File -Path $Script:LogfileFullPath -Force -Confirm:$false -WhatIf:$false | Out-Null
            Add-Content -Value 'Logging started.' -Path $Script:LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }

        # Write to the Script:Logfile
        Add-Content -Value $logLine -Path $Script:LogfileFullPath -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-Verbose $logLine
    }
    else {
        Write-Host $logLine
    }
}
function GeneratePassword {
    function Get-RandomCharacters($length, $characters) {
        $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
        $private:ofs = ''
        return [String]$characters[$random]
    }
    
    function Scramble-String([string]$inputString) {     
        $characterArray = $inputString.ToCharArray()   
        $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
        $outputString = -join $scrambledStringArray
        return $outputString 
    }
    
    $PW = Get-RandomCharacters -length 7 -characters 'abcdefghiklmnoprstuvwxyz'
    $PW += Get-RandomCharacters -length 2 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $PW += Get-RandomCharacters -length 3 -characters '1234567890'
    $PW += Get-RandomCharacters -length 1 -characters '!"$%&/()='
    $PW = Scramble-String $PW    
    Return $PW
}

function Write-UserPasswordsToFile {
    [CmdLetBinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$PW
    )

    $UserInfo = ($Username + ',' + $PW)

    # Create the Script:Logfile and folder structure if it doesn't exist
    if (-not (Test-Path $UserPasswordsFile -PathType Leaf)) {
        New-Item -ItemType File -Path $UserPasswordsFile -Force -Confirm:$false -WhatIf:$false | Out-Null
        Add-Content -Value 'Username,Password' -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }

    # Write to the Script:Logfile
    Add-Content -Value $UserInfo -Path $UserPasswordsFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Write-Verbose $UserInfo

}
function CreateADUser
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        [string]$GivenName,
        [string]$SurName,
        [string]$DisplayName,
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $true)]
        [guid]$ConsistencyGuid,
        [string]$mail,
        [array]$ProxyAddresses
    )

    # Initialize parameter hashtable
    $Parameters = @{}
    
    # For each Parameter of the current object
    foreach ($Parameter in $PSBoundParameters.GetEnumerator())
    {
        # if the Parameter has a value
        if ($Parameter.value)
    
        # Add the Parameter and it's value to the hashtable
        { $Parameters[$Parameter.Key] = $Parameter.Value }
    }

    $Parameters.Remove("ConsistencyGUID")
    $Parameters.Remove("mail")
    $Parameters.Remove("ProxyAddresses")
    
    if (-not [string]::IsNullOrWhiteSpace($DisplayName))
    {
        $Name = $DisplayName
    }
    
    else
    {
        $Name = $SamAccountName    
    }

    $Password = GeneratePassword
    $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String $Password

    $ConsistencyGuidBinary = $ConsistencyGuid.ToByteArray()

    # Create user and write password to file
    try
    {
        New-ADUser @Parameters -Name $Name -AccountPassword $SecurePassword -Server $DC -ErrorAction Stop
        Write-LogFile -Message  "Successfully created user $($SamAccountName)."
        Write-UserPasswordsToFile -Username $SamAccountName -PW $Password
        Enable-ADAccount -Identity $SamAccountName -Confirm:$false
    }

    catch
    {
        Write-LogFile -Message "Error creating user $($SamAccountName). The error is:" -ErrorInfo $_
    }

    # Clear mS-DS-ConsistencyGuid
    try
    {
        Set-ADUser -Identity $SamAccountName -Clear "mS-DS-ConsistencyGuid" -ErrorAction Stop
        Write-LogFile -Message "Successfully cleared mS-DS-ConsistencyGuid attribute on user $($SamAccountName)."
    }
    
    catch
    {
        Write-LogFile -Message "Error clearing mS-DS-ConsistencyGuid on user $($SamAccountName). The error is:" -ErrorInfo $_
    }

    # Write mS-DS-ConsistencyGuid
    try
    {
        Set-ADUser -Identity $SamAccountName -Add @{"mS-DS-ConsistencyGuid"=$ConsistencyGuidBinary} -ErrorAction Stop
        Write-LogFile -Message "Successfully set mS-DS-ConsistencyGuid attribute on user $($SamAccountName)."
    }
    
    catch
    {
        Write-LogFile -Message "Error setting mS-DS-ConsistencyGuid on user $($SamAccountName). The error is:" -ErrorInfo $_
    }

    if (-not [string]::IsNullOrWhiteSpace($mail))
    {
        # Write mail
        try
        {
            Set-ADUser -Identity $SamAccountName -Add @{"mail"=$mail} -ErrorAction Stop
            Write-LogFile -Message "Successfully set mail attribute on user $($SamAccountName)."
        }
        
        catch
        {
            Write-LogFile -Message "Error setting mail on user $($SamAccountName). The error is:" -ErrorInfo $_
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ProxyAddresses))
    {
        # Write mail
        try
        {
            Set-ADUser -Identity $SamAccountName -Add @{"proxyaddresses"=$ProxyAddresses} -ErrorAction Stop
            Write-LogFile -Message "Successfully set proxyaddresses attribute on user $($SamAccountName)."
        }
        
        catch
        {
            Write-LogFile -Message "Error setting proxyaddresses on user $($SamAccountName). The error is:" -ErrorInfo $_
        }
    }

}

$Users = Import-Clixml -Path $XMLFile
foreach ($user in $Users)
{
    $ConsistencyGuid = ConvertFrom-ImmutableIdToConsistencyGuid -ImmutableId $User.ImmutableID
    CreateADUser -UserPrincipalName $user.userPrincipalName -GivenName $user.givenName -SurName $user.surname -DisplayName $user.displayName -SamAccountName $user.onPremisesSamAccountName -ConsistencyGuid $ConsistencyGUID -mail $user.mail -ProxyAddresses $user.proxyaddresses
}
