#Requires -module Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups

Param (
    #Accepts both UPN and SAM Account Name
    [Parameter(Mandatory)]
    [String]$UserID
)

$ErrorActionPreference = 'Stop'

<#
We have a conditional access policy that blocks users outside of our network if they don't have MFA enabled
This means if we reset their MFA they wouldn't be able to log in to set their MFA back up unless they physically came into the office
To avoid that hassle, we have a group in AAD that temporarily bypasses that Conditional Access policy so that they can set their MFA back up immediately after reset
A separate script is used to remove users from this group on a nightly basis
#>
$MFABypassGroup = '### Some Group Name ###'

<#
We use certificate based authentication for unattended runs to log in via an app registration that has the necessary permissions to reset MFA
The certificate must be installed in the Personal Cert Store for the User account running the script, and MUST have the private key installed as well
App Registration needs the following API Permissions at minimum
    User.Read.All
    UserAuthenticationMethod.ReadWrite.All
#>
$CertBasedAuthData = @{
    ApplicationId         = '### App Registration Client ID ###'
    TenantId              = '### Azure Tenant ID ###'
    CertificateThumbprint = '### Thumbprint of Certifcate being used for Auth to App Registration'
}

Write-Host 'Attempting to connect to Graph'
Connect-MgGraph @CertBasedAuthData

# To test whether helpdesk entered a UPN or SAM account name, I typecast the input against [mailaddress] to see if it throws an error or not
$ErrorActionPreference = 'SilentlyContinue'
If ([mailAddress]$UserID) {
    $UPN = $true
} else {
    $UPN = $false
}
$ErrorActionPreference = 'Stop'

#List of properties we need Graph to return on a given user
$UserProperties = @(
    'Id',
    'OnPremisesSamAccountName',
    'UserPrincipalName'
)
#Searches for graph based on the findings from above
#The SAM Account Name needs the additional parameters because it's only filterable when doing an "Advanced Query", those additional paramters let Graph know this needs to be "Advanced"
If ($UPN) {
    $UserInfo = Get-MgUser -Filter "UserPrincipalName eq '$UserID'" -Property $UserProperties
} Else {
    $UserInfo = Get-MgUser -Filter "OnPremisesSamAccountName eq '$UserID'" -Property $UserProperties -ConsistencyLevel 'Eventual' -CountVariable 'Count'
}

#If user is found, outputs their data neatly for the log, otherwise sends a warning and exits
if (!$UserInfo) {
    Throw "User Not Found: No match for '$UserID' could be found in AAD"
}

<#
This function is used below is repeatedly called for each authentication method
Unfortunately, within graph, each individual auth method has it's own separate commands which makes this function somewhat bulky, but necessary to process through things.

Additionally, Graph won't allow you to delete someone's 'default' MFA method unless it's the final method still enabled. But Graph also doesn't give you a way to identify the default.
To get around this, there is some error detection to detect the default, and then it's re-tried later.
#>
function Remove-AuthMethod {
    param (
        [Parameter(Mandatory)]
        [String]$UserID,

        [Parameter(Mandatory)]
        [PSCustomObject]$Method
    )

    # Probably not needed, but here out of caution to avoid cross-contamination
    Remove-Variable 'AuthError' -Force -ErrorAction 'SilentlyContinue'

    # These are used for every method's removal
    $MethodArgs = @{
        UserId        = $UserID
        ErrorVariable = 'AuthError'			#Used as part of the error detection to find the default method
        ErrorAction   = 'SilentlyContinue'	#Needed so the script doesn't fail when it encounters the error from finding the default method
    }

    switch ($Method.Type) {
        'email' {
            Remove-MgUserAuthenticationEmailMethod @MethodArgs -EmailAuthenticationMethodId $Method.Id
        }
        'fido2' {
            Remove-MgUserAuthenticationFido2Method @MethodArgs -Fido2AuthenticationMethodId $Method.Id
        }
        'microsoftAuthenticator' {
            Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod @MethodArgs -MicrosoftAuthenticatorAuthenticationMethodId $Method.Id
        }
        'phone' {
            Remove-MgUserAuthenticationPhoneMethod @MethodArgs -PhoneAuthenticationMethodId $Method.Id
        }
        'softwareOath' {
            Remove-MgUserAuthenticationSoftwareOathMethod @MethodArgs -SoftwareOathAuthenticationMethodId $Method.Id
        }
        'temporaryAccessPass' {
            Remove-MgUserAuthenticationTemporaryAccessPassMethod @MethodArgs -TemporaryAccessPassAuthenticationMethodId $Method.Id
        }
        'windowsHelloForBusiness' {
            Remove-MgUserAuthenticationWindowsHelloForBusinessMethod @MethodArgs -WindowsHelloForBusinessAuthenticationMethodId $Method.Id
        }
        Default {
            # This shouldn't get hit currently, but is here in the case that MS adds more auth methods in the future.
            Throw "$($Method.Type): Encountered new unhandeled authentication method. Script needs updated to include removal commands associated with this new method."
        }
    }

    if ($AuthError.Exception.Message -like '*current default authentication method*') {
        # Labels this method as the 'Default' method so we know to try it again later
        return 'Default'
    } elseif ($AuthError) {
        # If it's some other error, just re-throw it so someone can look at it and handle it
        Throw $AuthError.Exception.Message
    } else {
        # If no error, we mark the method as removed
        return 'Removed'
    }
}

<#
Defines the object we want to create from the properties returned by each auth method, gets enforced in the Select-Object below
String replacements aren't strictly necessary, but are included for better human readability in logs and emails.
Each authentication method starts and ends with the exact same strings and this cleans those up so you are only left with the unique portion
Default and Removed fields are both used to track progress and reporting (report email has been removed from this public snippet)
#>
$MethodProperties = @(
    @{n = 'Type'; e = { ($_.AdditionalProperties.'@odata.type').Replace('#microsoft.graph.', '').Replace('AuthenticationMethod', '') } }
    'Id'
    @{n = 'Default'; e = { $False } }
    @{n = 'Removed'; e = { $False } }
)

# Gets all of the User's auth methods, then retrieves the Id and Type of method it is
# Password options are filtered out because that is the user's primary login/Single-Factor, and can not be removed
$Methods = Get-MgUserAuthenticationMethod -UserId $UserInfo.Id | Select-Object $MethodProperties | Where-Object { $_.Type -ne 'password' }

# If user did not have MFA enabled, prints a notice but still allows script to continue so that user is added into the temporary bypass group for registration
if (($Methods.count -eq 0) -or ($null -eq $Methods)) {
    Write-Host 'Authentication Methods Not Found'
} else {
    #Iterates through each method and attempts to delete it
    foreach ($authMethod in $Methods) {
        $Result = Remove-AuthMethod -UserId $UserInfo.Id -Method $authMethod

        if ($Result -eq 'Default') {
            $authMethod.Default = $true
        } elseif ($Result -eq 'Removed') {
            $authMethod.Removed = $true
        } else {
            # Shouldn't be possible to get here, but added as a failsafe
            Throw 'Unknown removal result'
        }

        # Once again, likely unneeded but added to avoid cross contamination
        Remove-Variable 'Result' -Force -ErrorAction 'SilentlyContinue'
    }

    <#
    This is what goes back through and re-attempts deletion of the default method
    In some cases, this code may not execute hence the if statements. For example, if the user only had 1 MFA method to begin with
    Or if the above loop just happened to hit things in the right order, this isn't executed
    #>
    if ($Methods.Default -contains $true) {
        $DefaultMethod = $Methods | Where-Object { $_.Default -eq $true }

        # Shouldn't be possible, but here in case something goes off the rails
        if ($DefaultMethod.Count -ge 2) {
            Throw 'Impossible Configuration: Multiple default methods found'
        } else {
            $Result = Remove-AuthMethod -UserId $UserInfo.Id -Method $DefaultMethod

            if ($Result -eq 'Removed') {
                $DefaultMethod.Removed = $true
            } else {
                # Shouldn't be possible to get here, but added as a failsafe
                Throw 'Unknown removal result'
            }
        }
    }
}

# Adding the user to the previously mentioned Conditional Access Bypass Group
$AzureExternalMFAEnabledGroup = Get-MgGroup -Filter "DisplayName eq '$MFABypassGroup'"

try {
    # New-MgGroupMember throws an error if the user is already in the group so it's wrapped in some error catching to ignore that specific error while still passing on others
    New-MgGroupMember -GroupId $AzureExternalMFAEnabledGroup.Id -DirectoryObjectId $UserInfo.Id
} catch {
    if ($_.exception -notlike '*One or more added object references already exist*') {
        Throw "Failed to add '$UserID' as member of group '$MFABypassGroup' which allows external MFA enrollment"
    }
}
