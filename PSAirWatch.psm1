
<#
    .Synopsis
    Tests Connectivity to the AW Instance 
    .DESCRIPTION
    This is the first function which needs to be invoked before using the member functions to invoke REST API endpoints.
    This will create in-memory variables which will be used by later
    .EXAMPLE
    Example of how to use this cmdlet
    .EXAMPLE
    Another example of how to use this cmdlet
#>

New-Variable -Name hostname -Value $null -Scope local
New-Variable -Name headers -Value @{} -Scope local

function Get-CMSURLAuthorizationHeader
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Input the URL to be
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [uri]$URL,

        # Specify the Certificate to be used 
        [Parameter(Mandatory=$true,
                    ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    Begin
    {
        Write-Verbose -Message '[Get-CMSURLAuthorizationHeader] - Starting  Function'
        
    }
    Process
    {
       TRY 
       { 
            #Get the Absolute Path of the URL encoded in UTF8
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($Url.AbsolutePath))

            #Open Memory Stream passing the encoded bytes
            $MemStream = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$bytes) -ErrorAction Stop

            #Create the Signed CMS Object providing the ContentInfo (from Above) and True specifying that this is for a detached signature
            $SignedCMS = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $MemStream,$true -ErrorAction Stop

            #Create an instance of the CMSigner class - this class object provide signing functionality
            $CMSigner = New-Object -TypeName System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $Certificate -Property @{IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly} -ErrorAction Stop

            #Add the current time as one of the signing attribute
            $null = $CMSigner.SignedAttributes.Add((New-Object -TypeName System.Security.Cryptography.Pkcs.Pkcs9SigningTime))

            #Compute the Signatur
            $SignedCMS.ComputeSignature($CMSigner)

            #As per the documentation the authorization header needs to be in the format 'CMSURL `1 <Signed Content>'
            #One can change this value as per the format the Vendor's REST API documentation wants.
            $CMSHeader = '{0}{1}{2}' -f 'CMSURL','`1 ',$([System.Convert]::ToBase64String(($SignedCMS.Encode())))
            Write-Output -InputObject $CMSHeader
        }
        Catch
        {
            Write-Error -Exception $_.exception -ErrorAction stop
        }
    }
    End
    {
        Write-Verbose -Message '[Get-CMSURLAuthorizationHeader] - Ending  Function'
    }
}
function Connect-AWInstance
{
    [CmdletBinding(DefaultParameterSetName='Certificate')]
    [OutputType([System.Collections.Hashtable])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        #Put a Validate Pattern here to match *.Airwatch.com
        [string]$Hostname,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$APIKey,

        [Parameter(Mandatory,
                    ParameterSetName='Credential')]
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory,
                    ParameterSetName='Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate


    )

    Begin
    {
        Write-Verbose -Message '[Connect-AWInstance] Begin - Starting the Function'
        $Url = "https://$Hostname/API/v1/help"
    }
    Process
    {
        Switch ($PSCmdlet.ParameterSetName)
        {
            'Credential'
            {
                try
                {
                    $EncodedUsernamePassword = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($('{0}:{1}' -f $Credential.UserName, $Credential.GetNetworkCredential().Password)))
                    $Headers = @{'Authorization' = "Basic $($EncodedUsernamePassword)";'aw-tenant-code' = "$APIKey";'Content-type' = 'application/json'}
            
                    $null = Invoke-RestMethod -Method Get -Uri $Url -Headers $Headers -ErrorAction Stop 
                    Write-Verbose -Message '[Connect-AWInstance] Success connecting to the AirWatch Instance'
                    $Script:Hostname = $Hostname #set the Module Variable now
                    $Script:Headers = $Headers #set the Module Headers now
                    
                    #Write-Output -InputObject $Headers
                }
                catch
                {
                    Write-Error -Exception $_.exception -ErrorAction Stop
                }
            }
            'Certificate'
            {
               try
                {
                    
                    $Headers = @{'Authorization' = "$(Get-CMSURLAuthorizationHeader -URL $Url -Certificate $Certificate)";'aw-tenant-code' = "$APIKey";'Content-type' = 'application/json'}
            
                    $null = Invoke-RestMethod -Method Get -Uri $Url -Headers $Headers -ErrorAction Stop 
                    Write-Verbose -Message '[Connect-AWInstance] Success connecting to the AirWatch Instance'
                    $Script:Hostname = $Hostname
                    $Headers.Authorization = {Get-CMSURLAuthorizationHeader -URL $Url -Certificate $Certificate} #set this 
                    $Script:PSDefaultParameterValues = @{'Get-CMSURLAuthorizationHeader:Certificate'=$Certificate}
                    $Script:Headers = $Headers #set the Script Headers
                    

                    Write-Output -InputObject $Headers
                   
                }
                catch
                {
                    Write-Error -Exception $_.exception -ErrorAction Stop
                }  
            }
        }

    }
    End
    {
         Write-Verbose -Message '[Connect-AWInstance] END - Ending the Function'
    }
}

#region User Management



function Get-AWUser
{
    [CmdletBinding(DefaultParameterSetName = 'Search')]
    [OutputType([PSObject[]])]
    Param
    (
        
        [Parameter(ParameterSetName = 'Search',ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$username,

        # Specify the User first name
        [Parameter(ParameterSetName = 'Search',ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Firstname,

        # Specify the User last name
        [Parameter(ParameterSetName = 'Search',ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$LastName,

        # Specify the Email Address
        [Parameter(ParameterSetName = 'Search',ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$EmailAddress,

        #specify the Location group Id
        [Parameter(ParameterSetName = 'Search',ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$LocationGroupId,

        #Specify the Role assigned to the User        
        [Parameter(ParameterSetName = 'Search',ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Role,

        #Specify the Enrollment User ID [It's an integer which uniquely identifies the User in DB]      
        [Parameter(ParameterSetName = 'UserID',ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [int[]]$EnrollmentUserID



        
    )

    Begin
    {
        Write-Verbose -Message '[Get-AWBasicUser] Begin - Starting the Function'
        
        #need to remove any common parameters specified..will write something more elegant to handle it later
        $null = $PSBoundParameters.Remove('Verbose') 
        #creating the URL to be used later
        $PSBoundParameters.Keys | ForEach-Object -Begin { $Url = "https://$Global:Hostname/API/v1/system/users/search?"} -Process {$Url = "$url{0}={1}&" -f $_, $($PSBoundParameters.($_ ))} -End {$Url = $Url.Trim('&')}

        Write-Verbose -Message "[Get-AWBasicUser] Begin - Created the REST URL `n $Url"
    }
    Process
    {
        Switch ($PSCmdlet.ParameterSetName)
        {
            'Search'
            {
                try
                {
                    Write-Verbose -Message "[Get-AWBasicUser] Process - Hitting the REST Endpoint url to search the User information `n $Url"
                    #call the rest endpoint based on the Authentication used
                    $local:Headers = $Script:Headers.Clone()
                    if (($header.Auth) -is [System.Management.Automation.ScriptBlock]) {$local:Headers = & ($Script:Headers.Authorization)}
                    $result = Invoke-RestMethod -Method Get -Uri $Url -Headers $local:Headers  -ErrorAction Stop
                    $Users = $result.Users | Select-Object -Property *, @{L = 'EnrollmentUserID';E = {$_.ID.Value}} -ExcludeProperty ID
                    Write-Output -InputObject  $Users
                }
                catch
                {
                    Write-Warning -Message "[Get-AWBasicUser] Process - Caught exception --> $_.exception"
                }
            }
            
            'UserID'
            {
                foreach ($id in $EnrollmentUserID)  
                {
                    $Url = "https://$Global:Hostname/API/v1/system/users/$($id)"
                    Write-Verbose -Message "[Get-AWBasicUser] Process - Hitting the REST Endpoint url to get the User with ID -> $id `n $Url"
                    $result = Invoke-RestMethod -Method Get -Uri $Url -Headers $Global:Headers  -ErrorAction Stop
                    $User = $result |  Select-Object -Property *, @{L = 'EnrollmentUserID';E = {$_.ID.Value}} -ExcludeProperty ID
                    Write-Output -InputObject $User
                }  
            }
        }
    }
    End
    {
        Write-Verbose -Message '[Get-AWBasicUser] End - Ending the Function'
    }
}

function Remove-AWUser
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [int[]]$EnrollmentUserID        


    )

    Begin
    {
        Write-Verbose -Message '[Remove-AWBasicUser] Begin - Starting the Function'
        
    }
    Process
    {
        TRY
        {
            foreach ($id in $EnrollmentUserID)
            {
                $Url = "https://$Global:Hostname/API/v1/system/users/$id/delete"
                Write-Verbose -Message "[Remove-AWBasicUser] PROCESS - created the URL`n $Url"
                $null = Invoke-RestMethod -Method DELETE -Uri $Url -Headers $Global:Headers -ErrorAction Stop 
                Write-Verbose -Message "[Remove-AWBasicUser] PROCESS - Removed user with ID -> $id"
            }
        }
        CATCH
        {
            Write-Warning -Message '[Remove-AWBasicUser] PROCESS -  Something went wrong'
        }
    }
    End
    {
        Write-Verbose -Message '[Remove-AWBasicUser] Begin - Ending the Function'
    }
}


function New-AWBasicUser
{
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    Param
    (
        

        #Specify the Siwtch to create active Users [By Default creates Inactive Users]
        [Switch]$Active,
        
        #Specify the Username (needs to be unique)
        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]        
        [ValidateNotNullOrEmpty()]
        [Alias('sAMAccountName')]
        [String]$UserName,

        #Specify the Password
        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Password,

        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$FirstName,

        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$LastName,

        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]
        [ValidatePattern('^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$')]
        [String]$EmailAddress,

        #Specify the Role associated with the User in AirWatch [Basic or Full Access]
        [Parameter(ValueFromPipelineBypropertyName = $true,
                    ValueFromRemainingArguments = $true)]
        [ValidateSet('Basic Access','Full Access')]
        [String]$Role='Basic Access',

        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$LocationGroupId,

        #Input the Contact no of the User
        [Parameter(ValueFromPipelineBypropertyName = $true)]
        [Alias('PhoneNumber','Mobile')]
        [String]$ContactNumber

        

    )

    Begin
    {
        Write-Verbose -Message '[New-AWBasicUser] Begin - Starting the Function'
        $Url = "https://$Global:Hostname/API/v1/system/users/adduser"
    }
    Process
    {
        $hash = @{
                    'UserName'=$UserName;
                    'Password'=$Password;
                    'FirstName'=$FirstName;
                    'LastName'=$LastName;
                    'Status'=$Status;
                    'Email'=$EmailAddress;
                    'SecurityType'='Basic';
                    'ContactNumber'=$ContactNumber;
                    'LocationGroupId'=$LocationGroupId;
                    'Role'=$Role
                } | ConvertTo-Json  #we create a JSON Object here

        try
        {
                            
            Write-Verbose -Message '[New-AWBasicUser] Process - Hitting the REST Endpoint url to create the basic User'
            #call the rest endpoint
            If (! ($Global:Headers.ContainsKey('Authorization')))
            {
                $localheader = $Global:Headers
                $localheader.Add('Authorization',$(Get-CMSURLAuthorizationHeader -URL $Url))
            }
            $UserID =Invoke-RestMethod -Method Post -Uri $Url -Headers $localheader -Body $hash -ErrorAction Stop
            
            $hash | ConvertFrom-Json | Select-Object -Property *,@{Label='UserID';Expression={$UserID.Value}}
        }
        catch
        {
            Write-Warning -Message "[New-AWBasicUser] Process - Caught exception --> $_.exception"
        }

    }          
    
    
    End
    {
        Write-Verbose -Message '[New-AWBasicUser] End - Ending the Function'
    }

}

function New-AWDirectoryUser
{
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    Param
    (
        

        #Specify the Siwtch to create active Users [By Default creates Inactive Users]
        [Switch]$Active,
        
        #Specify the Username (needs to be unique)
        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]        
        [ValidateNotNullOrEmpty()]
        [Alias('sAMAccountName')]
        [String]$UserName,

         #Specify the Role associated with the User in AirWatch [Basic or Full Access]
        [Parameter(ValueFromPipelineBypropertyName = $true,
                    ValueFromRemainingArguments = $true)]
        [ValidateSet('Basic Access','Full Access')]
        [String]$Role='Basic Access',

        [Parameter(Mandatory = $true,
                   ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$LocationGroupId,

        #Input the Contact no of the User
        [Parameter(ValueFromPipelineBypropertyName = $true)]
        [Alias('PhoneNumber','Mobile')]
        [String]$ContactNumber

        

    )

    Begin
    {
        Write-Verbose -Message '[New-AWDirectoryUser] Begin - Starting the Function'
        $Url = "https://$Global:Hostname/API/v1/system/users/adduser"
    }
    Process
    {
        $hash = @{
                    'UserName'=$UserName;
                    'Status'= $($Active.IsPresent);
                    'SecurityType'='Directory';
                    'ContactNumber'=$ContactNumber
                    'LocationGroupId'=$LocationGroupId
                    'Role'=$Role
                } | ConvertTo-Json  #we create a JSON Object here

        try
        {
                            
            Write-Verbose -Message '[New-AWDirectoryUser] Process - Hitting the REST Endpoint url to create the basic User'
            
            #call the rest endpoint
            $UserID = Invoke-RestMethod -Method Post -Uri $Url -Headers $global:headers -Body $hash -ErrorAction Stop
            $hash | ConvertFrom-Json | Select-Object -Property *,@{Label='UserID';Expression={$UserID.Value}}
        }
        catch
        {
            Write-Warning -Message "[New-AWDirectoryUser] Process - Caught exception --> $_.exception"
        }
            
    }

    End
    {
        Write-Verbose -Message '[New-AWDirectoryUser] End - Ending the Function'
    }

}

function Move-AWUserToLocationGroup
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # Specify the Enrollment User Id of the User to be moved
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [Int[]]
        $EnrollmentUserId,

        # Specify the LocationGroupID of the Destination OG
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias('DestinationLocationGroupID')]
        [String]$LocationGroupId
    )

    Begin
    {
        Write-Verbose -Message '[Move-AWUserToLocationGroup] - Starting  Function'
        
    }
    Process
    {
        Foreach ($Id in $EnrollmentUserId)
        {
             Write-Verbose -Message " [Move-AWUserToLocationGroup] - Processing the User with ID - $ID"
             $url = "https://$global:Hostname/API/v1/system/users/$Id/changelocationgroup?targetLG=$LocationGroupId"
             Write-Debug -Message "$url"
            Try 
            {
               
                $null = Invoke-RestMethod -Method Post -Uri $url -Headers $Global:Headers -ErrorAction Stop
                Write-Verbose -Message " [Move-AWUserToLocationGroup] - Successfully moved $User"
            
            }
            Catch
            {
                 Write-Error -Exception $_.exception -ErrorAction Stop
            }
             
        }
        
    }
    End
    {
         Write-Verbose -Message '[Move-AWUserToLocationGroup] - Ending the Function'   
    }
}

#URI – https://host/API/v1/system/users/{EnrollmentUserID}/registerdevice

function Register-AWDeviceForUser
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ALias('EnrollmentUserId')]
        $UserId,

        # Param2 help description
        [Parameter(Mandatory,
                    ValueFromPipelineByPropertyName)]
        $UserName,

        [Parameter(Mandatory,
                    ValueFromPipelineByPropertyName)]
        $LocatioGroupId,

        [Parameter(Mandatory,
                    ValueFromPipelineByPropertyName)]
        $Email
    )

    Begin
    {
         Write-Verbose -Message '[Register-AWDeviceForUser] - Starting  Function'
         $url =  "https://$global:hostname/API/v1/system/users/$UserId/registerdevice"
        
    }
    Process
    {
        $hash = @{
                    'Friendlyname'= "{0} 's Device" -f $UserName;
                    'TOEmailAddress'= $Email;
                    'LocationGroupId'=$LocationGroupId
                } | ConvertTo-Json  #we create a JSON Object here

        try
        {
                            
            Write-Verbose -Message '[Register-AWDeviceForUser]  Process - Hitting the REST Endpoint url to create the basic User'
            
            #call the rest endpoint
             Invoke-RestMethod -Method Post -Uri $Url -Headers $global:headers -Body $hash -ErrorAction Stop
            
        }
        catch
        {
            Write-Warning -Message "[Register-AWDeviceForUser]  Process - Caught exception --> $_.exception"
        }
    }
    End
    {
    }
}


#endregion User Management


#region Device Management

function Get-AWDevice
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String[]]$User,

        # Specify the Model of the Device
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Model
    )

    Begin
    {
        $null = $PSBoundParameters.Remove('Verbose')
        #creating the URL to be used later
        $PSBoundParameters.Keys | ForEach-Object -Begin {$Url = "https://$Global:Hostname/API/v1/mdm/devices/search?" }  -Process { $Url = "$url{0}={1}&" -f $_, $($PSBoundParameters.($_ )) }  -End { $Url = $Url.Trim('&') }
        Write-Verbose -Message "[Get-AWDevice] Begin - Created the REST URL `n $Url"
    }
    Process
    {
        try
        {
            Write-Verbose -Message '[Get-AWDevice] Process - Hitting the REST Endpoint url to get the User information'
            #call the rest endpoint
            $result = Invoke-RestMethod -Method Get -Uri $Url -Headers $Global:Headers  -ErrorAction Stop
            $result = $result.Devices | Select-Object -Property *, @{L = 'DeviceID';E = {$($_.id.Value)}} -ExcludeProperty ID
            Write-Output -InputObject  $result
        }
        catch
        {
            Write-Warning -Message "[Get-AWDevice] Process - Caught exception --> $_.exception"
        }
    }
    End
    {
    }
}

function Move-AWDeviceToLocationGroup
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # Specify the Enrollment User Id of the User to be moved
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [Int[]]
        $DeviceId,

        # Specify the LocationGroupID of the Destination OG
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [Alias('DestinationLocationGroupID')]
        [String]$LocationGroupId
    )

    Begin
    {
        Write-Verbose -Message '[Move-AWDeviceToLocationGroup] - Starting  Function'
        
    }
    Process
    {
        Foreach ($Id in $DeviceId)
        {
             Write-Verbose -Message " [Move-AWDeviceToLocationGroup] - Processing the User named $user"
             $url = "https://$global:Hostname/API/v1/mdm/devices/$Id/changeorganizationgroup/$LocationGroupId"
             Write-Debug -Message "$url"
            Try 
            {
               
                $null = Invoke-RestMethod -Method Post -Uri $url -Headers $Global:Headers -ErrorAction Stop
                Write-Verbose -Message " [Move-AWDeviceToLocationGroup] - Successfully moved $User"
            
            }
            Catch
            {
                 Write-Error -Exception $_.exception -ErrorAction Stop
            }
             
        }
        
    }
    End
    {
         Write-Verbose -Message '[Move-AWDeviceToLocationGroup] - Ending the Function'   
    }
}


function Get-AWDeviceForUser
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String[]]$User,

        # Specify the Model of the Device
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]$Model
    )

    Begin
    {
        $null = $PSBoundParameters.Remove('Verbose')
        #creating the URL to be used later
        $PSBoundParameters.Keys | ForEach-Object -Begin {$Url = "https://$Global:Hostname/API/v1/mdm/devices/search?" }  -Process { $Url = "$url{0}={1}&" -f $_, $($PSBoundParameters.($_ )) }  -End { $Url = $Url.Trim('&') }
        Write-Verbose -Message "[Get-AWDevice] Begin - Created the REST URL `n $Url"
    }
    Process
    {
        try
        {
            Write-Verbose -Message '[Get-AWDevice] Process - Hitting the REST Endpoint url to get the User information'
            #call the rest endpoint
            $result = Invoke-RestMethod -Method Get -Uri $Url -Headers $Global:Headers  -ErrorAction Stop
            
             $result.Devices |
                            ForEach-Object -Process {
                                                    $_.ModelID = $($_.modelID.Id.Value);
                                                    $_.LocationGroupId =$($_.LocationGroupId.id.Value);
                                                    $_.PlatformID = $($_.PlatformId.Id.Value);
                                                    $_.UserID = $($_.UserID.ID.Value);
                                                    $_ | Add-Member -MemberType NoteProperty -name 'DeviceID' -Value  $($_.id.Value)
                                                 } 
            $result.devices
           # Write-Output -InputObject  $result
        }
        catch
        {
            Write-Warning -Message "[Get-AWDevice] Process - Caught exception --> $_.exception"
        }
    }
    End
    {
    }
}

#endregion Device Management


#region Location Group Advanced Functions

function New-AWLocationGroup
{
    [CmdletBinding()]
    [OutputType([PSOBject[]])]
    Param
    (
        # Specify the name of the Location Group [Mandatory]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Name',
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        [System.String]$Name,

        [Parameter(Mandatory = $true,ValueFromPipelineByPropertyName = $true)]
        [String]$ParentOGName,

        # Desired Group ID 
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupID,

        #Specify the LocationGroupType [Default - Container type]
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Global','Customer','Partner','Container')]
        [String]$LocationGroupType = 'Container',

        #Specify the Country for the OG
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Country,

        #Specify the Locale for the OG
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Locale = 'English (United States)',


        #By default adds the default location
        [Switch]$AddDefaultLocation = $true
        
    )

    Begin
    {
        Write-Verbose -Message '[New-AWLocationGroup] Begin - Starting the Function'
    }
    Process
    {
        TRY 
        {
            $Parent = Get-AWLocationGroup -Name "$ParentOGName"  #handle the case where more than one OG are returned of the same name

            if (! $Parent)
            {
                Write-Error -Message "[New-AWLocationGroup] Begin - Couldn't find any OG with the name $ParentOGName " -ErrorAction Stop
            }
            $Url = "https://$Global:Hostname/API/v1/system/groups/$($parent.LocationGroupID)/creategroup"
                
            #This Parameter set is invoked when all entries are specified 
            $hash = @{
                        'Name' = $Name;
                        'GroupID' = $GroupID;
                        'LocationGroupType' = $LocationGroupType;
                        'Country' = $Country;
                        'Locale' = $Locale;
                        'AddDefaultLocation' = $AddDefaultLocation.IsPresent                               
                    } 
                    
            $result = Invoke-RestMethod  -Method Post -Headers $Global:Headers -Uri $Url -Body ($hash |  ConvertTo-Json)  -ErrorAction Stop

            $hash.add('LocationGroupId',"$($result.value)")
            $hash.add('ParentLocationGroupName',"$($Parent.Name)")
            $Object = New-Object -Property $hash -TypeName PSObject

            Write-Output -InputObject $Object
        }
        CATCH
        {
            Write-Error -Exception $_.exception  -ErrorAction Stop
        }
            
    }
    End
    {
         Write-Verbose -Message '[New-AWLocationGroup] END - Ending the Function'
    }
}

function Set-AWLocationGroup
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    Param
    (
        # Specify the Name of the Location Group [Allows partial Name]
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
        $Name,

        # Param2 help description
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$NewName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$GroupID,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Country,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Locale

    )

    Begin
    {
        Write-Verbose -Message '[Set-AWLocationGroup] Begin - Starting the Function'
        
    }
    Process
    {
        TRY
        {
            if ($OG = @(Get-AWLocationGroup -Name $Name -ErrorAction stop))
            {
                if ($OG.count -gt 1)
                {
                    $OG = $OG | Out-GridView -Title 'Select the OG (single) on which to perform the operation'  -OutputMode Single
                }
                
                $Url = "http://$Global:Hostname/API/v1/system/groups/$($OG.LocationGroupID)/update"
                Write-Verbose -Message "[Set-AWLocationGroup] PROCESS - Created the URL `n $URl"

                #one has to always specify Locale and Country, if not then set them to the original 
                if (! $NewName) 
                {
                    $NewName = $OG.Name
                }
                if (! $Locale )
                {
                    $Locale = $OG.Locale
                }
                if (! $Country ) 
                {
                    $Country = $OG.Country
                }
                if (! $PSBoundParameters.ContainsKey('GroupId')) 
                {
                    $GroupID = $OG.GroupID
                }


                $hash = @{
                            'Name' = $NewName;
                            'GroupID' = $GroupID;
                            'Country' = $Country;
                            'Locale' = $Locale;
                        
                        }

                $null = Invoke-RestMethod -Method Post -Uri $Url -Body ($hash | ConvertTo-Json ) -Headers $Global:Headers -ErrorAction Stop

                Write-Verbose -Message '[Set-AWLocationGroup] PROCESS - Successfully update the OG'

                Get-AWLocationGroup -Name $NewName -Type $OG.LocationGroupType $GroupID -ErrorAction stop
            }
            else
            {
                Write-Warning -Message "[Set-AWLocationGroup] PROCESS - Couldn't find an OG with name $Name"
            }
        }
        CATCH
        {
            Write-Error -Exception $_.exception -ErrorAction stop
        }
    }
    End
    {
        Write-Verbose -Message '[Set-AWLocationGroup] END - Ending the Function'
    }
}

function Get-AWLocationGroup
{
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    Param
    (
        #Specify the name of the Location group
        [Parameter(Mandatory,ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$Name,

        # Specify the type of the OG
        [Parameter(ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Type,

        # Specify the OG Group ID
        [Parameter(ValueFromPipelineBypropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$GroupID

        
    )

    Begin
    {
        Write-Verbose -Message '[Get-AWLocationGroup] Begin - Starting the Function'
        
        #need to remove any common parameters specified..will write something more elegant to handle it later
        $null = $PSBoundParameters.Remove('Verbose')
        #creating the URL to be used later
        $PSBoundParameters.Keys | ForEach-Object -Begin {$Url = "https://$Global:Hostname/API/v1/system/groups/search?" }  -Process { $Url = "$url{0}={1}&" -f $_, $($PSBoundParameters.($_ )) }  -End { $Url = $Url.Trim('&') }
        Write-Verbose -Message "[Get-AWLocationGroup] Begin - Created the REST URL `n $Url"
    }
    Process
    {
        try
        {
            Write-Verbose -Message '[Get-AWLocationGroup] Process - Hitting the REST Endpoint url to get the User information'
            #call the rest endpoint
            $result = Invoke-RestMethod -Method Get -Uri $Url -Headers $Global:Headers  -ErrorAction Stop
            $result = $result.LocationGroups | Select-Object -Property *, @{L = 'LocationGroupID';E = {
                    $($_.id.Value)
                }
            } -ExcludeProperty ID
            Write-Output -InputObject  $result
        }
        catch
        {
            Write-Warning -Message "[Get-AWLocationGroup] Process - Caught exception --> $_.exception"
        }
        
    }
    End
    {
        Write-Verbose -Message '[Get-AWLocationGroup] End - Ending the Function'
    }
}


function Get-AWLocationGroupUsers
{
   [CmdletBinding()]
    [OutputType([PSObject[]])]
    Param
    (
        #Specify the name of the LocationGroupID property here
        [Parameter(Mandatory,ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$LocationGroupID      

        
    )

    Begin
    {
        Write-Verbose -Message '[Get-AWLocationGroupUsers] Begin - Starting the Function'
        
        $Url = "https://$Global:Hostname/API/v1/system/groups/$($LocationGroupID)/getusers" 
        Write-Verbose -Message "[Get-AWLocationGroup] Begin - Created the REST URL `n $Url"
    }
    Process
    {
        try
        {
            Write-Verbose -Message '[Get-AWLocationGroup] Process - Hitting the REST Endpoint url to get the User information'
            #call the rest endpoint
            $result = Invoke-RestMethod -Method Get -Uri $Url -Headers $Global:Headers  -ErrorAction Stop
            $Users = $result | Select-Object -Property *, @{L = 'UserID';E = {$($_.id.Value)}} -ExcludeProperty ID
            Write-Output -InputObject  $Users
        }
        catch
        {
            Write-Warning -Message "[Get-AWLocationGroup] Process - Caught exception --> $_.exception"
        }
        
    }
    End
    {
        Write-Verbose -Message '[Get-AWLocationGroup] End - Ending the Function'
    }
}


 function Remove-AWLocationGroup
 {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    #[OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
        [int[]]$LocationGroupID,
 
        [Switch]$Force
    )
 
    Begin
    {
        $RejectAll = $false;
        $ConfirmAll = $false;
        Write-Verbose -Message '[Remove-AWLocationGroup] BEGIN - Starting the Function'
        
    }
    Process
    {       
        foreach($ID in $LocationGroupID) 
        {
            if($PSCmdlet.ShouldProcess("Remove the OG with LocationGroupID '$($ID)'?",'Removing LocationGroup' )) {
                if($Force -Or $PSCmdlet.ShouldContinue("Are you REALLY sure you want to remove the OG with OGId'$($ID)'?", 'Removing OG', [ref]$ConfirmAll, [ref]$RejectAll)) 
                {
                    Try 
                    {
                        $URL = "https://$Global:Hostname/API/v1/system/groups/$ID/delete"
                        Write-Verbose -Message '[Remove-AWLocationGroup] PROCESS - Deleting the LocationGroup'
                        $null = Invoke-RestMethod -Method Delete -Uri $URL -Headers $Global:headers -ErrorAction Stop
                    } 
                    Catch
                    {
                            Write-Error -Exception $_.exception  -ErrorAction Stop
                    }
                
                }
            }
        }
    }
    End
    {
      Write-Verbose -Message '[Remove-AWLocationGroup] END - Ending the Function'  
    }
}



#endregion Location Group Advanced Functions



#region Export the Module members

#Export-ModuleMember -Function *-AW* -Variable Hostname,Headers 


#endregion
# SIG # Begin signature block
# MIIOfwYJKoZIhvcNAQcCoIIOcDCCDmwCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUrT03S6ormElZ6y008WSvCtt9
# Dg2gggvEMIIFGTCCBAGgAwIBAgIQC0japWK58eEmaEk9Yy13dzANBgkqhkiG9w0B
# AQUFADBvMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMS4wLAYDVQQDEyVEaWdpQ2VydCBBc3N1cmVk
# IElEIENvZGUgU2lnbmluZyBDQS0xMB4XDTE0MTAyMzAwMDAwMFoXDTE1MTAyODEy
# MDAwMFowbzELMAkGA1UEBhMCSU4xEjAQBgNVBAgTCUthcm5hdGFrYTESMBAGA1UE
# BxMJQmFuZ2Fsb3JlMRswGQYDVQQKExJEZWVwYWsgU2luZ2ggRGhhbWkxGzAZBgNV
# BAMTEkRlZXBhayBTaW5naCBEaGFtaTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAKNLwYqd4Lu8CRmyuGGG8+1UIXBfkJmn0NrtUXtxM/3xLzu406RGNx2d
# LnCmT0ESH1vGyqYOkusoVLt04KMxVStD1PZnCNnorI/TKM0OKAfcsUuIb5E9KJHK
# e6Gm2RfL3F/N0Tbi1AcjrjKSs7fOTQREvlFcFq/DTOSqE/vLfFH2RP+h+BB73g0v
# wMGNV7iSHbUtiMIqrWUFwpiHOhBii8vfE8nkg6jepo+TaleGpBaXpvcVv8tKZpAP
# kMOpcepYdQE3rIocAGES5SA9jzwIZVXbHgmygt+30TQhCkSwbUJ7L/E6mJj2OfL3
# 4StyY+gsn3HW9ygrxVV7hmw2gSZx3xkCAwEAAaOCAa8wggGrMB8GA1UdIwQYMBaA
# FHtozimqwBe+SXrh5T/Wp/dFjzUyMB0GA1UdDgQWBBSCvErN9s7DnvsZs0HI+sXa
# ZJ8l8zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwbQYDVR0f
# BGYwZDAwoC6gLIYqaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL2Fzc3VyZWQtY3Mt
# ZzEuY3JsMDCgLqAshipodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vYXNzdXJlZC1j
# cy1nMS5jcmwwQgYDVR0gBDswOTA3BglghkgBhv1sAwEwKjAoBggrBgEFBQcCARYc
# aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBggYIKwYBBQUHAQEEdjB0MCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTAYIKwYBBQUHMAKG
# QGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENv
# ZGVTaWduaW5nQ0EtMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQUFAAOC
# AQEAjrxX9wBnP9I7KGicJJfsry6zSTyrhCRH8k2iYJxqbGZnJ7taBAe1W9XbsSqs
# xOd392fmChn435/hPzrJFl7GbXL5tE/OsJGUjtD02rfFx1W7lI5Wt76NY1QKL48C
# gbUqAbFfbA+zwAAPGbK4t6OPYgqc8p/TRj+MOaAhM/LtQXmCfu1PcF4vtp5XOb1h
# 8WqP5W12ZJvYFmlL7y5BNMyWlvFhkGNfzDoLJJU5kk36xaqJurb9znuCevkwpsn+
# TSyHNC2dMZ6GIy5Lcn3P5H+6LYbkliqrUWWmPr+bETvWQT4jfk1Js3qiEORj405J
# v8Btw626MErsX1fdj8pATOuFAjCCBqMwggWLoAMCAQICEA+oSQYV1wCgviF2/cXs
# bb0wDQYJKoZIhvcNAQEFBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGln
# aUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTExMDIxMTEyMDAwMFoXDTI2MDIx
# MDEyMDAwMFowbzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEuMCwGA1UEAxMlRGlnaUNlcnQgQXNz
# dXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EtMTCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBAJx8+aCPCsqJS1OaPOwZIn8My/dIRNA/Im6aT/rO38bTJJH/qFKT
# 53L48UaGlMWrF/R4f8t6vpAmHHxTL+WD57tqBSjMoBcRSxgg87e98tzLuIZARR9P
# +TmY0zvrb2mkXAEusWbpprjcBt6ujWL+RCeCqQPD/uYmC5NJceU4bU7+gFxnd7XV
# b2ZklGu7iElo2NH0fiHB5sUeyeCWuAmV+UuerswxvWpaQqfEBUd9YCvZoV29+1aT
# 7xv8cvnfPjL93SosMkbaXmO80LjLTBA1/FBfrENEfP6ERFC0jCo9dAz0eotyS+BW
# tRO2Y+k/Tkkj5wYW8CWrAfgoQebH1GQ7XasCAwEAAaOCA0MwggM/MA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzCCAcMGA1UdIASCAbowggG2MIIB
# sgYIYIZIAYb9bAMwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2ljZXJ0
# LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFWHoIB
# UgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkA
# YwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEA
# bgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMA
# UABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkA
# IABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwA
# aQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8A
# cgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMA
# ZQAuMBIGA1UdEwEB/wQIMAYBAf8CAQAweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmw0LmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwHQYDVR0OBBYE
# FHtozimqwBe+SXrh5T/Wp/dFjzUyMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBBQUAA4IBAQB7ch1k/4jIOsG36eepxIe725SS15BZ
# M/orh96oW4AlPxOPm4MbfEPE5ozfOT7DFeyw2jshJXskwXJduEeRgRNG+pw/alE4
# 3rQly/Cr38UoAVR5EEYk0TgPJqFhkE26vSjmP/HEqpv22jVTT8nyPdNs3CPtqqBN
# ZwnzOoA9PPs2TJDndqTd8jq/VjUvokxl6ODU2tHHyJFqLSNPNzsZlBjU1ZwQPNWx
# HBn/j8hrm574rpyZlnjRzZxRFVtCJnJajQpKI5JA6IbeIsKTOtSbaKbfKX8GuTwO
# vZ/EhpyCR0JxMoYJmXIJeUudcWn1Qf9/OXdk8YSNvosesn1oo6WQsQz/MYICJTCC
# AiECAQEwgYMwbzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEuMCwGA1UEAxMlRGlnaUNlcnQgQXNz
# dXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EtMQIQC0japWK58eEmaEk9Yy13dzAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQUfdC8gQU/awR70bhhkp4FhfZQsB8wDQYJKoZIhvcNAQEBBQAE
# ggEATcHoPZp5xJ8RViHla/tx0TdI21na0SVxMLm3mb1eX52CQwb96nR3B/gWt19L
# WosRq3osckHDCH+ePQha8sxki4yqSBT1ebbTx8gYPaD3pxVR3WPhhSBD9n0t8jjr
# TK4HeuZ4dQoNne3Ye0abw/wNJTFH+NTa3YaIBWXo4fdPOsXXyVZeqJl5EqTP+0Sl
# M5/8TAb8etgbXB6hHXZCRetbD7QzXRp3yxBDDOklN1kLAubB+MdOnb3V/zhhvtaO
# 8n9L6+I+BK5m1eBjgIPisitCUK05UsvQpg/sOX9UiNop8ckA1yeICPJ553ODPWNV
# JBtLHP73cvje3Q7pb3pEzcfopQ==
# SIG # End signature block
