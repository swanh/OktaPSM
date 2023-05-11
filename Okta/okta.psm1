<#
.SYNOPSIS
    A PowerShell module utilizing the Okta Management API to perform administrative actions in Okta.  
.LINK
    Okta Management API Documentation: https://developer.okta.com/docs/api
.NOTES  
    Author     : Swan Htet - sw@nhtet.net
    Requires   : PowerShell 
#>

#SET OKTA URL
$OKTA_BASE_URL = "YOUR_OKTA_URL"

#Prompt user to enter Okta API key if not already set

function Set-OKTAApiKey {

  param(
        [Parameter(Mandatory = $False)][string]$Key
    )

    if($Key){      
       $Script:OKTA_API_KEY = $Key
    }

    else {

     if ($OKTA_API_KEY -eq $null) {
        Write-Host "Okta API key has not been set."
        $Script:OKTA_API_KEY = Read-Host -Prompt "Enter your Okta API key: "
    }
    }
}

#Grab all active users from Okta
#https://developer.okta.com/docs/api/resources/users.html#list-all-users

function Get-OktaUser {
    param(
        [Parameter(Mandatory = $False)] [switch]$All,
        [Parameter(Mandatory = $False)] [string]$UserEmail,
        [Parameter(Mandatory = $False)] [string]$Filter
    )

    #Check if API key is set
    Set-OKTAApiKey
    
    #If All switch selected, return all Okta users
    if ($All) {
        $uri_all = "$OKTA_BASE_URL/api/v1/users"
        $ALL_USERS = (Invoke-WebRequest -Uri $uri_all -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($ALL_USERS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        #Clean the content of the first API call, add users to object 
        $ALL_USERS_CLEAN = $ALL_USERS.Content | ConvertFrom-Json
        
        #Loop through content until all users found
        while ($next -ne '') {
            $new_url = $next
            $ALL_USERS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
            $next = (($ALL_USERS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
            $ALL_USERS_CLEAN += $ALL_USERS_IN.Content | ConvertFrom-Json

        }

        $ALL_USERS_CLEAN }

    if($Filter){

    $uri_filter =  "$OKTA_BASE_URL/api/v1/users?filter=" + $Filter

    $FILTER_USERS = (Invoke-WebRequest -Uri $uri_filter -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($FILTER_USERS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
    $FILTER_USERS_CLEAN = $FILTER_USERS.Content | ConvertFrom-Json

      while ($next -ne '') {
            $new_url = $next
            $FILTER_USERS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
            $next = (($FILTER_USERS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
            $FILTER_USERS_CLEAN += $FILTER_USERS_IN.Content | ConvertFrom-Json

        }

        $FILTER_USERS_CLEAN

    }



    #Otherwise, return user specified in UserEmail parameter
    if($UserEmail) {
        $uri_one = "$OKTA_BASE_URL/api/v1/users/" + $UserEmail
        $ONE_USER = (Invoke-WebRequest -Uri $uri_one -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $ONE_USER.Content | ConvertFrom-Json
    }
}

#Grab all Okta groups
#https://developer.okta.com/docs/api/resources/groups#list-groups
function Get-OktaGroup {
    param(
        [Parameter(Mandatory = $False)] [switch]$All,
        [Parameter(Mandatory = $False)] [string]$GroupName,
        [Parameter(Mandatory = $False)] [string]$GroupID
    )
    #Check if API key is set
    Set-OKTAApiKey

    #if All switch selected, return all okta groups
    if($All){
    
    #First API call
    $uri_all = "$OKTA_BASE_URL/api/v1/groups"
    $ALL_GROUPS = (Invoke-WebRequest -Uri $uri_all -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($ALL_GROUPS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''

    #Clean the content of the first API call, add users to object 
    $ALL_GROUPS_CLEAN = $ALL_GROUPS.Content | ConvertFrom-Json
    
    #Loop through content until all users found
    while ($next -ne '') {
        $new_url = $next
        $ALL_GROUPS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($ALL_GROUPS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $ALL_GROUPS_CLEAN += $ALL_GROUPS_IN.Content | ConvertFrom-Json

    }
     #Return results to user
    $ALL_GROUPS_CLEAN
    
    }
    elseif($GroupID){

        $uri_one = "$OKTA_BASE_URL/api/v1/groups/$GroupID"
        $ONE_GROUP = (Invoke-WebRequest -Uri $uri_one -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        ($ONE_GROUP.Content | ConvertFrom-Json)
    }

    #grab group by name provided
    else {
        $groupName_clean = $groupName -replace " ","%20"
        $uri_one = "$OKTA_BASE_URL/api/v1/groups?q=$groupName_clean"
        $ONE_GROUP = (Invoke-WebRequest -Uri $uri_one -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        ($ONE_GROUP.Content | ConvertFrom-Json)[0]
        }
               
}

#Get a list of an Okta group's members
#https://developer.okta.com/docs/api/resources/groups#list-group-members

function Get-OktaGroupMembers {
    param(
        [Parameter(Mandatory = $False)] [string]$groupName,
        [Parameter(Mandatory = $False)] [string]$GroupID

    )

    #Check if API key is set
    Set-OKTAApiKey

    if($groupName){
    #Query Okta to grab the group ID, then use GroupID to construct new URI. GET to print out all users in the group
    $group_ID = (Get-OktaGroup -groupName $groupName).id
    $uri_grp_members = "$OKTA_BASE_URL/api/v1/groups/" + $group_ID + "/users"
    $GROUP_MEMBERS = (Invoke-WebRequest -Uri $uri_grp_members -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($GROUP_MEMBERS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
    #Clean the content of the first API call, add users to object 
    $GROUP_MEMBERS_CLEAN = $GROUP_MEMBERS.Content | ConvertFrom-Json
    #Loop through content until all users found
    while ($next -ne '') {
        $new_url = $next
        $GROUP_MEMBERS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($GROUP_MEMBERS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $GROUP_MEMBERS_CLEAN += $GROUP_MEMBERS_IN.Content | ConvertFrom-Json

    }

    $GROUP_MEMBERS_CLEAN  }

    #Run with provided groupID
    else{
    $uri_grp_members = "$OKTA_BASE_URL/api/v1/groups/" + $groupID + "/users"
    $GROUP_MEMBERS = (Invoke-WebRequest -Uri $uri_grp_members -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($GROUP_MEMBERS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
    #Clean the content of the first API call, add users to object 
    $GROUP_MEMBERS_CLEAN = $GROUP_MEMBERS.Content | ConvertFrom-Json
    #Loop through content until all users found
    while ($next -ne '') {
        $new_url = $next
        $GROUP_MEMBERS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($GROUP_MEMBERS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $GROUP_MEMBERS_CLEAN += $GROUP_MEMBERS_IN.Content | ConvertFrom-Json

    }

    $GROUP_MEMBERS_CLEAN

    }


}

#Add user to group
#https://developer.okta.com/docs/api/resources/groups#add-user-to-group

function Add-OktaUserToGroup {
    param(
        [Parameter(Mandatory = $True)] [string]$userEmail,
        [Parameter(Mandatory = $True)] [string]$groupName
    )
    #Check if API key is set
    Set-OKTAApiKey

    #Construct URL, find userID and groupID from input
    $groupID = (Get-OktaGroup -groupName $groupName).id
    $userID = (Get-OktaUser -UserEmail $userEmail).id
    $uri_grp_members_add = "$OKTA_BASE_URL/api/v1/groups/$groupID/users/$userID"

    #Send HTTP POST to add user to group
    (Invoke-WebRequest -Uri $uri_grp_members_add -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Put)
}

#Remove user to group
#https://developer.okta.com/docs/api/resources/groups#remove-user-from-group

function Remove-OktaUserFromGroup {
    param(
        [Parameter(Mandatory = $True)] [string]$userEmail,
        [Parameter(Mandatory = $True)] [string]$groupName
    )
    #Check if API key is set
    Set-OKTAApiKey

    #Construct URL, find userID and groupID from input
    $groupID = (Get-OktaGroup -groupName $groupName).id
    $userID = (Get-OktaUser -UserEmail $userEmail).id
    $uri_grp_members_kill = "$OKTA_BASE_URL/api/v1/groups/$groupID/users/$userID"

    #Send HTTP POST to remove user from group
    (Invoke-WebRequest -Uri $uri_grp_members_kill -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method DELETE)
}

#Create an Okta group
#https://developer.okta.com/docs/api/resources/groups#add-group

function Add-OktaGroup {

    param(
        [Parameter(Mandatory = $True)] [string]$Name,
        [Parameter(Mandatory = $false)] [string]$Description
    )

    #Check if API key is set
    Set-OKTAApiKey

    #Content URL and body to POST
    $uri_add_group = "$OKTA_BASE_URL/api/v1/groups"
    $body = (ConvertTo-Json -InputObject @{ profile = @{ 'name' = $Name; 'description' = $description } })

    #Send HTTP POST to add user
    (Invoke-WebRequest -Uri $uri_add_group -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method POST -Body $body).Content | ConvertFrom-Json
}

#Set or update profile attribute for Okta user. Currently need to expand to update all attributes. 
#https://developer.okta.com/docs/api/resources/users#update-user

function Set-OktaUser {

   param(
   [Parameter(Mandatory = $True,position=0)][string]$UserEmail,
   [Parameter(Mandatory = $False)][string]$FirstName,
   [Parameter(Mandatory = $False)][string]$LastName,
   [Parameter(Mandatory = $False)][string]$Password,
   [Parameter(Mandatory = $False)][string]$Email,
   [Parameter(Mandatory = $False)][string]$Department,
   [Parameter(Mandatory = $False)][string]$Title,
   [Parameter(Mandatory = $False)][string]$Manager,
   [Parameter(Mandatory = $False)][string]$Type,
   [Parameter(Mandatory = $False)][string]$StartDate,
   [Parameter(Mandatory = $False)][string]$OffboardDateTime,
   [Parameter(Mandatory = $False)][string]$Organization,
   [Parameter(Mandatory = $False)][array]$GroupMembership,
   [Parameter(Mandatory = $False)][array]$ProxyAddresses,
   [Parameter(Mandatory = $False)][string]$City,
   [Parameter(Mandatory = $False)][string]$State,
   [Parameter(Mandatory = $False)][string]$Country
   )

    #Check if API key is set
    Set-OKTAApiKey

    #Get okta user ID
    $userID = (Get-OktaUser -UserEmail $userEmail).id

    #Construct profile object to POST
   
    $body_prep = New-Object PSObject
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name firstName -Value $FirstName
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name lastName -Value $LastName
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name email -Value $Email
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name title -Value $Title
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name department -Value $Department
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name manager -Value $Manager
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name userType -Value $Type
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name startDate -Value $StartDate
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name offboardDateTime -Value $OffboardDateTime
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name group_membership -Value $GroupMembership
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name organization -Value $Organization
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name ProxyAdressess -Value $proxyAddresses
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name city -Value $City
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name state -Value $State
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name country -Value $Country

    $body_old = $body_prep | ForEach-Object {
   # Get array of names of object properties that can be cast to boolean TRUE
   
   # PSObject.Properties - https://msdn.microsoft.com/en-us/library/system.management.automation.psobject.properties.aspx
   $NonEmptyProperties = $_.psobject.Properties | Where-Object {$_.Value} | Select-Object -ExpandProperty Name
   
   # Convert object to JSON with only non-empty properties
   $_ | Select-Object -Property $NonEmptyProperties 
}

    $body_new = (ConvertTo-Json -InputObject @{profile = $body_old})
    
    Write-Verbose $body_new
    
    #URI
    $uri_update_user = "$OKTA_BASE_URL/api/v1/users/" + $userID

    #Update Okta user profile
    Invoke-WebRequest -Uri $uri_update_user -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method POST -Body $body_new
}

#Add multiple users to an Okta group. Still testing.
#https://developer.okta.com/docs/api/resources/groups#add-user-to-group

function Add-BulkOktaUserToGroup {

    param(
        [Parameter(Mandatory = $True)] [string]$GroupName,
        [Parameter(Mandatory = $True)] [array]$GroupMembers
        #Add more parameters here!
    )

    #Check if API key is set
    Set-OKTAApiKey

    #check if GroupMembers is array
    if ($GroupMembers -isnot [array]) {
        Write-Host -ForegroundColor Red "GroupMembers not an array. Please provide an array of user emails for the GroupMembers parameter."
        exit;
    }
    #Check if GroupMembers is email format
    elseif ($GroupMembers[0] -notlike '*@*.*') {
        Write-Host -ForegroundColor Red "GroupMembers not in email format. Please provide an array of user emails for the GroupMembers parameter."
        exit; }
    else {
        foreach ($i in $GroupMembers) {
            #add each group member to list
            Write-Host -ForegroundColor Green "Adding $i to $groupName"
            Add-OktaUserToGroup -UserEmail $i -groupName $GroupName

        }
    }
}

function Add-OktaUser {
 
    param(
        [Parameter(Mandatory = $True)] [string]$FirstName,
        [Parameter(Mandatory = $True)] [string]$LastName,
        [Parameter(Mandatory = $False)] [string]$Title,
        [Parameter(Mandatory = $False)] [string]$Department,
        [Parameter(Mandatory = $True)] [string]$Email,
        [Parameter(Mandatory = $False)][string]$PreferredName,
        [Parameter(Mandatory = $False)] [string]$SecondaryEmail,
        [Parameter(Mandatory = $False)] [string]$Manager,
        [Parameter(Mandatory = $False)][string]$startDate,
        [Parameter(Mandatory = $False)][string]$Organization,
        [Parameter(Mandatory = $False)][string]$userType,
        [Parameter(Mandatory = $False)] [array]$GroupIDs

    )

    #Check if API key is set
    Set-OKTAApiKey

    #Construct profile object to POST
   
    $body_prep = New-Object PSObject
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name firstName -Value $FirstName
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name lastName -Value $LastName
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name email -Value $Email
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name title -Value $Title
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name department -Value $Department
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name manager -Value $Manager
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name nickName -Value $PreferredName
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name secondEmail -Value $secondaryEmail
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name login -Value $Email
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name startDate -Value $startDate
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name organization -Value $Organization
    Add-Member -InputObject $body_prep -MemberType NoteProperty -Name userType -Value $userType
    
    $body_old = $body_prep | ForEach-Object {
   # Get array of names of object properties that can be cast to boolean TRUE
   
   # PSObject.Properties - https://msdn.microsoft.com/en-us/library/system.management.automation.psobject.properties.aspx
   $NonEmptyProperties = $_.psobject.Properties | Where-Object {$_.Value} | Select-Object -ExpandProperty Name
   
   # Convert object to JSON with only non-empty properties
   $_ | Select-Object -Property $NonEmptyProperties 
}

    $body_new = (ConvertTo-Json -InputObject @{profile = $body_old;groupIds = $GroupIDs})
    
    Write-Verbose $body_new
    
    #Content URL and body to POST
    $uri_add_user = "$OKTA_BASE_URL/api/v1/users?activate=true"

    #Send HTTP POST to add user
    Invoke-WebRequest -Uri $uri_add_user -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method POST -Body $body_new


}

function Get-OktaApp {

    param(
        [Parameter(Mandatory = $False)] [switch]$All,
        [Parameter(Mandatory = $False)] [string]$AppName,
        [Parameter(Mandatory = $False)] [string]$ID
    )
    #Check if API key is set
    Set-OKTAApiKey

    #First API call
    $uri_all = "$OKTA_BASE_URL/api/v1/apps"
    $ALL_APPS = (Invoke-WebRequest -Uri $uri_all -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($ALL_APPS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''

    #Clean the content of the first API call, add users to object 
    $ALL_APPS_CLEAN = $ALL_APPS.Content | ConvertFrom-Json
    
    #Loop through content until all users found
    while ($next -ne '') {
        $new_url = $next
        $ALL_APPS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($ALL_APPS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $ALL_APPS_CLEAN += $ALL_APPS_IN.Content | ConvertFrom-Json

    }
    #Return results to user
    if ($All){
        #First API call
    $uri_all = "$OKTA_BASE_URL/api/v1/apps"
    $ALL_APPS = (Invoke-WebRequest -Uri $uri_all -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($ALL_APPS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''

    #Clean the content of the first API call, add users to object 
    $ALL_APPS_CLEAN = $ALL_APPS.Content | ConvertFrom-Json
    
    #Loop through content until all users found
    while ($next -ne '') {
        $new_url = $next
        $ALL_APPS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($ALL_APPS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $ALL_APPS_CLEAN += $ALL_APPS_IN.Content | ConvertFrom-Json}


        $ALL_APPS_CLEAN}

    elseif($ID){
        $uri_all = "$OKTA_BASE_URL/api/v1/apps/$ID"
        $ALL_APPS = (Invoke-WebRequest -Uri $uri_all -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)

        $ALL_APPS_CLEAN = $ALL_APPS.Content | ConvertFrom-Json

        $ALL_APPS_CLEAN

        }

    else {

        #First API call
    $uri_all = "$OKTA_BASE_URL/api/v1/apps"
    $ALL_APPS = (Invoke-WebRequest -Uri $uri_all -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($ALL_APPS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''

    #Clean the content of the first API call, add users to object 
    $ALL_APPS_CLEAN = $ALL_APPS.Content | ConvertFrom-Json
    
    #Loop through content until all users found
    while ($next -ne '') {
        $new_url = $next
        $ALL_APPS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($ALL_APPS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $ALL_APPS_CLEAN += $ALL_APPS_IN.Content | ConvertFrom-Json}

        
        $ALL_APPS_CLEAN | Where-Object {$_.label -eq $AppName}
        }
}

function Deactivate-OktaUser {

     param(
        [Parameter(Mandatory = $True)] [string]$UserEmail
               #Add more parameters here!
    )

    $user = Get-OktaUser -UserEmail $UserEmail
    $url = $OKTA_BASE_URL + "/api/v1/users/" + $user.id + "/lifecycle/deactivate"
    Write-Host $url
    Invoke-WebRequest -Uri $url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method POST
    
}

function Suspend-OktaUser {

     param(
        [Parameter(Mandatory = $True)] [string]$UserEmail
               #Add more parameters here!
    )

    $user = Get-OktaUser -UserEmail $UserEmail
    Invoke-WebRequest -Uri $user._links.suspend.href  -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method POST
    
}

function Activate-OktaUser {

     param(
        [Parameter(Mandatory = $True)] [string]$UserEmail
               #Add more parameters here!
    )
    
    $user = Get-OktaUser -UserEmail $UserEmail
    Invoke-WebRequest -Uri $user._links.activate.href  -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method POST
}


function Reactivate-OktaUser {

     param(
        [Parameter(Mandatory = $True)] [string]$UserEmail
               #Add more parameters here!
    )

    $user = Get-OktaUser -UserEmail $UserEmail
    Invoke-WebRequest -Uri $user._links.reactivate.href  -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method POST
}

function Expire-OktaUserPassword {

     param(
        [Parameter(Mandatory = $True)] [string]$UserEmail
              
    )

    $user = Get-OktaUser -UserEmail $UserEmail
    $url = "$OKTA_BASE_URL/api/v1/users/$($user.id)/lifecycle/expire_password"
    Invoke-WebRequest -Uri $url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method POST
}

function Get-OktaGroupApplications {

    param(
        [Parameter(Mandatory = $False)] [switch]$IncludeInactive,
        [Parameter(Mandatory = $True)] [string]$GroupName
    )

    if(!$IncludeInactive){

    $groupID = Get-OktaGroup -GroupName $GroupName
    $uri_group_apps = "$OKTA_BASE_URL/api/v1/groups/" + $groupID.id + "/apps"

    $GROUP_APPS = (Invoke-WebRequest -Uri $uri_group_apps -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
       $GROUP_APPS_CLEAN = $GROUP_APPS.Content | ConvertFrom-Json
    $GROUP_APPS_CLEAN | Where-Object {$_.status -ne 'INACTIVE'}
    }     

    elseif($IncludeInactive){
    $groupID = Get-OktaGroup -GroupName $GroupName
    $uri_group_apps = "$OKTA_BASE_URL/api/v1/groups/" + $groupID.id + "/apps"
    $GROUP_APPS = (Invoke-WebRequest -Uri $uri_group_apps -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $GROUP_APPS_CLEAN = $GROUP_APPS.Content | ConvertFrom-Json
    }
}

function Get-OktaAppUser {

     param(
         [Parameter(Mandatory = $True)] [string]$ApplicationID,
         [Parameter(Mandatory = $False)] [int]$Limit
         
    )
    
    $uri = "$OKTA_BASE_URL/api/v1/apps/" +$ApplicationID + "/users"
    $APP_USERS = (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($APP_USERS.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
    $APP_USERS_CLEAN = $APP_USERS.Content | ConvertFrom-Json

    while($next -ne ''){

        $new_url = $next
        $APP_USERS_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($APP_USERS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $APP_USERS_CLEAN += $APP_USERS_IN.Content | ConvertFrom-Json      
    }

   $APP_USERS_CLEAN
}

function Get-OktaUserLogs {
    
    param(
         [Parameter(Mandatory = $True)][string]$DaysAgo,
         [Parameter(Mandatory = $False)][string]$UserID
         )
              
      $SINCE = Get-Date (Get-Date).AddDays(-$DaysAgo) -Format o
      
      $uri = "$OKTA_BASE_URL/api/v1/logs?limit=1000&since=$SINCE"
   
      if($UserID){

      $uri = $uri + "&q=$UserID"          

      }
      
      $LOG_DATA = (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
      $next = (($LOG_DATA.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
      $LOG_DATA_CLEAN = $LOG_DATA.Content | ConvertFrom-Json 

      while($next -ne ''){

      $new_url = $next
      
      $LOG_DATA_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)

      $next = (($LOG_DATA_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''

      $LOG_DATA_CLEAN += $LOG_DATA_IN.Content | ConvertFrom-Json             

      }
      
      $LOG_DATA_CLEAN

}

function Get-OktaUserGroups{

    param(
         [Parameter(Mandatory = $False)] [string]$UserEmail,
         [Parameter(Mandatory = $False)] [string]$UserID               
         )
    #Check if API key is set
    Set-OKTAApiKey
    
    #Grab user ID from email
    if($UserEmail){
    $user_email_to_id = (Get-OktaUser -UserEmail $UserEmail).id

    #construct URI with ID from user object

    $uri =  "$OKTA_BASE_URL/api/v1/users/$user_email_to_id/groups"}

    if($UserID){

    $uri = "$OKTA_BASE_URL/api/v1/users/$userID/groups"

    

    }

    (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get).content | ConvertFrom-Json
          


}


function Get-OktaUserApps{

    param(
         [Parameter(Mandatory = $False)] [string]$UserEmail,
         [Parameter(Mandatory = $False)] [string]$UserID               
         )
    #Check if API key is set
    Set-OKTAApiKey
    
    #Grab user ID from email
    if($UserEmail){
    $user_email_to_id = (Get-OktaUser -UserEmail $UserEmail).id

    #construct URI with ID from user object

    $uri =  "$OKTA_BASE_URL/api/v1/apps?filter=user.id eq " + '"' + $user_email_to_id + '"'}

    if($UserID){

    $uri = "$OKTA_BASE_URL/api/v1/apps?filter=user.id eq " + '"' + $UserId + '"'

    

    }

    (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get).content | ConvertFrom-Json
          

}

function Get-OktaAppCerts{

    param(
         [Parameter(Mandatory = $True)] [string]$ApplicationID                   
         )
    #Check if API key is set
    Set-OKTAApiKey
       
    #construct URI with ID from user object

    $uri =  "$OKTA_BASE_URL/api/v1/apps/$ApplicationID/credentials/keys"

   (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get).Content | ConvertFrom-Json
         
}

function Clone-OktaAppCerts{

    param(
         [Parameter(Mandatory = $False)] [string]$SourceAppName,
         [Parameter(Mandatory = $False)] [string]$TargetAppName,
         [Parameter(Mandatory = $False)] [string]$KID          
         )
    #Check if API key is set
    Set-OKTAApiKey
    
    #Get application IDs
    $source_app_id = (Get-OktaApp -AppName $SourceAppName).id
    $target_app_id = (Get-OktaApp -AppName $TargetAppName).id
    
    #construct URI with ID from user object

    $uri =  "$OKTA_BASE_URL/api/v1/apps/$source_app_id/credentials/keys/$KID/clone?targetAid=$target_app_id"
   (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method POST).content | ConvertFrom-Json
          
}

function Get-OktaAppMetaData {

    param(
         [Parameter(Mandatory = $True)] [string]$ApplicationID,
         [Parameter(Mandatory = $True)] [string]$KID
                          
         )
    #Check if API key is set
    Set-OKTAApiKey
    
    #construct URI with ID from user object
    $uri =  "$OKTA_BASE_URL/api/v1/apps/$ApplicationID/sso/saml/metadata?kid=$KID"

    (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
      
}

function Update-OktaAppCreds {
 
    param(
         [Parameter(Mandatory = $True)] [string]$AppName,
         [Parameter(Mandatory = $False)] [string]$KID
                           
         )
    #Check if API key is set
    Set-OKTAApiKey

    $App_data = Get-OktaApp -AppName $AppName
    $app_data_id = $App_data.id

    $uri =  "$OKTA_BASE_URL/api/v1/apps/$App_data_id"

    $body = @{name = $App_data.name; label = $App_data.label; signOnMode = 'SAML_2_0'; credentials = @{signing = @{kid = $KID}}} | ConvertTo-Json
    
    (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Body $body -Method PUT).Content | ConvertFrom-Json

}

function Get-OktaGroupRules {

    param(
         [Parameter(Mandatory = $False)] [switch]$All                  
         )
    #Check if API key is set
    Set-OKTAApiKey
       
    #First API call
    $uri_all = "$OKTA_BASE_URL/api/v1/groups/rules"
    $ALL_RULES = (Invoke-WebRequest -Uri $uri_all -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
    $next = (($ALL_RULES.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''

    #Clean the content of the first API call, add users to object 
    $ALL_RULES_CLEAN = $ALL_RULES.Content | ConvertFrom-Json
    
    #Loop through content until all users found
    while ($next -ne '') {
        $new_url = $next
        $ALL_RULES_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $next = (($ALL_RULES_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
        $ALL_RULES_CLEAN += $ALL_RULES_IN.Content | ConvertFrom-Json

    }
     #Return results to user
    $ALL_RULES_CLEAN

}

function Get-OktaAppGroup {

    param(
         [Parameter(Mandatory = $True)] [string]$ApplicationID                
         )
    #Check if API key is set
    Set-OKTAApiKey
       
    #construct URI with ID
    $uri =  "$OKTA_BASE_URL/api/v1/apps/$ApplicationID/groups"

    (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get).Content | ConvertFrom-Json

}

function Search-OktaGroups {

    param(
         [Parameter(Mandatory = $False)][string]$GroupID,
         [Parameter(Mandatory = $False)][string]$GroupName                
         )

    #Check if API key is set
    Set-OKTAApiKey
       
    #construct URI with ID
    $uri =  "$OKTA_BASE_URL/api/v1/apps/$ApplicationID/groups"

    (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get).Content | ConvertFrom-Json

}

function Remove-OktaAppUser {

    param(
         [Parameter(Mandatory = $True)][string]$ApplicationId,
         [Parameter(Mandatory = $True)][string]$UserEmail
                           )
    #Check if API key is set
    Set-OKTAApiKey

    #Convert email to userId
    $userId = (Get-OktaUser -UserEmail $UserEmail).id

    #Construct URL to unassign app
    $uri =  "$OKTA_BASE_URL/api/v1/apps/$ApplicationID/users/$userId"

    (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method DELETE).Content | ConvertFrom-Json
}

function generateTestAccounts {

    param(
         [Parameter(Mandatory = $True)][int]$Count,
         [Parameter(Mandatory = $True)][string]$EmailDomain
                           )
        #Check if API key is set
    Set-OKTAApiKey

    $testAccountData = @()

    for($i=1; $i -le $Count; $i++){

        $FirstName = "Test" + $(Get-Random -Maximum 500) + $i
        $LastName = "User" + $(Get-Random -Maximum 500) + $i
        $Email = $FirstName + "." + $LastName + $EmailDomain

        $data_obj = New-Object PSObject
        Add-Member -InputObject $data_obj -MemberType NoteProperty -Name FirstName -Value $FirstName
        Add-Member -InputObject $data_obj -MemberType NoteProperty -Name LastName -Value $LastName
        Add-Member -InputObject $data_obj -MemberType NoteProperty -Name Email -Value $Email

        $oktaAccount = (Add-OktaUser -FirstName $FirstName -LastName $LastName -Email $Email).Content | ConvertFrom-Json -Depth 100

        $testAccountData += $oktaAccount

    }

    $testAccountData

}

function Get-OktaPolicy {
    
    param(
         [Parameter(Mandatory = $True)][switch]$All,
         [Parameter(Mandatory = $True)][ValidateSet("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL")][string]$Type
         )

        #Check if API key is set
    Set-OKTAApiKey
              
      if($All){
      
      $uri = "$OKTA_BASE_URL/api/v1/policies?type=$Type"
      
      $POLICY_DATA = (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
      $next = (($POLICY_DATA.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
      $POLICY_DATA_CLEAN = $POLICY_DATA.Content | ConvertFrom-Json 

      while($next -ne ''){

          $new_url = $next
          $POLICY_DATA_IN = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
          $next = (($POLICY_DATA_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
          $POLICY_DATA_CLEAN += $POLICY_DATA_IN.Content | ConvertFrom-Json             

      }}
      
      $POLICY_DATA_CLEAN

}

function Delete-OktaGroup {

     param(
        [Parameter(Mandatory = $True)][string]$GroupId
               #Add more parameters here!
    )
         #Check if API key is sethttps://account.ghost.org/
    Set-OKTAApiKey
    $url = $OKTA_BASE_URL + "/api/v1/groups/" + $GroupId
    Write-Host $url
    Invoke-WebRequest -Uri $url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method DELETE

}

function Update-OktaUserAppAssignmentType {

     param(
        [Parameter(Mandatory = $True)][string]$ApplicationId,
        [Parameter(Mandatory = $True)][string]$UserId,
        [Parameter(Mandatory = $True)][string]$AssignmentType
        
               #Add more parameters here!
    )
         #Check if API key is set
    Set-OKTAApiKey
    $url = $OKTA_BASE_URL + "/api/v1/apps/" + $ApplicationId + "/users/" + $UserId
    
    $body = @{"scope" = $AssignmentType} | ConvertTo-Json   

    Invoke-WebRequest -Uri $url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method POST -Body $body
    
}

function Get-OktaProfileMapping {

     param(
        
        [Parameter(Mandatory = $False)][string]$MappingsId,
        [Parameter(Mandatory = $False)][switch]$All
    )
    
    #Check if API key is set
    Set-OKTAApiKey

    if($MappingsId){
        $uri = $OKTA_BASE_URL + "/api/v1/mappings/$MappingsId"

        $mappings_data_clean = (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method GET).Content | ConvertFrom-Json
    }

    if($All){

      $uri = $OKTA_BASE_URL + "/api/v1/mappings?limit=200"

      $mappings_data = (Invoke-WebRequest -Uri $uri -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
      $next = (($mappings_data.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
      $mappings_data_clean = $mappings_data.Content | ConvertFrom-Json 

      while($next -ne ''){

      $new_url = $next
      Write-Host $new_url
      
      $mappings_data_in = (Invoke-WebRequest -Uri $new_url -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)

      $next = (($mappings_data_in.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''

      if($next -eq $new_url){$next = ''}
      Write-Host $next

      $mappings_data_clean += $mappings_data_in.Content | ConvertFrom-Json             

    }}

    return $mappings_data_clean
    
}
