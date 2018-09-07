<#
.SYNOPSIS
    A PowerShell module utilizing the Okta Management API to perform administrative actions in Okta.  
.LINK
    Okta Management API Documentation: https://developer.okta.com/docs/api/resources/apps
.NOTES  
    Author     : Swan Htet - sw@nhtet.net 
    Requires   : PowerShell 
#>

#SET OKTA URL
$OKTA_BASE_URL = "PUT BASE URL HERE"

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
            $next = (($ALL_USERS_IN.Headers.Link) -split ',' -split ';')[2] -replace '<','' -replace '>',''
            $FILTER_USERS_CLEAN += $FILTER_USERS_IN.Content | ConvertFrom-Json

        }

        $FILTER_USERS_CLEAN

    }

    #Otherwise, return user specified in UserEmail parameter
    else {
        $uri_one = "$OKTA_BASE_URL/api/v1/users/" + $UserEmail
        $ONE_USER = (Invoke-WebRequest -Uri $uri_one -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method Get)
        $ONE_USER.Content | ConvertFrom-Json
    }
}

#Grab all Okta groups
#https://developer.okta.com/docs/api/resources/groups#list-groups

#SWAN CLEAN THIS UP! ADD CONTROL FLOW TO CHECK IF ALL SWITCH SELECTED FOOL!

function Get-OktaGroup {
    param(
        [Parameter(Mandatory = $False)] [switch]$All,
        [Parameter(Mandatory = $False)] [string]$GroupName
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
        [Parameter(Mandatory = $True)] [string]$groupName
    )

    #Check if API key is set
    Set-OKTAApiKey

    #Query Okta to grab the group ID, then use GroupID to construct new URI. GET to print out all users in the group
    $groupID = (Get-OktaGroup -groupName $groupName).id
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
    Invoke-WebRequest -Uri $uri_add_group -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method POST -Body $body
}

#Set or update qboxID profile attribute for Okta user. Currently need to expand to update all attributes. 
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
   [Parameter(Mandatory = $False)][array]$GroupMembership
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
        [Parameter(Mandatory = $True)] [string]$Title,
        [Parameter(Mandatory = $True)] [string]$Department,
        [Parameter(Mandatory = $True)] [string]$Email,
        [Parameter(Mandatory = $False)][string]$PreferredName,
        [Parameter(Mandatory = $True)] [string]$SecondaryEmail,
        [Parameter(Mandatory = $True)] [string]$Manager,
        [Parameter(Mandatory = $False)][string]$startDate,
        [Parameter(Mandatory = $True)] [array]$GroupIDs

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
    $uri_add_user = "$OKTA_BASE_URL/api/v1/users?activate=false"

    #Send HTTP POST to add user
    Invoke-WebRequest -Uri $uri_add_user -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json" } -Method POST -Body $body_new


}

function Get-OktaApp {

    param(
        [Parameter(Mandatory = $False)] [switch]$All,
        [Parameter(Mandatory = $False)] [string]$AppName
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
        $ALL_APPS_CLEAN}
    else {
        $ALL_APPS_CLEAN | Where-Object {$_.label -eq $AppName}}


}

function Deactivate-OktaUser {

     param(
        [Parameter(Mandatory = $True)] [string]$UserEmail
               #Add more parameters here!
    )

    $user = Get-OktaUser -UserEmail $UserEmail
    Invoke-WebRequest -Uri $user._links.deactivate.href  -Headers @{ "Authorization" = "SSWS $OKTA_API_KEY"; "Content-Type" = "application/json"; "Accept" = "application/json"} -Method POST
    
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