# Active directory timeline generated with replication metadata
# Leonard SAVINA - ANSSI\SDO\DR\INM - CERT-FR
# Issues and PR welcome https://github.com/ANSSI-FR/ADTimeline

# Use paramater server if running offline mode or GC is not found
# Use parameter customgroups to retrieve replication metadata from specific groups.
# customgroups argument can be a string with multiple group comma separated (no space)
# PS>./ADTimeline -customgroups "VIP-group1,ESX-Admins,Tier1-admins"
# customgroups can also be an array, in case you import the list from a file (one group per line)
# PS>$customgroups = get-content customgroups.txt
# PS>./ADTimeline -customgroups $customgroups

Param (
[parameter(Mandatory=$false)][string]$server = $null,
[parameter(Mandatory=$false)]$customgroups = $null
)

if($customgroups)
	{
	if(($customgroups.gettype()).FullName -eq "System.String")
		{
		$groupscustom = $customgroups.split(",")
		write-output -inputobject "---- Custom groups argument is a string ----"
		}
	elseif(($customgroups.gettype()).FullName -eq "System.Object[]")
		{
		$groupscustom = $customgroups
		"---- Custom groups argument is an array ----"
		}
	else 
		{
		write-output -inputobject "---- Wrong argument object type ----"
		Exit $WRONG_ARG_TYPE
		}
		
	}

# You can also directly uncomment and edit the below $customgroups variable if you do not want to set an argument
# Example of custom groups variable
# $groupscustom = ("VIP-group1","ESX-Admins","Tier1-admins")


# Set Variables for error handling 
Set-Variable -name ERR_BAD_OS_VERSION -option Constant -value 1
Set-Variable -name ERR_NO_AD_MODULE   -option Constant -value 2
Set-Variable -name ERR_NO_GC_FOUND   -option Constant -value 3
Set-Variable -name ERR_GC_BIND_FAILED   -option Constant -value 4
Set-Variable -name WRONG_ARG_TYPE   -option Constant -value 5


# AD Timeline is supported on Windows 6.1 +
if([Environment]::OSVersion.version -lt (new-object 'Version' 6,1))
	{
	write-output -inputobject "---- Script must be launched on a Windows 6.1 + computer ----"
	Exit $ERR_BAD_OS_VERSION
	}

# Check AD Psh module
If(-not(Get-Module -name activedirectory -listavailable))
	{
	write-output -inputobject "---- Script must be launched on a computer with Active Directory PowerShell module installed ----"
	Exit $ERR_NO_AD_MODULE
	}
Else
	{import-module activedirectory}

# Check Global Catalog
$GCsinmysite = $null

if(-not($server))
	{
	$mySite = (nltest /dsgetsite 2>$null)[0]
	$ADroot = $(get-adDomain).DNSroot
	$GCsinmysite = get-ADDomainController -Filter {(IsGlobalCatalog -eq $true) -and (Site -eq $mySite) -and (Domain -eq $ADroot) -and (Enabled -eq $true)}
	if($GCsinmysite)
		{ $server = ($GCsinmysite  | select-object -first 1).Hostname }
	Else
		{
		write-output -inputobject "---- No Global Catalog found in current AD site, please run the script and specify a Global Catalog name with the server argument ----"
		Exit $ERR_NO_GC_FOUND
		}
	}

$error.clear()
# LDAP root information, to retrieve partitions paths
$root = Get-ADRootDSE -server $server

if($error)
	{
	write-output -inputobject "---- Retrieving AD root on $($server) failed ----"
	Exit $ERR_GC_BIND_FAILED
	}

# Check if script is running offline or online and set GC port
if([string]$server.contains(":") -eq $true)
	{
	$gcport = [int]::parse($server.split(":")[1]) + 2
	$gc = $server.split(":")[0] + ":" + $gcport
	$isonline = $false
	}
else {
	$error.clear()
	$dntstroot = [void]([adsi]"LDAP://$server").distinguishedName
	[void][adsi]"GC://$server/$dntstroot"
	if($error)
		{
		write-output -inputobject "---- DC is not Global Catalog, please provide a GC with the server argument ----"
		Exit $ERR_NO_GC_FOUND	
		}
	Else
		{
		$gc = $server + ':3268'
		$isonline = $true
		}
	}

write-output -inputobject "---- Running script on: $($server) ----"

write-output -inputobject "---- Collecting AD objects ----"

# TimeStamp formating for log file
function Get-TimeStamp
    {
    return "{0:yyyy-MM-dd} {0:HH:mm:ss}" -f (get-date)
    }

"$(Get-TimeStamp) Starting script on $($server)" | out-file log-adexport.log

if($isonline -eq $true)
	{
	"$(Get-TimeStamp) Script running in online mode" | out-file log-adexport.log
	}
else
	{
	"$(Get-TimeStamp) Script running in offline mode" | out-file log-adexport.log
	}

# Function adapted from https://www.petri.com/expanding-active-directory-searcher-powershell Added SID processing
Function Convert-ADSearchResult
{
	[cmdletbinding()]
	Param(
	[Parameter(Position = 0,Mandatory = $true,ValueFromPipeline = $true)]
	[ValidateNotNullorEmpty()]
	[System.DirectoryServices.SearchResult]$SearchResult
	)
	Begin {
    Write-Verbose "Starting $($MyInvocation.MyCommand)"
	}
	Process {
    Write-Verbose "Processing result for $($searchResult.Path)"
    #create an ordered hashtable with property names alphabetized
    $props = $SearchResult.Properties.PropertyNames | Sort-Object
	$objHash = @{}
    foreach ($p in $props)
	{
		if(($p -eq "objectSID") -or ($p -eq "SIDHistory"))
			{
			$value = @()
			$binaryvalue =  $searchresult.Properties.item($p)
				foreach($SID in $binaryvalue)
				{
				$value += (New-Object System.Security.Principal.SecurityIdentifier($SID,0)).value
				}
			}
		else
		{
		$value =  $searchresult.Properties.item($p)
		}
		if ($value.count -eq 1)
			{$value = $value[0]}
     $objHash.add($p,$value)
    }
	new-object psobject -property $objHash

	}
	End
	{
    Write-Verbose "Ending $($MyInvocation.MyCommand)"
	}
}


# Initializing PowerShell objects in order to store results from LDAP queries
$criticalobjects = @()
$gcobjects = @()

#Getting root domain information
$dom = Get-ADObject -SearchBase ($root.defaultNamingContext) -SearchScope Base -Server $server  -Filter * -properties *
#If operation times out a different ResultPageSize is used
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$dom = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope Base -Server $server  -Filter * -properties *
		$i++
		}
	if($dom){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}

$criticalobjects += $dom

if($error)
    { "$(Get-TimeStamp) Error while retrieving domain root information $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	#Get current domain SID and PDCe, will be used later
	$domSID = $dom.ObjectSID.value
	$PDCe = (($dom.fsmoRoleOwner).replace($root.configurationNamingContext,"")).replace("CN=NTDS Settings,","")
	"$(Get-TimeStamp) Domain root information retrieved" | out-file log-adexport.log -append
	"$(Get-TimeStamp) Domain DistinguishedName is: $($dom.distinguishedName) " | out-file log-adexport.log -append
	"$(Get-TimeStamp) Domain SID is: $($domSID)" | out-file log-adexport.log -append
	#Getting accounts having an ACE on domain root
	$accountsACEondomain = ($dom.ntsecuritydescriptor).getaccessrules($true , $true , [System.Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference -like "S-1-5-21-*"} | group-object -property IdentityReference
	if($error)
		{ "$(Get-TimeStamp) Error while retrieving accounts having an ACE on domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else
		{
		$usrcount = 0
		foreach($accountACE in $accountsACEondomain)
			{
			$userACE = Get-ADObject -Filter {ObjectSID -eq $accountACE.Name} -Server $server -properties *
			if($error)
				{ "$(Get-TimeStamp) Error while getting object SID $($accountACE.Name) with error $($error)" | out-file log-adexport.log -append ; $error.clear() }
			else
				{
				$criticalobjects += $userACE
				if(($userACE.ObjectClass -eq "user") -or ($userACE.ObjectClass -eq "inetOrgPerson"))
					{$usrcount++}
				}
			
			}
		}
		if($usrcount -ge 1)
			{
			 "$(Get-TimeStamp) Number of user accounts having an ACE on domain root $($usrcount)" | out-file log-adexport.log -append
			}
	}

#Getting root of the configuration partition
$rootconf = Get-ADObject -SearchBase ($root.ConfigurationNamingContext) -SearchScope Base -Server $server  -Filter * -properties *
#If operation times out a different ResultPageSize is used
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$rootconf = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.ConfigurationNamingContext) -SearchScope Base -Server $server  -Filter * -properties *
		$i++
		}
	if($rootconf){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $rootconf

if($error)
    { "$(Get-TimeStamp) Error while retrieving root of the configuration partition $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	"$(Get-TimeStamp) Root of the configuration partition retrieved" | out-file log-adexport.log -append
	}

#Getting root of the schema partition
$rootschema = Get-ADObject -SearchBase ($root.SchemaNamingContext) -SearchScope Base -Server $server  -Filter * -properties *
#If operation times out a different ResultPageSize is used
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$rootschema = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.SchemaNamingContext) -SearchScope Base -Server $server  -Filter * -properties *
		$i++
		}
	if($rootschema){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $rootschema

if($error)
    { "$(Get-TimeStamp) Error while retrieving root of the schema partition $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	$SchemaMaster = (($rootschema.fsmoRoleOwner).replace($root.configurationNamingContext,"")).replace("CN=NTDS Settings,","")
	"$(Get-TimeStamp) Root of the schema partition retrieved" | out-file log-adexport.log -append
	"$(Get-TimeStamp) Schema version is $($rootschema.objectVersion)" | out-file log-adexport.log -append
	}


#Check if current user is DA or EA when online mode running
if($isonline -eq $true)
	{
	$mygrps = whoami /groups /fo csv | ConvertFrom-Csv
	$Dasid = $domsid + "-512"
	$isda = $mygrps | where-object{($_.SID -eq $Dasid) -or ($_.SID -like "*-519")}
	if($isda)
		{
		"$(Get-TimeStamp) Current user is domain admin or enterprise admin" | out-file log-adexport.log -append
		}
	else
		{
		write-output -inputobject "Script not running as domain or enterprise admin, some objects might be missing"
		"$(Get-TimeStamp) Script not running as domain or enterprise admin, some objects might be missing" | out-file log-adexport.log -append
		}
	}


#Retrieving objects located directly under the root domain, except Organizational Units
$dom1 = Get-ADObject -SearchBase ($root.defaultNamingContext) -SearchScope OneLevel -Server $server  -filter {ObjectClass -ne "organizationalUnit"} -properties *
#If operation times out a different ResultPageSize is used
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$dom1 = Get-ADObject -SearchBase ($root.defaultNamingContext) -SearchScope OneLevel -Server $server  -filter {ObjectClass -ne "organizationalUnit"} -properties *
		$i++
		}
	if($dom1){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}



$criticalobjects += $dom1
$countdom1 = ($dom1 | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving objects directly under domain root $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of objects directly under domain root, OU excluded:  $($countdom1)" | out-file log-adexport.log -append
	$inframaster = ((($dom1 | where-object{($_.Name -eq "Infrastructure") -and ($_.ObjectClass -eq "infrastructureUpdate")}).fsmoRoleOwner).replace($root.configurationNamingContext,"")).replace("CN=NTDS Settings,","")
	}

#Objects protected by the SDProp process (AdminSDHolder ACL, Admincount=1)
$SDPropObjects = Get-ADObject  -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -filter {AdminCount -eq 1} -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$SDPropObjects = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -filter {AdminCount -eq 1} -Server $server -properties *
		$i++
		}
	if($SDPropObjects){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $SDPropObjects
$countSDPROP = ($SDPropObjects | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving objects protected by the SDProp process $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of objects protected by the SDProp process: $($countSDPROP)" | out-file log-adexport.log -append}

#Grabing "Pre Windows 2000 Compatibility access group", not recursive...
$pre2000SID = "S-1-5-32-554"
$pre2000grp =  Get-ADObject -filter {ObjectSID -eq $pre2000SID} -Server $server -properties *
if($error)
	{ "$(Get-TimeStamp) Error while retrieving Pre Windows 2000 Compatibility access group $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	if($pre2000grp)
		{
		$criticalobjects += $pre2000grp
		$countpre2000grp = ($pre2000grp | measure-object).count
		if($countpre2000grp -eq 1)
			{
			if($pre2000grp.member -eq ('CN=S-1-1-0,CN=ForeignSecurityPrincipals,'+ $root.defaultNamingContext))
				{ "$(Get-TimeStamp) Member of Pre Windows 2000 Compatibility access group is Everyone" | out-file log-adexport.log -append}
			Elseif($pre2000grp.member -eq ('CN=S-1-5-11,CN=ForeignSecurityPrincipals,'+ $root.defaultNamingContext))
				{ "$(Get-TimeStamp) Member of Pre Windows 2000 Compatibility access group is Authenticated users" | out-file log-adexport.log -append}
			Elseif($pre2000grp.member -eq ('CN=S-1-5-7,CN=ForeignSecurityPrincipals,'+ $root.defaultNamingContext))
				{ "$(Get-TimeStamp) Member of Pre Windows 2000 Compatibility access group is Anonymous logon" | out-file log-adexport.log -append}
			else
				{ "$(Get-TimeStamp) Member of Pre Windows 2000 Compatibility access group is $($pre2000grp.member)" | out-file log-adexport.log -append}
			}
		else
		{"$(Get-TimeStamp) Number of Pre Windows 2000 Compatibility access group members: $($countpre2000grp)" | out-file log-adexport.log -append}
		}
	}

#Grabing the DNSAdmin groups and its members well knwon SID is S-1-5-21-<Domain>-1102
$dndnsadminSID = $domSID + "-1102"
$dnsadmin =  Get-ADObject -filter {ObjectSID -eq $dndnsadminSID} -Server $server -properties *
#Group might not exist if DNS role not installed
if($dnsadmin)
	{
	$criticalobjects += $dnsadmin
	if($isonline -eq $true)
		{
		#Get recursive membership
		$dnsadminsmembers = (Get-ADGroupMember -recursive $dnsadmin -server $server  | foreach-object{get-adobject $_ -server $server -properties *})
		#Get groups till level 2 is reached if groups are nested.
			if($dnsadminsmembers)
			{
			$criticalobjects += $dnsadminsmembers
			$nestedgrp = @()
			$level1 = Get-ADGroupMember $dnsadmin  -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName
				if($level1)
				{
				$nestedgrp += $level1
				$nestedgrp  += $level1 | foreach-object{Get-ADGroupMember $_.DistinguishedName -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName}
				$criticalobjects += ($nestedgrp | foreach-object{get-adobject $_.DistinguishedName -server $server -properties *})
				}
			}
		}
	else
		{
		#Cannot use recursive membership cmdlet in offline mode, get direct members only
		$dnsadminsmembers = ($dnsadmin | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *})
		$criticalobjects += $dnsadminsmembers
		#Get groups till level 2 is reached if groups are nested.
		$continue = $dnsadminsmembers | where-object{$_.ObjectClass -eq "Group"}
			if($continue)
				{foreach($grp in $continue){$dnsadmingrpcn2 = $grp | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *};$criticalobjects += $dnsadmingrpcn2}}
		}
				$countdnsadminsmembers = ($dnsadminsmembers | measure-object).count
		if($error)
			{ "$(Get-TimeStamp) Error while retrieving DNSADmins group members $($error)" | out-file log-adexport.log -append ; $error.clear() }
		else
			{"$(Get-TimeStamp) Number of DNSAdmins group members: $($countdnsadminsmembers)" | out-file log-adexport.log -append}
	}

#Grabing Group Policy Creators owners, using SID because name depends on the installation language
$gpoownersSID = $domSID + "-520"
$gpoowners = Get-ADObject -filter {ObjectSID -eq $gpoownersSID} -Server $server -properties *
$criticalobjects += $gpoowners
if($isonline -eq $true)
	{
	#Get recursive membership
	$gpoownersmembers = (Get-ADGroupMember -recursive $gpoowners -server $server  | foreach-object{get-adobject $_ -server $server -properties *})
	#Get groups till level 2 is reached if groups are nested.
		if($gpoownersmembers)
		{
		$criticalobjects += $gpoownersmembers
		$nestedgrp = @()
		$level1 = Get-ADGroupMember $gpoowners  -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName
			if($level1)
			{
			$nestedgrp += $level1
			$nestedgrp  += $level1 | foreach-object{Get-ADGroupMember $_.DistinguishedName -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName}
			$criticalobjects += ($nestedgrp | foreach-object{get-adobject $_.DistinguishedName -server $server -properties *})
			}
		}
	}
else
	{
	#Cannot use recursive membership cmdlet in offline mode, get direct members only
	$gpoownersmembers = ($gpoowners | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *})
	$criticalobjects += $gpoownersmembers
	#Get groups till level 2 is reached if groups are nested.
	$continue = $gpoownersmembers | where-object{$_.ObjectClass -eq "Group"}
		if($continue)
			{foreach($grp in $continue){$gpoownersgrpcn2 = $grp | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *};$criticalobjects += $gpoownersgrpcn2}}
	}
			$countgpoownersmembers = ($gpoownersmembers | measure-object).count
	if($error)
		{ "$(Get-TimeStamp) Error while retrieving GPO owners group members $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else
		{"$(Get-TimeStamp) Number of GPO creators ownners group members: $($countgpoownersmembers)" | out-file log-adexport.log -append}

#Grabing Cert publishers, using SID because name depends on the installation language
$certpublishersSID = $domSID + "-517"
$certpublishers = Get-ADObject -filter {ObjectSID -eq $certpublishersSID} -Server $server -properties *
$criticalobjects += $certpublishers
if($isonline -eq $true)
	{
	#Get recursive membership
	$certpublishersmembers = (Get-ADGroupMember -recursive $certpublishers -server $server  | foreach-object{get-adobject $_ -server $server -properties *})
	#Get groups till level 2 is reached if groups are nested.
		if($certpublishersmembers)
		{
		$criticalobjects += $certpublishersmembers
		$nestedgrp = @()
		$level1 = Get-ADGroupMember $certpublishers  -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName
			if($level1)
			{
			$nestedgrp += $level1
			$nestedgrp  += $level1 | foreach-object{Get-ADGroupMember $_.DistinguishedName -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName}
			$criticalobjects += ($nestedgrp | foreach-object{get-adobject $_.DistinguishedName -server $server -properties *})
			}
		}
	}
else
	{
	#Cannot use recursive membership cmdlet in offline mode, get direct members only
	$certpublishersmembers = ($certpublishers | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *})
	$criticalobjects += $certpublishersmembers
	#Get groups till level 2 is reached if groups are nested.
	$continue = $certpublishersmembers | where-object{$_.ObjectClass -eq "Group"}
		if($continue)
			{foreach($grp in $continue){$certpublishersgrpcn2 = $grp | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *};$criticalobjects += $certpublishersgrpcn2}}
	}
			$countcertpublishersmembers = ($certpublishersmembers | measure-object).count
	if($error)
		{ "$(Get-TimeStamp) Error while retrieving Cert publishers group members $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else
		{"$(Get-TimeStamp) Number of Cert publishers group members: $($countcertpublishersmembers)" | out-file log-adexport.log -append}

#Retrieving deleted Group Policy Objects
$DeleteBase = "CN=Deleted Objects," + $root.defaultNamingContext
$deletedgpo = Get-ADObject -searchbase $DeleteBase -filter {(IsDeleted -eq $true) -and (ObjectClass -eq "groupPolicyContainer")} -IncludeDeletedObjects -Server $server -properties *

if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$deletedgpo = Get-ADObject -ResultPageSize $resultspagesize -searchbase $DeleteBase -filter {(IsDeleted -eq $true) -and (ObjectClass -eq "groupPolicyContainer")} -IncludeDeletedObjects -Server $server -properties *
		$i++
		}
	if($deletedgpo){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $deletedgpo
$countdeletedgpo = ($deletedgpo  | measure-object).count
if($error)
    { "$(Get-TimeStamp) Erreur while retrieving deleted GPOs $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of deleted (tombstoned) GPOs: $($countdeletedgpo)" | out-file log-adexport.log -append}



#Retrieving Deleted (tombstoned) users, NTSecurityDescriptor porperty is excluded because with a large number of tombstoned users it can take a large amount of RAM. This property is not relevant for analysis if object is in the "Deleted Objects" container.
$deletedusers = Get-ADObject -searchbase $DeleteBase -filter {(IsDeleted -eq $true) -and ((ObjectClass -eq "User") -or (ObjectClass -eq "InetOrgPerson"))} -IncludeDeletedObjects -Server $server -properties CanonicalName, CN, Deleted, Description, DisplayName, DistinguishedName, instanceType, isDeleted, isRecycled, LastKnownParent, Modified, modifyTimeStamp, Name, ObjectCategory, ObjectClass, ObjectGUID, objectSid, ProtectedFromAccidentalDeletion, sAMAccountName, sDRightsEffective, userAccountControl, uSNChanged, uSNCreated, whenChanged, whenCreated
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$deletedusers = Get-ADObject -ResultPageSize $resultspagesize -searchbase $DeleteBase -filter {(IsDeleted -eq $true) -and ((ObjectClass -eq "User") -or (ObjectClass -eq "InetOrgPerson"))} -IncludeDeletedObjects -Server $server -properties CanonicalName, CN, Deleted, Description, DisplayName, DistinguishedName, instanceType, isDeleted, isRecycled, LastKnownParent, Modified, modifyTimeStamp, Name, ObjectCategory, ObjectClass, ObjectGUID, objectSid, ProtectedFromAccidentalDeletion, sAMAccountName, sDRightsEffective, userAccountControl, uSNChanged, uSNCreated, whenChanged, whenCreated
		$i++
		}
	if($deletedusers){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$countdeletedusers = ($deletedusers  | measure-object).count
if($countdeletedusers -ge 3000)
	{
	#If number of deleted objects is larger than 3000, metadata retrieval might take a while. As a consequence we sort them by creation date and take only the last 3000 created accounts.
	$criticalobjects += $deletedusers |  where-object{$_.WhenCreated -ne $null} | Sort-Object -Property whencreated -Descending | select-object -first 3000
	"$(Get-TimeStamp) Number of deleted (tombstoned) user objects is $($countdeletedusers), because it is larger than 3000 only last 3000 newly created accounts will be retrieved" | out-file log-adexport.log -append
	}
else
	{
	$criticalobjects += $deletedusers
	"$(Get-TimeStamp) Number of deleted (tombstoned) user objects: $($countdeletedusers)" | out-file log-adexport.log -append
	}
if($error)
    { "$(Get-TimeStamp) Error while retrieving deleted (tombstoned) user objects $($error)" | out-file log-adexport.log -append ; $error.clear() }



#Retrieving deleted objects located in configuration partition, msExchActiveSyncDevice objectclass is excluded as it can generate some noise
$deleteconf =  Get-ADObject -searchbase $root.configurationNamingContext  -filter {(IsDeleted -eq $true) -and (ObjectClass -ne "msExchActiveSyncDevice")} -IncludeDeletedObjects -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$deleteconf = Get-ADObject -ResultPageSize $resultspagesize -searchbase $root.configurationNamingContext  -filter {(IsDeleted -eq $true) -and (ObjectClass -ne "msExchActiveSyncDevice")} -IncludeDeletedObjects -Server $server -properties *
		$i++
		}
	if($deleteconf){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $deleteconf
$countdeleteconf = ($deleteconf | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving deleted (tombstoned) objects located in configuration partition $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of deleted (tombstoned) objects located in configuration partition: $($countdeleteconf)" | out-file log-adexport.log -append}





#Retrieving classSchema objects (defaultSecurityDescriptor backdoor)
$Classesschema = Get-ADObject -searchbase $root.schemaNamingContext -Filter {ObjectClass -eq "classSchema"} -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$Classesschema = Get-ADObject -ResultPageSize $resultspagesize -searchbase $root.schemaNamingContext -Filter {ObjectClass -eq "classSchema"} -Server $server -properties *
		$i++
		}
	if($Classesschema){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $Classesschema
$countClassesschema = ($Classesschema | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving classSchema objects $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of classSchema objects:  $($countClassesschema)" | out-file log-adexport.log -append}


#Retrieving server and ntdsdsa class objects located in the configuration partition (Domain Controllers)
$dcrepls =  Get-ADObject -searchbase $root.configurationNamingContext -filter {(ObjectClass -eq 'Server') -or (ObjectClass -eq 'nTDSDSA')} -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$dcrepls = Get-ADObject -ResultPageSize $resultspagesize -searchbase $root.configurationNamingContext -filter {(ObjectClass -eq 'Server') -or (ObjectClass -eq 'nTDSDSA')} -Server $server -properties *
		$i++
		}
	if($dcrepls){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $dcrepls
$countdcrepls = ($dcrepls | measure-object).count
$countserverd = ($deleteconf | where-object{$_.ObjectClass -eq 'Server'} | measure-object).count
$countnTDSDSAd = ($deleteconf | where-object{$_.ObjectClass -eq 'nTDSDSA'} | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving server and ntdsdsa class objects located in the configuration partition and in the tombstone $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
		"$(Get-TimeStamp) Number of server and ntdsdsa class objects located in the configuration partition: $($countdcrepls)" | out-file log-adexport.log -append
		if(($countnTDSDSAd -ge 1) -or ($countserverd -ge 1))
			{"$(Get-TimeStamp) Domain Controller demotion or use of DCShadow: $($countserverd) deleted server objects and $($countnTDSDSAd) deleted nTDSDSA objects located in the tombstone" | out-file log-adexport.log -append}
	}

#Domain controller computer objects (existing en deleted)
$OUDCs = "OU=Domain Controllers," + $root.defaultNamingContext
#Existing Domain controllers in current domain
$DCpresents = Get-ADObject -searchbase $OUDCs -filter {(ObjectClass -eq 'Computer') -and ((PrimaryGroupID -eq 521) -or (PrimaryGroupID -eq 516))} -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$DCpresents = Get-ADObject -ResultPageSize $resultspagesize -searchbase $OUDCs -filter {(ObjectClass -eq 'Computer') -and ((PrimaryGroupID -eq 521) -or (PrimaryGroupID -eq 516))} -Server $server -properties *
		$i++
		}
	if($DCpresents){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
if($error)
    { "$(Get-TimeStamp) Error while retrieving existing domain controllers in current domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
$countDCpresents = ($DCpresents | measure-object).count
$criticalobjects += $DCpresents
# Deleted domain controllers in current domain (tombstoned)
$DCeffaces = Get-ADObject -searchbase $DeleteBase -filter {(IsDeleted -eq $true) -and (LastKnownParent -eq $OUDCs) -and (ObjectClass -eq 'Computer')} -IncludeDeletedObjects -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$DCeffaces = Get-ADObject -ResultPageSize $resultspagesize -searchbase $DeleteBase -filter {(IsDeleted -eq $true) -and (LastKnownParent -eq $OUDCs) -and (ObjectClass -eq 'Computer')} -IncludeDeletedObjects -Server $server -properties *
		$i++
		}
	if($DCeffaces){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
if($error)
    { "$(Get-TimeStamp) Error while retrieving deleted domain controllers in current domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
$countDCeffaces = ($DCeffaces| measure-object).count
$criticalobjects +=  $DCeffaces
# Retrieving existing domain controllers outside current domain and inside the current forest
$ComputerCategory = "CN=Computer," + $root.SchemaNamingContext
$search = new-object System.DirectoryServices.DirectorySearcher
$search.pagesize = 256
$search.filter = "(&(ObjectCategory=$($ComputerCategory))(|(PrimaryGroupID=521)(PrimaryGroupID=516)))"
$search.searchroot = [ADSI]"GC://$($gc)"
$allDCs =  $search.findall() | Convert-ADSearchResult
$otherDCs = $allDCs | where-object{$_.DistinguishedName -notlike "*$($OUDCs)"}
$countallDCs = ($allDCs | measure-object).count
$gcobjects += $otherDCs
if($error)
    { "$(Get-TimeStamp) Error while retrieving domain controllers in the current forest via GC $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	"$(Get-TimeStamp) Total number of existing domain controllers computer objects in the current forest: $($countallDCs)"  | out-file log-adexport.log -append
	"$(Get-TimeStamp) Total number of existing domain controllers computer objects in the current domain: $($countDCpresents)"  | out-file log-adexport.log -append
	"$(Get-TimeStamp) Total number of deleted domain controllers computer objects in the current domain: $($countDCeffaces)"  | out-file log-adexport.log -append
	}


#Objects with kerberos delagation configured
$delegkrb = Get-ADObject -filter {(UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like "*") -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like "*")} -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$delegkrb = Get-ADObject -ResultPageSize $resultspagesize -filter {(UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like "*") -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like "*")} -Server $server -properties *
		$i++
		}
	if($delegkrb){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$countdelegkrb = ($delegkrb | measure-object).count
$delegkrbnoconstrained = $delegkrb | where-object{($_.UserAccountControl -BAND 0x0080000)}
$countdelegkrbnoconstrained  = ($delegkrbnoconstrained | measure-object).count
$criticalobjects += $delegkrb
if($error)
    { "$(Get-TimeStamp) Error while retrieving objects trusted for Kerberos delegation: $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	"$(Get-TimeStamp) Number of objects kerberos delegation setup: $($countdelegkrb) "  | out-file log-adexport.log -append
	"$(Get-TimeStamp) Number of objects with Kerberos unconstrained delegation configured: $($countdelegkrbnoconstrained) - $($countDCpresents) of them are domain controllers"  | out-file log-adexport.log -append
	}


#Directory Service Information object
$DSInfo = "CN=Directory Service,CN=Windows NT,CN=Services," + $root.configurationNamingContext
$criticalobjects += Get-ADObject $DSInfo -Server $server -properties *
if($error)
    { "$(Get-TimeStamp) Error while retrieving Directory Service Information object information $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	"$(Get-TimeStamp) Directory Service Information object retrieved in the configuration partition "  | out-file log-adexport.log -append
	}


#Getting all existing and deleted DNS Zones
$DNSZones = $root.namingcontexts | where-object{$_ -like "*DnsZones,*"} | foreach-object{get-adobject -searchbase $_ -Filter {ObjectClass -eq 'DNSZone'} -includedeletedobjects -properties * -server $server}
$criticalobjects += $DNSZones
$countDNSZones = ($DNSZones | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving DNS zones $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of existing and deleted DNS zones: $($countDNSZones)" | out-file log-adexport.log -append}


#Group Policy Objects, trusts, DPAPI secrets, AdminSDHolder, domainPolicy, RIDManager under the System container
$sysroot = "CN=System,"  + ($root.defaultNamingContext)
$sysobjects =  get-adobject -searchbase $sysroot -SearchScope SubTree -Filter {(ObjectClass -eq "groupPolicyContainer") -or (ObjectClass -eq "trustedDomain") -or (ObjectClass  -eq "rIDManager")  -or (ObjectClass -eq "secret")  -or (ObjectClass -eq "domainPolicy") -or (Name -eq "AdminSDHolder")} -server $server -properties *

if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$sysobjects = Get-ADObject -ResultPageSize $resultspagesize -searchbase $sysroot -SearchScope SubTree -Filter {(ObjectClass -eq "groupPolicyContainer") -or (ObjectClass -eq "trustedDomain")  -or (ObjectClass  -eq "rIDManager") -or (ObjectClass -eq "secret") -or (ObjectClass -eq "domainPolicy") -or (Name -eq "AdminSDHolder")} -server $server -properties *
		$i++
		}
	if($sysobjects){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $sysobjects
$countsysobjects = ($sysobjects | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving objects under the system container $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {
	$ridmanager = ((($sysobjects | where-object{$_.ObjectClass  -eq "rIDManager"}).fsmoRoleOwner).replace($root.configurationNamingContext,"")).replace("CN=NTDS Settings,","")
	"$(Get-TimeStamp) Number of objects of interest under the system container (GPOs, domain trusts, DPAPI secrets, AdminSDHolder and domainPolicy): $($countsysobjects)" | out-file log-adexport.log -append
}

#Loop through domain trusts and return their state
$trusts = $sysobjects | where-object{$_.ObjectClass -eq "trustedDomain"}

if($trusts)
    {
    $counttrusts = ($trusts | measure-object).count
    "$(Get-TimeStamp) Number of domain trusts: $($counttrusts)" | out-file log-adexport.log -append

    foreach($trust in $trusts)
	    {
		$sidfilt = "enabled"
	    if(([int32]$trust.trustattributes -band 0x00000004) -eq 0)
		    {
		    $sidfilt = "disabled"
		    }
		if(([int32]$trust.trustattributes -band 0x00000008) -eq 8)
		    {
		    $type = "inter-forest"
		    }
		if(([int32]$trust.trustattributes -band 0x00000032) -eq 32)
		    {
		    $type = "forest internal"
		    }
		if(([int32]$trust.trustattributes -band 0x00000016) -eq 16)
		    {
		    $type = "cross org trust with selective authentication"
		    }
		if(([int32]$trust.trustdirection) -eq 3)
		    {
		    $dir = "both directions"
		    }
		if(([int32]$trust.trustdirection) -eq 2)
		    {
		    $dir = "outgoing"
		    }
		if(([int32]$trust.trustdirection) -eq 1)
		    {
		    $dir = "incoming"
		    }
		if(([int32]$trust.trustdirection) -eq 0)
		    {
		    $dir = "disabled"
		    }
		"$(Get-TimeStamp) The domain trust with $($trust.name) is $($type) and $($dir) , SID filtering is $($sidfilt)" | out-file log-adexport.log -append
	    }
    }
else
    { "$(Get-TimeStamp) No domain trusts to process" | out-file log-adexport.log -append }

if($error)
    { "$(Get-TimeStamp) Error while retrieving domain trusts $($error)" | out-file log-adexport.log -append ; $error.clear() }

# Get all domain trusts of each domain in the forest through global catalog
$ContSys = "CN=System," + $root.defaultNamingContext
$TrustCat = "CN=Trusted-Domain," + $root.SchemaNamingContext
$search = new-object System.DirectoryServices.DirectorySearcher
$search.searchroot = [ADSI]"GC://$($gc)"
$search.pagesize = 256
$search.filter = "(ObjectCategory=$($TrustCat))"
$allTrustsquery = $search.findall()
if($allTrustsquery)
	{
	$allTrusts  = $allTrustsquery  | Convert-ADSearchResult
	$otherTrusts = $allTrusts | where-object{$_.DistinguishedName -notlike "*$($ContSys)"}
	$countallTrusts = ($allTrusts | group-object -property TrustPartner | measure-object).count
	$gcobjects += $otherTrusts
	if($error)
		{ "$(Get-TimeStamp) Error while retrieving domain trusts of each domain in the forest through GC $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else {"$(Get-TimeStamp) Number of trust partners in the forest: $($countallTrusts)" | out-file log-adexport.log -append}
	}

# Get all domain roots in the forest through global catalog
$DomainCat = "CN=Domain-DNS," + $root.SchemaNamingContext
$search = new-object System.DirectoryServices.DirectorySearcher
$search.searchroot = [ADSI]"GC://$($gc)"
$search.pagesize = 256
$search.filter = "(ObjectCategory=$($DomainCat))"
$alldomains = $search.findall()  | Convert-ADSearchResult
$otherdomains = $alldomains | where-object{$_.DistinguishedName -ne $root.DefaultNamingContext}
$gcobjects += $otherdomains
$countallDomains = ($alldomains  | measure-object).count
	if($error)
		{ "$(Get-TimeStamp) Error while retrieving forest domain roots through GC $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else {"$(Get-TimeStamp) Number of domain roots located in the forest: $($countallDomains)" | out-file log-adexport.log -append}

# Processing SID History accounts
# Get all accounts with SIDHistory present in the forest, limit properties loaded (DN,SID,SIDHistory) for performance
$search = new-object System.DirectoryServices.DirectorySearcher
$search.filter = "(SIDHistory=*)"
$search.pagesize = 256
$search.searchroot = [ADSI]"GC://$($gc)"
$search.PropertiesToLoad.Addrange(('DistinguishedName','SIDHistory','objectSID'))
$allSIDHistory  = $search.findall() | Convert-ADSearchResult
$countSIDHistory = ($allSIDHistory | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving accounts with SID History through GC $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of accounts with SIDHistory in the forest: $($countSIDHistory)" | out-file log-adexport.log -append}

#Get accounts in the current domain with a suspicious SIDHistory: Meaning with a SIDHistory of its own domain or a well known SID with high privileges
$CurrDomainSIDHistory = $allSIDHistory | where-object {($_.objectSID -like "$domSID*") -and (($_.SIDHistory -like "*$domSID*") -or ($_.SIDHistory -like "*-500") -or ($_.SIDHistory -eq "S-1-5-32-548") -or ($_.SIDHistory -eq "S-1-5-32-544") -or ($_.SIDHistory -eq "S-1-5-32-551") -or ($_.SIDHistory -like "*-512") -or ($_.SIDHistory -like "*-516") -or ($_.SIDHistory -like "*-519") -or ($_.SIDHistory -eq "S-1-5-32-550") -or ($_.SIDHistory -like "*-498") -or ($_.SIDHistory -like "*-518")  -or ($_.SIDHistory -eq "S-1-5-32-549"))}
if($CurrDomainSIDHistory)
	{
	$NbCurrDomainSIDHistory = ($CurrDomainSIDHistory | measure-object).count
	 "$(Get-TimeStamp) Number of accounts with a suspicious SIDHistory in the current domain: $($NbCurrDomainSIDHistory)" | out-file log-adexport.log -append
	 foreach($objSIDH in $CurrDomainSIDHistory)
		{
		$criticalobjects += get-adobject $objSIDH.DistinguishedName -Server $server -properties *
		if($error){ "$(Get-TimeStamp) Error while retrieving accounts with a suspicious SIDHistory in the current domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
		}
	}

# Get accounts in other domains than the current one within the forest which have an SIDHistory belonging to the current domain.
$OtherDomainSIDHistory = $allSIDHistory | where-object {($_.objectSID -notlike "$domSID*") -and ($_.SIDHistory -like "*$domSID*")}
if($OtherDomainSIDHistory)
	{
	# Get SIDs of accounts protected by SDProp in the current domain (i.e. privileged accounts)
	$sensibeSID = ($SDPropObjects | where-object{$_.objectSID -like "$domSID*"} | select-object -expandproperty objectSID).value
	$DangerOtherDomainSIDHistory = @()
	$NbOtherDomainSIDHistory = ($OtherDomainSIDHistory | measure-object).count
	$search = new-object System.DirectoryServices.DirectorySearcher
	$search.searchroot = [ADSI]"GC://$($gc)"
	"$(Get-TimeStamp) Number of accounts in other domains within the forest which have an SIDHistory belonging to the current domain $($NbOtherDomainSIDHistory)" | out-file log-adexport.log -append
	# Foreach account in other domains within the forest which have an SIDHistory belonging to the current domain we compare its SIDHistory with SIDs of accounts protected in the current domain by SDProp. If there is a match that could be suspicious.
	foreach($objSIDH in $OtherDomainSIDHistory)
			{
			foreach($SIDH in $objSIDH.SIDHistory)
				{

				if($sensibeSID.contains($SIDH))
					{
					$search.filter = "(DistinguishedName=$($objSIDH.DistinguishedName))"
					$DangerOtherDomainSIDHistory += $search.findone() | Convert-ADSearchResult
					}
				}
			if($error){ "$(Get-TimeStamp) Error while retrieving accounts in other domains within the forest which have an SIDHistory belonging to the current domain $($error)" | out-file log-adexport.log -append ; $error.clear() }

			}
	if($DangerOtherDomainSIDHistory)
		{
		$nbDangerOtherDomainSIDHistory = ($DangerOtherDomainSIDHistory | measure-object).count
		"$(Get-TimeStamp) Number of accounts in the forest with a suspicious SIDHistory value matching the current domain: $($nbDangerOtherDomainSIDHistory)" | out-file log-adexport.log -append
		$gcobjects += $DangerOtherDomainSIDHistory
		}
	}



#Fetch Organizational Units Objects, do not load all poperties for performance issues
$objOUs = Get-ADObject  -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -Filter {ObjectClass -eq "organizationalUnit"}  -Server $server

if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$objOUs = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -Filter {ObjectClass -eq "organizationalUnit"}  -Server $server
		$i++
		}
	if($objOUs){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
if($error)
    	{ "$(Get-TimeStamp) Error while retrieving OUs $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	$countobjOUs = ($objOUs | measure-object).count
	#If there is more than 1000 OUs we take only the level 1 + level 2 OUs and load all properties
	if($countobjOUs -ge 1000)
		{
		"$(Get-TimeStamp) Total number of OUs: $($countobjOUs), only level 1 and 2 OUs will be processed" | out-file log-adexport.log -append
		$OULevel1 = Get-ADObject -SearchBase ($root.defaultNamingContext) -SearchScope OneLevel -Server $server  -filter {ObjectClass -eq "organizationalUnit"} -properties *
		if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
			{
			$i = 1
			while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
				{
				write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
				$resultspagesize = 256 - $i * 40
				$error.clear()
				$OULevel1 = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope OneLevel -Server $server  -filter {ObjectClass -eq "organizationalUnit"} -properties *
				$i++
				}
			if($OULevel1){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
			else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
			}
		$totalOU = ($OULevel1 | measure-object).count
		$criticalobjects += $OULevel1
		if($error)
    			{ "$(Get-TimeStamp) Error while retrieving level 1 OUs $($error)" | out-file log-adexport.log -append ; $error.clear() }
		foreach($OU in $OULevel1)
			{
			$OULevel2 = Get-ADObject -SearchBase ($OU.DistinguishedName) -SearchScope OneLevel -Server $server  -filter {ObjectClass -eq "organizationalUnit"} -properties *

			if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
				{
				$i = 1
				while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
					{
					$resultspagesize = 256 - $i * 40
					write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
					$error.clear()
					$OULevel2 = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($OU.DistinguishedName) -SearchScope OneLevel -Server $server  -filter {ObjectClass -eq "organizationalUnit"} -properties *
					$i++
					}
				if($OULevel2){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
				else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
				}
			$totalOU = $totalOU + ($OULevel2 | measure-object).count
			$criticalobjects += $OULevel2
			if($error)
    				{ "$(Get-TimeStamp) Error while retrieving level 2 OUs $($error)" | out-file log-adexport.log -append ; $error.clear() }
			}

		"$(Get-TimeStamp) Total number of OUs processed: $($totalOU)" | out-file log-adexport.log -append
		}
	else
		{
		#Less than 1000 OUs we process every OU and load all properties
		"$(Get-TimeStamp) Total number of OUs: $($countobjOUs)" | out-file log-adexport.log -append
		$objOUsfull = Get-ADObject  -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -Filter {ObjectClass -eq "organizationalUnit"}  -Server $server -Properties *
		if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
			{
			$i = 1
			while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
				{
				$resultspagesize = 256 - $i * 40
				write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
				$error.clear()
				$objOUsfull = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -Filter {ObjectClass -eq "organizationalUnit"}  -Server $server -Properties *
				$i++
				}
			if($objOUsfull){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
			else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
			}
		$criticalobjects += $objOUsfull
		if($error)
    			{ "$(Get-TimeStamp) Error while retrieving OUs $($error)" | out-file log-adexport.log -append ; $error.clear() }
		}
	}


#Get AD replication sites, CertificationAuthority, CrossRefs objects in the configuration partition
$sitesIGC = get-adobject -searchbase $root.configurationNamingContext -SearchScope SubTree -Filter {(ObjectClass -eq "CertificationAuthority") -or (ObjectClass -eq "site") -or (ObjectClass -eq "crossRefContainer") -or (ObjectClass -eq "crossRef")} -server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$sitesIGC = Get-ADObject -ResultPageSize $resultspagesize -searchbase $root.configurationNamingContext -SearchScope SubTree -Filter {(ObjectClass -eq "CertificationAuthority") -or (ObjectClass -eq "site") -or (ObjectClass -eq "crossRefContainer") -or (ObjectClass -eq "crossRef")} -server $server -properties *
		$i++
		}
	if($sitesIGC){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects +=  $sitesIGC
$countADreplsites = ($sitesIGC | where-object{$_.ObjectClass -eq "site"} |  measure-object).count
$countADIGC = ($sitesIGC | where-object{$_.ObjectClass -eq "CertificationAuthority"} |  measure-object).count

if($error)
    { "$(Get-TimeStamp) Error while retrieving AD replication sites and CertificationAuthority objects $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {
	"$(Get-TimeStamp) Number of AD replication sites in the configuration partition: $($countADreplsites)" | out-file log-adexport.log -append
	"$(Get-TimeStamp) Number of CertificationAuthority objects in the configuration partition: $($countADIGC)" | out-file log-adexport.log -append
	$crossrefcontainer = $sitesIGC | where-object{($_.Name -eq "Partitions") -and ($_.ObjectClass -eq "crossRefContainer")}
	$DomainNamingMaster = (($crossrefcontainer.fsmoRoleOwner).replace($root.configurationNamingContext,"")).replace("CN=NTDS Settings,","")
	}


# Displayin FSMO role olders and FFL + DFL
if($PDCe)
	{ "$(Get-TimeStamp) PDCe for the domain is: $($PDCe)" | out-file log-adexport.log -append}
if($inframaster)
	{ "$(Get-TimeStamp) Infrastructure master for the domain is: $($inframaster)" | out-file log-adexport.log -append}
if($ridmanager)
	{ "$(Get-TimeStamp) RID Manager for the domain is: $($ridmanager)" | out-file log-adexport.log -append}
if($DomainNamingMaster)
	{ "$(Get-TimeStamp) Domain naming master for the forest is: $($DomainNamingMaster)" | out-file log-adexport.log -append}
if($SchemaMaster)
	{ "$(Get-TimeStamp) Schema master for the forest is: $($SchemaMaster)" | out-file log-adexport.log -append}
if($crossrefcontainer)
	{ "$(Get-TimeStamp) Forest functional level is: $($crossrefcontainer."msDS-Behavior-Version")" | out-file log-adexport.log -append}
$refdomains = $sitesIGC | where-object{($_.Objectclass -eq "crossRef") -and ($_.SystemFlags -eq 3)}
if($refdomains)
	{
	foreach($refdomain in $refdomains){ "$(Get-TimeStamp) $($refdomain.dnsRoot) domain functional level is $($refdomain."msDS-Behavior-Version")" | out-file log-adexport.log -append}
	}

#Find user accounts sensitive to Kerberoast attack (Service Principal Name not null)
$ObjCategoryusr = "CN=Person," + ($root.schemaNamingContext)
$kerberoast = Get-ADObject -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -LDAPFilter "(&(objectCategory=$ObjCategoryusr)(ServicePrincipalName=*))" -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$kerberoast = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -LDAPFilter "(&(objectCategory=$ObjCategoryusr)(ServicePrincipalName=*))" -Server $server -properties *
		$i++
		}
	if($kerberoast){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $kerberoast
$kerberoastcount = ($kerberoast | where-object{($_.Name -ne "krbtgt")} | measure-object).count
$kerberoastadmcount = ($kerberoast | where-object{($_.Name -ne "krbtgt") -and ($_.Admincount -eq 1)} | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving kerberoastable accounts  $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
		"$(Get-TimeStamp) Number of kerberoastable accounts: $($kerberoastcount)" | out-file log-adexport.log -append
		if($kerberoastadmcount -ge 1)
			{"$(Get-TimeStamp) Number of kerberoastable accounts protected by SDProp: $($kerberoastadmcount)" | out-file log-adexport.log -append}
	}

#Find user accounts sensitive to AS-REP roast attack
$asreproast = Get-ADObject -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -ldapfilter {(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))} -Server $server -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$resultspagesize = 256 - $i * 40
		$error.clear()
		$asreproast = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -ldapfilter {(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))}  -Server $server -properties *
		$i++
		}
	if($asreproast){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects += $asreproast
$asreproastcount = ($asreproast | measure-object).count
$asreproastadmcount = ($asreproast | where-object {($_.Admincount -eq 1)} | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving AS-Rep roastables accounts  $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
		"$(Get-TimeStamp) Number of AS-Rep roastables accounts: $($asreproastcount)" | out-file log-adexport.log -append
		if($asreproastadmcount -ge 1)
			{"$(Get-TimeStamp) Number of AS-Rep roastable accounts protected by SDProp: $($asreproastadmcount)" | out-file log-adexport.log -append}
	}


#Get Extended rights defined in the Configuration partition
$extroot = "CN=Extended-Rights," +  $root.configurationNamingContext
$extrights = Get-ADObject -SearchBase $extroot -SearchScope OneLevel -Server $server -filter {ObjectClass -eq "controlAccessRight"} -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$extrights = Get-ADObject -ResultPageSize $resultspagesize -SearchBase $extroot -SearchScope OneLevel -Server $server -filter * -properties *
		$i++
		}
	if($extrights){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects +=  $extrights
$countextrights = ($extrights | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving extended rights $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of extended rights: $($countextrights)" | out-file log-adexport.log -append}


# Get schema attributes with Searchflags marked as confidential
$confidattr = Get-ADObject -SearchBase $root.SchemaNamingContext  -SearchScope OneLevel -Server $server -filter {(SearchFlags -BAND 0x00000080) -and (ObjectClass -eq "attributeSchema")} -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$confidattr = Get-ADObject -ResultPageSize $resultspagesize -SearchBase $root.SchemaNamingContext  -SearchScope OneLevel -Server $server -filter {(SearchFlags -BAND 0x00000080) -and (ObjectClass -eq "attributeSchema")} -properties *
		$i++
		}
	if($extrights){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects +=  $confidattr
$countconfidattr = ($confidattr | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving schema attributes marked as confidential $($error)" | out-file log-adexport.log -append ; $error.clear() }
else
	{
	"$(Get-TimeStamp) Number of schema attributes marked as confidential: $($countconfidattr)" | out-file log-adexport.log -append
	$laps = $confidattr | where-object{$_.Name -eq "ms-Mcs-AdmPwd"}
	if($laps)
		{"$(Get-TimeStamp) LAPS is setup in this forest and ms-Mcs-AdmPwd is marked as confidential" | out-file log-adexport.log -append}
	else
		{"$(Get-TimeStamp) LAPS is not setup in the forest or ms-Mcs-AdmPwd is not marked as confidential" | out-file log-adexport.log -append}
	$bitlocker = $confidattr | where-object{$_.Name -eq "ms-FVE-RecoveryPassword"}
	if($bitlocker)
		{"$(Get-TimeStamp) Bitlocker recovery key attribute is marked as confidential" | out-file log-adexport.log -append}
	else
		{"$(Get-TimeStamp) Bitlocker recovery key attribute is not marked as confidential" | out-file log-adexport.log -append}
	}


# Get schema attributes with Searchflags marked as never audit
$neveraudit = Get-ADObject -SearchBase $root.SchemaNamingContext  -SearchScope OneLevel -Server $server -filter {(SearchFlags -BAND 0x00000100) -and (ObjectClass -eq "attributeSchema")} -properties *
if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$neveraudit = Get-ADObject -ResultPageSize $resultspagesize -SearchBase $root.SchemaNamingContext  -SearchScope OneLevel -Server $server -filter {(SearchFlags -BAND 0x00000100) -and (ObjectClass -eq "attributeSchema")} -properties *
		$i++
		}
	if($extrights){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$criticalobjects +=  $neveraudit
$countneveraudit = ($neveraudit | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving schema attributes marked as never to audit $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {"$(Get-TimeStamp) Number of schema attributes marked as never to audit: $($countneveraudit)" | out-file log-adexport.log -append}



#Check if current domain is root or child domain. if child domain get domain, enterprise, schema admins of root domain
if($root.rootDomainNamingContext -eq $root.DefaultNamingContext)
	{
	"$(Get-TimeStamp) Current domain is the root domain" | out-file log-adexport.log -append
	}
Else
	{
	"$(Get-TimeStamp) Current domain is a child domain" | out-file log-adexport.log -append
	$search = new-object System.DirectoryServices.DirectorySearcher
	$search.searchroot = [ADSI]"GC://$($gc)/$($root.rootDomainNamingContext)"
	$search.searchscope = "Base"
	$search.filter = "(ObjectSID=*)"
	$rootdom = $search.Findone() | Convert-ADSearchResult
	$gcobjects  += $rootdom
	$rootdomSID = $rootdom.ObjectSID
	$rootDomadmSID = $rootdomSID + "-512"
	$rootEntadmSID = $rootdomSID + "-519"
	$rootSchemaSID = $rootdomSID + "-518"
	#Cannot retrieve privileged accounts via SDProp, because AdminCount is not in partial attribute set, getting by group membership.
	#Retrieving the domain admins group which is global: cannot get members via GC
	$search.searchscope = "Subtree"
	$search.filter = "(ObjectSID=$($rootDomadmSID))"
	$rootda = $search.Findone() | Convert-ADSearchResult
	$gcobjects += $rootda
	if($error)
			{ "$(Get-TimeStamp) Error while retrieving domain admins group in root domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else
			{"$(Get-TimeStamp) Domain admins group sucessfully retrieved in root domain" | out-file log-adexport.log -append}
	#Retrieving the schema and enterprise admins groups which are universal: we can retrieve members via GC
	$search.filter = "(|(ObjectSID=$($rootEntadmSID))(ObjectSID=$($rootSchemaSID)))"
	$rootUadmins = $search.FindAll() | Convert-ADSearchResult
	$gcobjects += $rootUadmins
	$countrootadminsmembers = 0
	foreach($rootadmin in $rootUadmins)
		{
		$rootadminsmembers = $null
		$search.searchroot = [ADSI]"GC://$($gc)"
		if($rootadmin.Member){$rootadminsmembers = $rootadmin.Member | foreach-object{$search.filter = "(DistinguishedName=$($_))"; $search.FindOne() | Convert-ADSearchResult}}
		$countrootadminsmembers = ($rootadminsmembers | measure-object).count + $countrootadminsmembers
		$gcobjects += $rootadminsmembers
		}
		if($error)
			{ "$(Get-TimeStamp) Error while retrieving enterprise and schema admins members located in the root domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
				else
			{"$(Get-TimeStamp) Number of level 1 enterprise and schema admins members located in the root domain: $($countrootadminsmembers)" | out-file log-adexport.log -append}
	}


#Check if MS Exchange is installed by testing the Exchange Trusted SubSystem (ETS) existance
$trustedSubSystem = "CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups," + ($root.rootDomainNamingContext)
$ISets = [ADSI]::Exists("GC://$($gc)/$($trustedSubSystem)")
$serviceNC = "CN=Services," + ($root.configurationNamingContext)
$RBAC = $null
if($error)
    { "$(Get-TimeStamp) Error while retrieving Exchange trusted subsystem  object $($error)" | out-file log-adexport.log -append ; $error.clear() }

if($ISets -eq $true)
#Exchange is installed
	{
	if($root.rootDomainNamingContext -eq $root.DefaultNamingContext)
		{
		# If current domain is root domain, we do not need GC to retrieve Exchange objects information.
		$ets = get-adobject $trustedSubSystem -server $server -properties *
		$criticalobjects += $ets
		"$(Get-TimeStamp) Retrieving Exchange Trusted Subsytem, Exchange servers and Exchange Windows Permissions groups" | out-file log-adexport.log -append
		$Winperm = "CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups," + ($root.rootDomainNamingContext)
		$ExcSRV = "CN=Exchange Servers,OU=Microsoft Exchange Security Groups," + ($root.rootDomainNamingContext)
		$criticalobjects += get-adobject $Winperm -server $server -properties *
		$criticalobjects += get-adobject $ExcSRV -server $server -properties *

		if($error)
			{ "$(Get-TimeStamp) Error while retrieving Exchange Trusted Subsytem or Exchange servers or Exchange Windows Permissions groups $($error)" | out-file log-adexport.log -append ; $error.clear() }

		if($isonline -eq $true)
			{
			$trustedsubsysmembers = (Get-ADGroupMember -recursive $ets -server $server  | foreach-object{get-adobject $_ -server $server -properties *})
			$criticalobjects += $trustedsubsysmembers
			$nestedgrp = @()
			$level1 = Get-ADGroupMember $ets -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName
			if($level1)
				{
				$nestedgrp += $level1
				$nestedgrp  += $level1 | foreach-object{Get-ADGroupMember $_.DistinguishedName -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName}
				$criticalobjects += ($nestedgrp | foreach-object{get-adobject $_.DistinguishedName -server $server -properties *})
				}
				$counttrustedsubsysmembers = ($trustedsubsysmembers | measure-object).count
				if($error)
				{ "$(Get-TimeStamp) Error while retrieving ETS members $($error)" | out-file log-adexport.log -append ; $error.clear() }
				else
				{"$(Get-TimeStamp) Number of  ETS members: $($counttrustedsubsysmembers)" | out-file log-adexport.log -append}
			}
		else
			{
			$trustedsubsysmembers = ($ets | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *})
			$criticalobjects += $trustedsubsysmembers
			$continue = $trustedsubsysmembers | where-object{$_.ObjectClass -eq "Group"}
			if($continue)
				{foreach($grp in $continue){$trustedsubsysmembersn2 = $grp | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *};$criticalobjects += $trustedsubsysmembersn2}}
			if($error)
				{ "$(Get-TimeStamp) Error while retrieving ETS members $($error)" | out-file log-adexport.log -append ; $error.clear() }
				else
				{"$(Get-TimeStamp) ETS members processed, getting nested groups till level 2 " | out-file log-adexport.log -append}
			}
		# Fetching transport rules, accepted domains, SMTP connectors and Mailbox databases
		$SMTP = Get-ADObject -searchbase $root.configurationNamingContext -filter {(ObjectClass -eq "msExchTransportRule") -or (ObjectClass -eq "msExchAcceptedDomain")  -or (ObjectClass -eq "msExchRoutingSMTPConnector")  -or (ObjectClass -eq "msExchSmtpReceiveConnector") -or (ObjectClass -eq "msExchMDB")} -server $server -Properties *
		if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
			{
			$i = 1
			while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
				{
				$resultspagesize = 256 - $i * 40
				write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
				$error.clear()
				$SMTP = Get-ADObject -ResultPageSize $resultspagesize -searchbase $root.configurationNamingContext -filter {(ObjectClass -eq "msExchTransportRule") -or (ObjectClass -eq "msExchAcceptedDomain")  -or (ObjectClass -eq "msExchRoutingSMTPConnector")  -or (ObjectClass -eq "msExchSmtpReceiveConnector") -or (ObjectClass -eq "msExchMDB")} -server $server -Properties *
				$i++
				}
			if($SMTP){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
			else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
			}
		$criticalobjects += $SMTP
		$countSMTP = ($SMTP | measure-object).count
				if($error)
				{ "$(Get-TimeStamp) Error while retrieving mail flow and storage related objects $($error)" | out-file log-adexport.log -append ; $error.clear() }
				else
				{
				if($SMTP)
						{"$(Get-TimeStamp) Number of mail flow and storage related objects: $($countSMTP)" | out-file log-adexport.log -append}
					else
						{"$(Get-TimeStamp) Cannot read mail flow and storage related objects with the account running the script" | out-file log-adexport.log -append}
				}
		#Getting RBAC rol assignements
		"$(Get-TimeStamp) Retrieving RBAC role assignements" | out-file log-adexport.log -append
		$RBAC = Get-ADObject -SearchBase $serviceNC -SearchScope SubTree -filter {ObjectClass -eq "msExchRoleAssignment"} -server $server -properties *
		if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
			{
			$i = 1
			while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
				{
				$resultspagesize = 256 - $i * 40
				write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
				$error.clear()
				$RBAC = Get-ADObject -ResultPageSize $resultspagesize -SearchBase $serviceNC -SearchScope SubTree -filter {ObjectClass -eq "msExchRoleAssignment"} -server $server -properties *
				$i++
				}
			if($RBAC){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
			else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
			}
		if($RBAC)
			{
			$countRBAC = ($RBAC | Measure-object).count
			"$(Get-TimeStamp) Number of RBAC role assignements: $($countRBAC)" | out-file log-adexport.log -append
			$criticalobjects += $RBAC
			# Get accounts with an RBAC role assigned
			$RBACassignements =  $RBAC | Group-Object -Property msExchUserLink | foreach-object{if($_.Name){get-adobject -Filter {DistinguishedName -eq $_.Name} -server $server -Properties *}}

				if($error)
					{ "$(Get-TimeStamp) Error while retrieving accounts with an RBAC role assigned $($error)" | out-file log-adexport.log -append ; $error.clear() }

			#Get direct assignements
			$usrRBACassignements = $RBACassignements | where-object{($_.objectClass -eq "user") -or ($_.objectClass -eq "inetOrgPerson") -or ($_.objectClass -eq "Computer")}
			$criticalobjects += $usrRBACassignements
				$countusrRBACassignements = ($usrRBACassignements | Measure-Object).count
				"$(Get-TimeStamp) Number of accounts with RBAC direct assignement: $($countusrRBACassignements)" | out-file log-adexport.log -append
			if($error)
					{ "$(Get-TimeStamp) Error while retrieving RBAC direct assignements $($error)" | out-file log-adexport.log -append ; $error.clear() }
			#Get assignements by groups, retrieve group membership
			$grpRBACassignements = $RBACassignements | where-object{($_.objectClass -eq "group")}
			$countgrpRBACassignements = ( $grpRBACassignements | measure-object).count
			"$(Get-TimeStamp) Number of accounts with RBAC indirect assignement: $($countgrpRBACassignements)" | out-file log-adexport.log -append
			$criticalobjects += $grpRBACassignements
			foreach($grp in $grpRBACassignements)
				{
				$membersROLE = $null
				if($isonline -eq $true)
					{
					$membersROLE = Get-ADGroupMember -recursive $grp -server $server
					if($membersROLE)
						{
						$criticalobjects += ($membersROLE | foreach-object{get-adobject $_ -server $server -properties *})
						$nestedgrp = @()
						$level1 = Get-ADGroupMember $grp -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName
						if($level1)
							{
							$nestedgrp += $level1
							$nestedgrp  += $level1 | foreach-object{Get-ADGroupMember $_.DistinguishedName -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName}
							$criticalobjects += ($nestedgrp | foreach-object{get-adobject $_.DistinguishedName -server $server -properties *})
							}
						}
					}
				else
					{
					$membersROLE = ($grp | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *})
					$criticalobjects += $membersROLE
					$continue = $membersROLE | where-object{$_.ObjectClass -eq "Group"}
					if($continue)
						{foreach($grprole in $continue){$membersROLEn2 = $grprole | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *};$criticalobjects += $membersROLEn2}}
					if($error)
						{ "$(Get-TimeStamp) Error while retrieving RBAC indirect assignements $($error)" | out-file log-adexport.log -append ; $error.clear() }
					}
				}
			if($error)
				{ "$(Get-TimeStamp) Error while retrieving RBAC indirect assignements $($error)" | out-file log-adexport.log -append ; $error.clear() }

			}
		else
			{
			"$(Get-TimeStamp) Cannot read RBAC role assignements with the account running the script" | out-file log-adexport.log -append
			$OUGrpExch = "OU=Microsoft Exchange Security Groups," + $root.DefaultNamingContext
			$GrpsExch = get-adobject -searchbase $OUGrpExch -Filter {ObjectClass -eq "Group"} -server $server -Properties *
			$countGrpsExch = ($GrpsExch | measure-object).count
			if($error)
				{ "$(Get-TimeStamp) Error while retrieving groups under MS Exchange Security Groups container $($error)" | out-file log-adexport.log -append ; $error.clear() }
			else
				{"$(Get-TimeStamp) Number of groups under MS Exchange Security Groups container: $($countGrpsExch)" | out-file log-adexport.log -append}

			if($GrpsExch)
				{
				$criticalobjects += $GrpsExch
				if($isonline -eq $true)
					{
					foreach($GrpExch in $GrpsExch)
						{
						$criticalobjects += (Get-ADGroupMember -recursive $GrpExch -server $server  | foreach-object{get-adobject $_ -server $server -properties *})
						$nestedgrp = @()
						$level1 = Get-ADGroupMember $GrpExch -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName
						if($level1)
							{
							$nestedgrp += $level1
							$nestedgrp  += $level1 | foreach-object{Get-ADGroupMember $_.DistinguishedName -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName}
							$criticalobjects += ($nestedgrp | foreach-object{get-adobject $_.DistinguishedName -server $server -properties *})
							}
						}
					}
				else
					{
					foreach($GrpExch in $GrpsExch)
						{
							$exchgrpc = ($GrpExch | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *})
							$criticalobjects += $exchgrpc
							$continue = $exchgrpc | where-object{$_.ObjectClass -eq "Group"}
							if($continue)
								{foreach($grp in $continue){$exchgrpcn2 = $grp | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *};$criticalobjects += $exchgrpcn2}}
						}
					}

				if($error)
					{ "$(Get-TimeStamp) Error while retrieving group membership of groups located under MS Exchange Security Groups container $($error)" | out-file log-adexport.log -append ; $error.clear() }
				}

			}

		}

	else
		{
		# If current domain is child domain, we need GC to retrieve some Exchange objects information.
		"$(Get-TimeStamp) Retrieving Exchange Trusted Subsystem on root domain" | out-file log-adexport.log -append
		$search = new-object System.DirectoryServices.DirectorySearcher
		$search.searchroot = [ADSI]"GC://$($gc)"
		$search.filter = "(DistinguishedName=$($trustedSubSystem))"
		$ets = $search.FindOne() | Convert-ADSearchResult
		$gcobjects += $ets
		if($ets.Member)
			{
			$rootobjectsmembers = $ets.Member | foreach-object{$search.filter = "(DistinguishedName=$($_))"; $search.FindOne() | Convert-ADSearchResult}
			$counttrustedsubsysmembers = ($rootobjectsmembers | measure-object).count
			$gcobjects += $rootobjectsmembers
			}
		if($error)
			{ "$(Get-TimeStamp) Error while retrieving Exchange Trusted SubSystem members in root domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
				else
			{"$(Get-TimeStamp) Number of level 1 Exchange Trusted SubSystem members $($counttrustedsubsysmembers)" | out-file log-adexport.log -append}
		# Windows Permissions and Exchange Servers is also retieved
		$Winperm = "CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups," + ($root.rootDomainNamingContext)
		$ExcSRV = "CN=Exchange Servers,OU=Microsoft Exchange Security Groups," + ($root.rootDomainNamingContext)
		$search.filter = "(DistinguishedName=$($Winperm))"
		$gcobjects += $search.FindOne() | Convert-ADSearchResult
		$search.filter = "(DistinguishedName=$($ExcSRV))"
		$gcobjects += $search.FindOne() | Convert-ADSearchResult
		if($error)
			{ "$(Get-TimeStamp) Error while retrieving Exchange Windows Permissions or Exchange servers groups $($error)" | out-file log-adexport.log -append ; $error.clear() }
		# Fetching transport rules, accepted domains, SMTP connectors and Mailbox databases
		$SMTP = Get-ADObject -searchbase $root.configurationNamingContext -filter {(ObjectClass -eq "msExchTransportRule") -or (ObjectClass -eq "msExchAcceptedDomain")  -or (ObjectClass -eq "msExchRoutingSMTPConnector")  -or (ObjectClass -eq "msExchSmtpReceiveConnector") -or (ObjectClass -eq "msExchMDB")} -server $server -Properties *

		if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
			{
			$i = 1
			while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
				{
				$resultspagesize = 256 - $i * 40
				write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
				$error.clear()
				$SMTP = Get-ADObject -ResultPageSize $resultspagesize -searchbase $root.configurationNamingContext -filter {(ObjectClass -eq "msExchTransportRule") -or (ObjectClass -eq "msExchAcceptedDomain")  -or (ObjectClass -eq "msExchRoutingSMTPConnector")  -or (ObjectClass -eq "msExchSmtpReceiveConnector") -or (ObjectClass -eq "msExchMDB")} -server $server -Properties *
				$i++
				}
			if($SMTP){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
			else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
			}

		$criticalobjects += $SMTP
		$countSMTP = ($SMTP | measure-object).count
				if($error)
					{ "$(Get-TimeStamp) Error while retrieving mail flow and storage related objects $($error)" | out-file log-adexport.log -append ; $error.clear() }
				else
					{
					if($SMTP)
						{"$(Get-TimeStamp) Number of mail flow and storage related objects: $($countSMTP)" | out-file log-adexport.log -append}
					else
						{"$(Get-TimeStamp) Cannot read mail flow and storage related objects with the account running the script" | out-file log-adexport.log -append}
					}

		#Getting RBAC role assignements
		$RBAC = Get-ADObject -SearchBase $serviceNC -SearchScope SubTree -filter {ObjectClass -eq "msExchRoleAssignment"} -server $server -properties *
		if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
			{
			$i = 1
			while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
				{
				$resultspagesize = 256 - $i * 40
				write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
				$error.clear()
				$RBAC = Get-ADObject -ResultPageSize $resultspagesize -SearchBase $serviceNC -SearchScope SubTree -filter {ObjectClass -eq "msExchRoleAssignment"} -server $server -properties *
				$i++
				}
			if($RBAC){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
			else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
			}
		if($RBAC)
			{
			$countRBAC = ($RBAC | Measure-object).count
			"$(Get-TimeStamp) Number of RBAC role assignements: $($countRBAC)" | out-file log-adexport.log -append
			$criticalobjects += $RBAC
			# Get objects assigned to role via GC
			$RBACassignements =  $RBAC | Group-Object -Property msExchUserLink | foreach-object{if($_.Name){$search.filter = "(DistinguishedName=$($_.Name))"; $search.FindOne() | Convert-ADSearchResult}}
			if($error)
				{ "$(Get-TimeStamp) Error while retrieving accounts with an RBAC role assigned $($error)" | out-file log-adexport.log -append ; $error.clear() }

			$usrRBACassignements = $RBACassignements | where-object{($_.objectClass -eq "user") -or ($_.objectClass -eq "inetOrgPerson") -or ($_.objectClass -eq "Computer")}
			$gcobjects += $usrRBACassignements
			$countusrRBACassignements = ($usrRBACassignements | Measure-Object).count
			"$(Get-TimeStamp) Number of accounts with a direct RBAC assignement: $($countusrRBACassignements)" | out-file log-adexport.log -append
			$grpRBACassignements = $RBACassignements | where-object{($_.objectClass -eq "group")}
			# Get RBAC indirect assignements but not group membership
			$countgrpRBACassignements = ( $grpRBACassignements | measure-object).count
			"$(Get-TimeStamp) Number of groups with an indirect RBAC assignement:  $($countgrpRBACassignements)" | out-file log-adexport.log -append
			$gcobjects += $grpRBACassignements
			}
		else
			{
			"$(Get-TimeStamp) RBAC roles could not be retrieved by current account" | out-file log-adexport.log -append
			"$(Get-TimeStamp) Retrieving groups located in the Microsoft Exchange Security Groups container via GC" | out-file log-adexport.log -append
			$OUGrpExch = "OU=Microsoft Exchange Security Groups," + $root.rootDomainNamingContext
			$search.searchroot = [ADSI]"GC://$($gc)/$($OUGrpExch)"
			$search.filter = "(ObjectClass=Group)"
			$search.pagesize = 256
			$GrpsExch = $search.FindAll() | Convert-ADSearchResult
			$gcobjects += $GrpsExch
			$countGrpsExch = ( $GrpsExch | measure-object).count
			$search.searchroot = [ADSI]"GC://$($gc)"
			foreach($GrpExch in $GrpsExch)
				{
				$GrpExchmembers = $null
				if($GrpExch.Member){$GrpExchmembers = $GrpExch.Member | foreach-object{$search.filter = "(DistinguishedName=$($_))"; $search.FindOne() | Convert-ADSearchResult}}
				$gcobjects += $GrpExchmembers
				}
			if($error)
				{ "$(Get-TimeStamp) Error while retrieving groups plus members located under the Microsoft Exchange Security Groups container in the root domain $($error)" | out-file log-adexport.log -append ; $error.clear() }
			else
				{"$(Get-TimeStamp) Number of groups located in Microsoft Exchange Security Groups container in the root domain: $($countGrpsExch)" | out-file log-adexport.log -append}

			}
		}

	}

$error.clear()

#Processing custom group, please fill in table at the begining of the script for processing
if($groupscustom)
	{
    "$(Get-TimeStamp) Custom groups provided by the analyst" | out-file log-adexport.log -append
	foreach($grpcustom in $groupscustom)
		{
		$grpc = get-adobject -filter {Name -eq $grpcustom} -server $server -properties *
		$criticalobjects += $grpc
		if($isonline -eq $true)
			{
			$criticalobjects += (Get-ADGroupMember -recursive $grpc -server $server  | foreach-object{get-adobject $_ -server $server -properties *})
			$nestedgrp = @()
			$level1 = Get-ADGroupMember $grpc -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName
			if($level1)
				{
				$nestedgrp += $level1
				$nestedgrp  += $level1 | foreach-object{Get-ADGroupMember $_.DistinguishedName -server $server | where-object{$_.objectclass -eq "Group"} | select-object distinguishedName}
				$criticalobjects += ($nestedgrp | foreach-object{get-adobject $_.DistinguishedName -server $server -properties *})
				}
			}
		else
			{
			$customgrpc = ($grpc | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *})
			$criticalobjects += $customgrpc
			$continue = $customgrpc | where-object{$_.ObjectClass -eq "Group"}
			if($continue)
				{foreach($grp in $continue){$customgrpcn2 = $grp | select-object -expandproperty member  | foreach-object{get-adobject $_ -server $server -properties *};$criticalobjects += $customgrpcn2}}
			}
		}

        if($error)
            { "$(Get-TimeStamp) Error while retrieving custom groups $($error)" | out-file log-adexport.log -append ; $error.clear() }
        "$(Get-TimeStamp) Custom groups retrieved" | out-file log-adexport.log -append
	}



 #Get dynamic objects
 $DynObjects = Get-ADObject  -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -Filter {ObjectClass -eq "dynamicObject"}  -Server $server -properties *
 if(($error -like '*timeout*') -or ($error -like '*invalid enumeration context*'))
	{
	$i = 1
	while((($error -like '*timeout*') -or ($error -like '*invalid enumeration context*')) -and ($i -le 5))
		{
		$resultspagesize = 256 - $i * 40
		write-output -inputobject "LDAP time out, trying again with ResultPageSize $($resultspagesize)"
		$error.clear()
		$DynObjects = Get-ADObject -ResultPageSize $resultspagesize -SearchBase ($root.defaultNamingContext) -SearchScope SubTree -Filter {ObjectClass -eq "dynamicObject"}  -Server $server -properties *
		$i++
		}
	if($DynObjects){write-output -inputobject "LDAP query succeeded with different ResultPageSize"}
	else{write-output -inputobject "LDAP query failure despite different ResultPageSize, resuming script"}
	}
$countDynObjects = ($DynObjects | measure-object).count
if($error)
    { "$(Get-TimeStamp) Error while retrieving dynamic objects $($error)" | out-file log-adexport.log -append ; $error.clear() }
else {
	"$(Get-TimeStamp) Number of dynamic objects: $($countDynObjects)" | out-file log-adexport.log -append
	}
if($DynObjects)
	{
	$ttlcount = 0
	#Merging TTL constructed attributes with AD Object
	foreach($DynObject in $DynObjects)
		{
		$ttl = Get-ADObject $DynObject -Server $server -properties msDS-Entry-Time-To-Die,entryTTL | select-object msDS-Entry-Time-To-Die,entryTTL
		if($ttl."msDS-Entry-Time-To-Die" -and $ttl.entryTTL)
			{
			$a = $ttl.entryTTL.tostring()
			$b = $ttl."msDS-Entry-Time-To-Die".tostring()
			$DynObject | add-member -MemberType NoteProperty -Name msDS-Entry-Time-To-Die -Value $a -force
			$DynObject |  add-member -MemberType NoteProperty -Name entryTTL -Value $b -force
			$DynObject |  add-member -MemberType NoteProperty -Name IsDynamic -Value $true -force
			$criticalobjects = $criticalobjects | where-object{$_.DistinguishedName -ne $DynObject.DistinguishedName}
			$criticalobjects += $DynObject
			$ttlcount++
			}
		else
			{
			$DynObject |  add-member -MemberType NoteProperty -Name IsDynamic -Value $true -force
			$criticalobjects = $criticalobjects | where-object{$_.DistinguishedName -ne $DynObject.DistinguishedName}
			$criticalobjects += $DynObject
			}
		}

	if($error)
		{ "$(Get-TimeStamp) Error while retrieving TTL for dynamic objects $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else
		{"$(Get-TimeStamp) Number of dynamic objects with TTL set: $($ttlcount)" | out-file log-adexport.log -append}
	}


write-output -inputobject "---- AD objects collected ----"



#Removing variables
if($SDPropObjects){Remove-variable SDPropObjects}
if($deletedusersgpo){Remove-variable deletedusersgpo}
if($sysobjects){Remove-variable sysobjects}
if($trusts){Remove-variable trusts}
if($allSIDHistory){Remove-variable allSIDHistory}
if($CurrDomainSIDHistory){Remove-variable CurrDomainSIDHistory}
if($OtherDomainSIDHistory){Remove-variable OtherDomainSIDHistory}
if($objOUs){Remove-variable objOUs}
if($kerberoast){Remove-variable kerberoast}
if($sitesIGC){Remove-variable sitesIGC}
if($RBAC){Remove-variable RBAC}
if($RBACassignements){Remove-variable RBACassignements}
if($usrRBACassignements){Remove-variable usrRBACassignements}
if($grpRBACassignements){Remove-variable grpRBACassignements}
if($membersROLE){Remove-variable membersROLE}
if($trustedsubsysmembers){Remove-variable trustedsubsysmembers}
if($deleteconf){Remove-variable deleteconf}
if($GrpsExch){Remove-variable GrpsExch}
if($GrpExchmembers){Remove-variable GrpExchmembers}
if($SMTP){Remove-variable SMTP}
if($dom1){Remove-variable dom1}
if($dcrepls){Remove-variable dcrepls}
if($DCpresents){Remove-variable DCpresents}
if($DCeffaces){Remove-variable DCeffaces}
if($customgrpc){Remove-variable customgrpc}
if($exchgrpc){Remove-variable exchgrpc}
if($otherDCs){Remove-variable otherDCs}
if($otherdomains){Remove-variable otherdomains}
if($DangerOtherDomainSIDHistory){Remove-variable DangerOtherDomainSIDHistory}
if($rootdom){Remove-variable rootdom}
if($rootda){Remove-variable rootda}
if($rootUadmins ){Remove-variable rootUadmins}
if($rootadminsmembers){Remove-variable rootadminsmembers}
if($deletedgpo){Remove-variable deletedgpo}
if($deletedusers){Remove-variable deletedusers}
if($OULevel1){Remove-variable OULevel1}
if($OULevel2){Remove-variable OULevel2}
if($asreproast){Remove-variable asreproast}
if($Classesschema){Remove-variable Classesschema}
if($dnsadmin){Remove-variable dnsadmin}
if($dnsadminsmembers){Remove-variable dnsadminsmembers}
if($delegkrb){Remove-variable delegkrb}
if($DNSZones){Remove-variable DNSZones}
if($objOUsfull){Remove-variable objOUsfull}
if($extrights){Remove-variable extrights}
if($confidattr){Remove-variable confidattr}
if($neveraudit){Remove-variable neveraudit}
if($rootschema){Remove-variable rootschema}
if($rootconf){Remove-variable rootconf}
if($DynObjectswithttl){Remove-variable DynObjectswithttl}
if($DynObjects){Remove-variable DynObjects}



#Launching garbage collector to free up some RAM
"$(Get-TimeStamp) Freeing up memory" | out-file log-adexport.log -append
write-output -inputobject "---- Freeing up memory ----"
[System.GC]::Collect()
if($error)
    { "$(Get-TimeStamp) Error while freeing up memory $($error)" | out-file log-adexport.log -append ; $error.clear() }



write-output -inputobject "---- Exporting objects as XML ----"
#Removing objects collected twice or more
$criticalobjects = $criticalobjects | sort-object -unique -Property DistinguishedName
"$(Get-TimeStamp) Removed LDAP objects collected twice or more" | out-file log-adexport.log -append
# Exporting objects
$criticalobjects | export-cliXML ADobjects.xml
"$(Get-TimeStamp) Objects retrieved via LDAP exported in ADobjects.xml" | out-file log-adexport.log -append
if($error)
    { "$(Get-TimeStamp) Error while exporting objects retrieved via LDAP $($error)" | out-file log-adexport.log -append ; $error.clear() }



$nbviaLDAP = $null
$nbviagc = $null
if($gcobjects)
	{
	$gcobjects = $gcobjects | sort-object -unique -Property DistinguishedName
	"$(Get-TimeStamp) Removed GC objects collected twice or more" | out-file log-adexport.log -append
	$gcobjects | export-cliXML gcADobjects.xml
	"$(Get-TimeStamp) Global Catalog objects exported in gcADobjects.xml" | out-file log-adexport.log -append
	if($error)
		{ "$(Get-TimeStamp) Error while exporting global catalog objects $($error)" | out-file log-adexport.log -append ; $error.clear() }

	$nbviaLDAP = ($criticalobjects | measure-object).count
	$nbviagc = ($gcobjects | measure-object).count
	"$(Get-TimeStamp) Number of objects retrieved via LDAP $($nbviaLDAP) and via Global Catalog $($nbviagc)" | out-file log-adexport.log -append
	$criticalobjects += $gcobjects
	}


# generation TimeLine � partir des metadata de r�plication
write-output -inputobject "---- Export done ----"
write-output -inputobject "---- Generating AD timeline ----"
"$(Get-TimeStamp) Starting to retrieve AD replication metadata" | out-file log-adexport.log -append
$countcrit = ($criticalobjects | measure-object).count
"$(Get-TimeStamp) Number of objects to process: $($countcrit)" | out-file log-adexport.log -append
write-output -inputobject "----$($countcrit) Objects to process ----"


$groupClass = "CN=Group," + $root.SchemaNamingContext
# Initializing AD replication metadata object
$Replinfo = [System.Collections.ArrayList]@()
$i = 0

foreach ($criticalobject in $criticalobjects)
	{
	if($criticalobject.DistinguishedName)
	{
	#Displaying progress bar
	write-progress -Activity "AD replication metadata" -Status "$i objects processed:" -percentcomplete ($i/$countcrit*100)
	#Parsing de msDS-ReplAttributeMetadata see blog Once Upon a Case https://blogs.technet.microsoft.com/pie/2014/08/25

	if($nbviagc -and ($i -ge $nbviaLDAP))
		{
		$search = new-object System.DirectoryServices.DirectorySearcher
		$search.searchroot = [ADSI]"GC://$($gc)"
		$search.Tombstone = $true
		$search.PropertiesToLoad.Addrange(('msDS-ReplAttributeMetadata','Name','DistinguishedName'))
		$search.filter = "(DistinguishedName=$($criticalobject.DistinguishedName))"
		$search.pagesize = 256
		$obj = 	$search.FindAll()  | Convert-ADSearchResult

		}
	else
		{$obj = get-adobject $criticalobject.DistinguishedName -Properties msDS-ReplAttributeMetadata -server $server -IncludeDeletedObjects}

	$metadas = $obj."msDS-ReplAttributeMetadata" | foreach-object{ ([xml] $_.Replace("`0","")).DS_REPL_ATTR_META_DATA }

	if($criticalobject.whencreated)
		{$whencreatedUTC = get-date (get-date($criticalobject.whencreated)).ToUniversalTime() -format u}
	else{$whencreatedUTC = "N/A"}

    	if($error)
        {"$(Get-TimeStamp) Error while retrieving AD replication metadata attributes msDS-ReplAttributeMetadata for $($criticalobject.DistinguishedName) $($error)" | out-file log-adexport.log -append ; $error.clear() }
	else
        {
	    foreach($metada in $metadas)
		    {

		    # Creating temp object with AD replication metadata attributes plus some object attributes relevant for timeline analysis
		    $tmpobj = new-object psobject
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name ftimeLastOriginatingChange -Value $metada.ftimeLastOriginatingChange
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name Name -Value $obj.Name
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name pszAttributeName -Value $metada.pszAttributeName
			add-member -InputObject $tmpobj -MemberType NoteProperty -Name ObjectClass -Value $criticalobject.ObjectClass
			add-member -InputObject $tmpobj -MemberType NoteProperty -Name DN -Value $obj.DistinguishedName
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name ObjectCategory -Value $criticalobject.ObjectCategory
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name SamAccountName -Value $criticalobject.SamAccountName
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name dwVersion -Value $metada.dwVersion
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name WhenCreated -Value $whencreatedUTC
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name Member -Value ""
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name ftimeCreated -Value ""
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name ftimeDeleted -Value ""
		    add-member -InputObject $tmpobj -MemberType NoteProperty -Name SID -Value $criticalobject.objectSid
			add-member -InputObject $tmpobj -MemberType NoteProperty -Name pszLastOriginatingDsaDN -Value $metada.pszLastOriginatingDsaDN
	    	add-member -InputObject $tmpobj -MemberType NoteProperty -Name uuidLastOriginatingDsaInvocationID -Value $metada.uuidLastOriginatingDsaInvocationID
	    	add-member -InputObject $tmpobj -MemberType NoteProperty -Name usnOriginatingChange -Value $metada.usnOriginatingChange
	    	add-member -InputObject $tmpobj -MemberType NoteProperty -Name usnLocalChange -Value $metada.usnLocalChange

	    	    # Append temp object to global AD replication metadata object
	    	    [void]$Replinfo.add($tmpobj)
		    if($error){ "$(Get-TimeStamp) Error while editing global AD replication metadata object $($error) for $($criticalobject.DistinguishedName)" | out-file log-adexport.log -append ; $error.clear() }
		    }
        }

	if($criticalobject.ObjectCategory -eq $groupClass)
		{
		#For groups we retrieve also the msDS-ReplValueMetadata attribute
		$isgcanduniversalorindom = $true
		if($nbviagc -and ($i -ge $nbviaLDAP))
			{
			# Only universal groups are processed
			if($criticalobject.GroupType -eq "-2147483640")
					{
					$search = new-object System.DirectoryServices.DirectorySearcher
					$search.searchroot = [ADSI]"GC://$($gc)"
					$search.Tombstone = $true
					$search.PropertiesToLoad.Addrange(('msDS-ReplValueMetadata','Name','DistinguishedName'))
					$search.filter = "(DistinguishedName=$($criticalobject.DistinguishedName))"
					$search.pagesize = 256
					$objgrp = 	$search.FindAll() | Convert-ADSearchResult
					}
			else
				{$isgcanduniversalorindom = $false}
			}

		else
			{$objgrp = get-adobject $criticalobject.DistinguishedName -Properties msDS-ReplValueMetadata -server $server -IncludeDeletedObjects}

		if($isgcanduniversalorindom)
			{if($objgrp."msDS-ReplValueMetadata"){$metadasgrp = $objgrp."msDS-ReplValueMetadata" | foreach-object{ ([xml] $_.Replace("`0","")).DS_REPL_VALUE_META_DATA}}}
		else {$metadasgrp  = $null}

			if($error)
        			{ "$(Get-TimeStamp) Error while retrieving AD replication metadata attributes msDS-ReplValueMetadata for $($criticalobject.DistinguishedName) $($error)" | out-file log-adexport.log -append ; $error.clear() }

			else
				{
				$metadasgrpmbr = $metadasgrp | where-object{$_.pszAttributeName -eq "member"}
				if($metadasgrpmbr)
					{
					foreach($metada in $metadasgrpmbr)
						{

						$tmpobj = new-object psobject
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name ftimeLastOriginatingChange -Value $metada.ftimeLastOriginatingChange
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name Name -Value $obj.Name
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name pszAttributeName -Value $metada.pszAttributeName
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name ObjectClass -Value $criticalobject.ObjectClass
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name DN -Value $obj.DistinguishedName
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name ObjectCategory -Value $criticalobject.ObjectCategory
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name SamAccountName -Value $criticalobject.SamAccountName
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name dwVersion -Value $metada.dwVersion
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name WhenCreated -Value $whencreatedUTC
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name Member -Value $metada.pszObjectDn
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name ftimeCreated -Value $metada.ftimeCreated
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name ftimeDeleted -Value $metada.ftimeDeleted
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name SID -Value $criticalobject.objectSid
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name pszLastOriginatingDsaDN -Value $metada.pszLastOriginatingDsaDN
	   					add-member -InputObject $tmpobj -MemberType NoteProperty -Name uuidLastOriginatingDsaInvocationID -Value $metada.uuidLastOriginatingDsaInvocationID
	    				add-member -InputObject $tmpobj -MemberType NoteProperty -Name usnOriginatingChange -Value $metada.usnOriginatingChange
						add-member -InputObject $tmpobj -MemberType NoteProperty -Name usnLocalChange -Value $metada.usnLocalChange

	    				[void]$Replinfo.add($tmpobj)
						if($error){ "$(Get-TimeStamp) Error while editing global AD replication metadata object $($error) for $($criticalobject.DistinguishedName)" | out-file log-adexport.log -append ; $error.clear() }
						}


					}
				}
		}
	}
	$i++
	}

"$(Get-TimeStamp) AD replication metadata retrieved" | out-file log-adexport.log -append


# Sort by ftimeLastOriginatingChange to generate timeline and export as csv
"$(Get-TimeStamp) Sorting AD replication metadata to generate timeline " | out-file log-adexport.log -append

$Replinfo | Sort-Object -Property ftimeLastOriginatingChange | export-csv timeline.csv -delimiter ";" -NoTypeInformation
    if($error)
        { "$(Get-TimeStamp) Error while sortig timeline $($error)" | out-file log-adexport.log -append ; $error.clear() }
    else
        { "$(Get-TimeStamp) Timeline created" | out-file log-adexport.log -append }

write-output -inputobject "---- Timeline created ----"


