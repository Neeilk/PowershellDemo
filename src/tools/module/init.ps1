<#
	Downloads nuget.exe and sets alias
#>
function Get-Nuget {
	$sourceNugetExe = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
	$targetNugetExe = "$($PSScriptRoot)\nuget.exe"
	if (!(Test-Path $targetNugetExe))
	{
		Invoke-WebRequest $sourceNugetExe -OutFile $targetNugetExe
	}
	if (!(Get-Alias -Name "nuget" -ErrorAction SilentlyContinue))
	{
		Set-Alias nuget $targetNugetExe -Scope Global
	}
}
<#
	Download log4net from nuget
#>
function Get-AndLoadLog4net {
	# download nuget if alias doesnt exist
	if (!(Get-Alias -Name "nuget" -ErrorAction SilentlyContinue))
	{
		Get-Nuget
	}
	$packageName = "log4net"
	$output = nuget install $packageName -source https://api.nuget.org/v3/index.json
	#$output | Write-Output
	if ($LASTEXITCODE -ne 0)
	{
		throw "An error occured whilst trying to download log4net`n$($output)"
	}
	# load the nitro dll
	if ($installedOut = $output | Where-Object {$_.Contains("Added package '")})
	{
		$version = $installedOut.Split("'")[1]
		if ($version.Contains(".0.0"))
		{
			$version = $version.Replace(".0.0", ".0")
		}
		$folder = $installedOut.Split("'")[3]
		$libFolder = "$((Get-Location).Path)\$($version)\lib\net45-full\log4net.dll"
		Add-Type -Path $libFolder
	}
	if ($alreadyInstalledOut = $output | Where-Object {$_.Contains("is already installed.")})
	{
		$version = $alreadyInstalledOut.Split('"')[1]
		if ($version.Contains(".0.0"))
		{
			$version = $version.Replace(".0.0", ".0")
		}
		$libFolder = "$((Get-Location).Path)\$($version)\lib\net45-full\log4net.dll"
		Add-Type -Path $libFolder
	}
}
<#
	Sets up log4net logger
#>
function Set-Logging {        	
    # Load Log4Net assembly:
	#Get-AndLoadLog4net
	#Set-Location -Path "$($PSScriptRoot)\bin"
	try {
		[void][Reflection.Assembly]::LoadFile("$($PSScriptRoot)\bin\Newtonsoft.Json.dll")
		[void][Reflection.Assembly]::LoadFile("$($PSScriptRoot)\bin\Logzio.DotNet.Log4net.dll")
		[void][Reflection.Assembly]::LoadFile("$($PSScriptRoot)\bin\log4net.dll")
		[log4net.LogManager]::ResetConfiguration()
	}
	catch {
		throw $_
		break
	}	
	
	# find log4net config
	$configFile = "$($PSScriptRoot)\conf\log4net.config"
    $log4netConfigFilePath = Resolve-Path $configFile -ErrorAction SilentlyContinue -ErrorVariable Err 
    if ($Err) 
	{ 
        throw "Log4Net configuration file $configFile cannot be found" 	
		break	
    } 
    
    # Construct FileInfo as argument to log4net.Config.XmlConfigurator.Configure:
    $FileInfo = New-Object System.IO.FileInfo($log4netConfigFilePath) 

    # Load log4net configuration:
	$parent = $PSScriptRoot
    [string] $name = $ENV:USERNAME + "\" + (Get-Date -Format "yyyyMMdd")
	$tempFolder = (Join-Path $parent $name)
	if (!(Test-Path $tempFolder)) {
    	New-Item -ItemType Directory -Path $tempFolder | Out-Null
	}
	# set logz token
	# QA by default
	$logzToken = "mVIhDJAburvIDBaAonNByeAABrjCnVmx"
	$logzEnvironment = "STG"
	if (!($Global:Staging)) {
		#PROD
		$logzToken = "jzVTNqTPPyeZugcUCnhrdcBirVFAYKiQ"
		$logzEnvironment = "PROD"
	}
	[log4net.GlobalContext]::Properties["LogPath"] = $tempFolder
	[log4net.GlobalContext]::Properties["LogzToken"] = $logzToken
	[log4net.GlobalContext]::Properties["LogzEnvironment"] = $logzEnvironment
    [log4net.Config.XmlConfigurator]::Configure($FileInfo) 
	[log4net.Config.XmlConfigurator]::ConfigureAndWatch($FileInfo)
    
	$global:logger = [log4net.LogManager]::GetLogger("FailoverControl");
	
	$global:logzIoLogger = [log4net.LogManager]::GetLogger("LogzIo");	

	$global:logger.Warn("Log path set as '$($tempFolder)'")
	#Pop-Location
}
function Test-IsAdmin {
	$check = $true
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
		[Security.Principal.WindowsBuiltInRole] "Administrator"))  
    {  
		$check = $false
	}

	return $check
}
function Test-Interactive {
    <#
    .Synopsis
        Determines whether both the user and process are interactive.
    #>

    [CmdletBinding()] Param()
    [Environment]::UserInteractive -and
    !([Environment]::GetCommandLineArgs() |? {$_ -ilike '-NonI*'})
}
function Get-UserParameterChoices {
    param
    (
        [Parameter(Mandatory = $true)]
        $Parameters
    )

    foreach ($parameter in $Parameters.Keys) {
		if (!($varCheck = Get-Variable -Name $parameter -Scope Global -ErrorAction SilentlyContinue)) {
			$type = $Parameters[$parameter]
			do {
				$conversion = $null
				if ($type -eq [securestring]) {
					$conversion = Read-Host -Prompt "Please enter value for '$($parameter)' ($($type.Name))" -AsSecureString
				}
				else {
					$response = Read-Host -Prompt "Please enter value for '$($parameter)' ($($type.Name))"
					try {
						$conversion = [System.Convert]::ChangeType($response, $type)
					}
					catch {
						$conversion = $null
					}
				}			
			}
			while ($conversion -eq $null)
			if ($varCheck = Get-Variable -Name $parameter -Scope Global -ErrorAction SilentlyContinue) {
				Set-Variable -Name $parameter -Value $conversion -Scope Global -Force | Out-Null
			}
			else {
				New-Variable -Name $parameter -Value $conversion -Scope Global -Force | Out-Null
			}
			# Zee set this param to 0...
			if ($parameter -ieq "ActionParallelism") {
				$varCheck = Get-Variable -Name $parameter -Scope Global -ErrorAction SilentlyContinue
				if ($varCheck.Value -lt 1) {
					Set-Variable -Name $parameter -Value 1 -Scope Global -Force | Out-Null
				}
			}
			$Global:logger.Info("Global variable '$($parameter)' set as '$($conversion)'")
		}
    }
}
function Set-StreambasePaths {
    
    $sbHome       = "C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3"
    $sbPath       = "C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3\bin64"
    $sbPythonPath = "C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3\lib64\python2.6"
    $sbClasspath  = "C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3\lib64\sbclient.jar"
   
    
    if((Test-Path -Path $sbHome)){
    
        Write-Information "Adding ENV Variables "
        if($env:Path -notcontains "StreamBase.7.3\bin64") {
			$env:Path="C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3\bin64;$env:Path"
			$Global:logger.Info("PATH Updated with Streambase bin64...")
		}
        if($env:PYTHONPATH -notcontains "python2") {
			$env:PYTHONPATH="C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3\lib64\python2.6"
			$Global:logger.Info("PYTHONPATH Updated with Streambase lib64...")
		}
        if($env:STREAMBASE_HOME -notcontains "Streambase.7.3") {
			$env:STREAMBASE_HOME="C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3"
			$Global:logger.Info("STREAMBASE_HOME Updated with Streambase...")
		}
        if($CLASSPATH  -notcontains "sbclient.jar") {
			$CLASSPATH="C:\Program Files (x86)\StreamBase Systems\StreamBase.7.3\lib64\sbclient.jar;$CLASSPATH"
			$Global:logger.Info("CLASSPATH Updated with Streambase sbclient.jar...")			
		}
		$Global:StreambaseEnabled = $true
    }
    else
    {
        Write-Warning "No streambase found in local machine"
    }
}
# bomb if not admin
if (!(Test-IsAdmin)) {
	Write-Error "You must run this module as an Administrator"
	break
}

# load modules
try {
	#Set-Location -Path "$($PSScriptRoot)"
	#if (!($var = Get-Variable -Name "logger" -Scope Global -ErrorAction SilentlyContinue)) {
	Set-Logging
	$requiredParameters = [ordered]@{
   		Staging = [bool];
	}
	if (Test-Interactive) {
		Get-UserParameterChoices -Parameters $requiredParameters
	}
	else {
		# set defaults
		$paramCheck = $true
		$requiredParameters.Keys | ForEach-Object {
			if (!($var = Get-Variable -Name $_ -Scope Global -ErrorAction SilentlyContinue)) {
				$paramCheck = $false
				$Global:logger.Warn("Required global variable '$($_)' is not set.")
			}
		}
		if (!($paramCheck)) {
			$err = "Global variable validation failed, cannot continue."
			$Global:logger.Fatal($err)
			throw $err
			break
		}
	}	
	#}
}
catch {
	throw $_
	Write-Error "Do not continue to use this session, importing of log4net and/or nitro dll's failed."
}

# check sb command available for price engines
$Global:StreambaseEnabled = $false
if (!(Get-Command -Name "sbadmin" -ErrorAction SilentlyContinue)) {
	Set-StreambasePaths
}
if (!(Get-Command -Name "sbadmin" -ErrorAction SilentlyContinue)) {
	Write-Warning "Command 'sbadmin' not available, price engine failover cannot be actioned in this session."
}
else {
	$Global:StreambaseEnabled = $true
}

#region set global variables
$requiredParameters = [ordered]@{
    NitroUsername = [string];
    NitroPassword = [securestring];
    ActionParallelism = [int];
    Timeout = [int];
    NoPrompt = [bool];
	RunChecks = [bool];
	SlwIntegration = [bool];
}
if (Test-Interactive) {
    Get-UserParameterChoices -Parameters $requiredParameters
}
else {
    # set defaults
    $paramCheck = $true
    $requiredParameters.Keys | ForEach-Object {
        if (!($var = Get-Variable -Name $_ -Scope Global -ErrorAction SilentlyContinue)) {
            $paramCheck = $false
            $Global:logger.Warn("Required global variable '$($_)' is not set.")
        }
    }
    if (!($paramCheck)) {
		$err = "Global variable validation failed, cannot continue."
		$Global:logger.Fatal($err)
        throw $err
        break
    }
}
# set slw url
if ($Global:SlwIntegration) {
	[hashtable]$requiredParameters = @{
		SlwUsername = [string];
		SlwPassword = [securestring];
	}
	if (Test-Interactive) {
		Get-UserParameterChoices -Parameters $requiredParameters
	}
	else {
		# set defaults
		$paramCheck = $true
		$requiredParameters.Keys | ForEach-Object {
			if (!($var = Get-Variable -Name $_ -Scope Global -ErrorAction SilentlyContinue)) {
				$paramCheck = $false
				$Global:logger.Warn("Required global variable '$($_)' is not set.")
			}
		}
		if (!($paramCheck)) {
			$err = "Global variable validation failed, cannot continue."
			$Global:logger.Fatal($err)
			throw $err
			break
		}
	}
	# SSL needs to be trusted as it is a untrusted one
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	$Global:SlwUrl = "https://pkh-stg-slw01:17778/SolarWinds/InformationService/v3/Json"
	if ($Staging) {
		$Global:SlwUrl = "https://pkh-stg-slw01:17778/SolarWinds/InformationService/v3/Json"
	}
	# create slw creds
	$Global:SlwCredentials = New-Object System.Management.Automation.PSCredential ($Global:SlwUsername, $Global:SlwPassword)
}

# set ebd url
$EdbUrl = "http://edb.cityindex.co.uk"
if ($Staging) {
    $EdbUrl = "http://edb-stg.cityindex.co.uk"
}
if ($Global:Debug) {
    $EdbUrl = "http://pkh-qat-cont01/stgdb"
}
# test dependencies and bomb if not available
# test edb
if (!($varCheck = Get-Variable -Name "edbCheck" -Scope Global -ErrorAction SilentlyContinue)) {
	$Global:edbCheck = Test-NetConnection -ComputerName $EdbUrl.Replace("http://", "").Split('/')[0] -Port 80
	#$jiraCheck = Test-NetConnection -ComputerName "jira.gaincapital.com" -Port 80
	if (!($Global:edbCheck.TcpTestSucceeded)) {
		$Global:logger.Fatal("EDB TCP Check failed, this module will not function correctly.")
		throw "EDB TCP Check failed, this module will not function correctly."
		break
	}
}
#if (!($jiraCheck.TcpTestSucceeded)) {
#    $Global:logger.Warn("JIRA TCP Check failed, this module will not function correctly.")
#}

# set full edb url
$Global:EdbUrl = $EdbUrl + "/ApplicationData.svc"
$Global:logger.Info("EDB URL is set as '$($Global:EdbUrl)'")

# set global data for param auto population
try {
	if (!($varCheck = Get-Variable -Name "AllAppGroups" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllAppGroups = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
				-Uri "$($Global:EdbUrl)/ApplicationGroups?`$select=Name" -Headers @{"Accept" = "application/json"}).Value.Name
	}
	if (!($varCheck = Get-Variable -Name "AllClusters" -Scope Global -ErrorAction SilentlyContinue)) {
   		$Global:AllClusters = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
            -Uri "$($Global:EdbUrl)/Clusters?`$select=Name" -Headers @{"Accept" = "application/json"}).Value.Name
	}
	if (!($varCheck = Get-Variable -Name "AllEnvironmentData" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllEnvironmentData = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
            -Uri "$($Global:EdbUrl)/Environments" -Headers @{"Accept" = "application/json"}).Value
	}
	if (!($varCheck = Get-Variable -Name "AllEnvironments" -Scope Global -ErrorAction SilentlyContinue)) {
    	$Global:AllEnvironments = ($Global:AllEnvironmentData | ForEach-Object {$_.Name})
	}
	if (!($varCheck = Get-Variable -Name "AllServers" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllServers = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
            -Uri "$($Global:EdbUrl)/Servers" -Headers @{"Accept" = "application/json"}).Value
	}
	if (!($varCheck = Get-Variable -Name "AllWindowsServices" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllWindowsServices = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
            -Uri "$($Global:EdbUrl)/WindowsServices" -Headers @{"Accept" = "application/json"}).Value
	}
	if (!($varCheck = Get-Variable -Name "AllServerWindowsServices" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllServerWindowsServices = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
            -Uri "$($Global:EdbUrl)/ServerWindowsServices" -Headers @{"Accept" = "application/json"}).Value
	}
	if (!($varCheck = Get-Variable -Name "AllWebServices" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllWebServices = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
            -Uri "$($Global:EdbUrl)/WebServices" -Headers @{"Accept" = "application/json"}).Value
	}
	if (!($varCheck = Get-Variable -Name "AllServerWebServices" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllServerWebServices = (Invoke-RestMethod -Method Get -UseBasicParsing -UseDefaultCredentials `
            -Uri "$($Global:EdbUrl)/ServerWebServices" -Headers @{"Accept" = "application/json"}).Value
	}
	if (!($varCheck = Get-Variable -Name "AllDatabases" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllDatabases = ($Global:AllServerWindowsServices | Where-Object {$_.Dependencies} | ForEach-Object {
			(ConvertFrom-Json -InputObject $_.Dependencies).DataSources.Database
		}) | Sort-Object -Unique
	}
	if (!($varCheck = Get-Variable -Name "AllSqlServers" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllSqlServers = ($Global:AllServerWindowsServices | Where-Object {$_.Dependencies} | ForEach-Object {
			(ConvertFrom-Json -InputObject $_.Dependencies).DataSources.DBServer
		}) | Sort-Object -Unique
	}
	if (!($varCheck = Get-Variable -Name "AllPriceEngines" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllPriceEngines = ($Global:AllWindowsServices | Where-Object {$_.BundlePath.Length -gt 1})
	}
	if (!($varCheck = Get-Variable -Name "AllPriceEngineNames" -Scope Global -ErrorAction SilentlyContinue)) {
		$Global:AllPriceEngineNames = ($Global:AllPriceEngines.Name | Sort-Object -Unique)
	}
}
catch {
    $Global:logger.Fatal($_.Message)
    throw $_
    break	
}

# set acceptable groups
[array]$Global:ForceGroups = @("GC\Business Continuity", "GC\IT Release Management", "CITYINDEX\QAT_Server_Admins", "CITYINDEX\GAIN-PlatformOperation")

# set the base nitro params
$Global:NitroParams = @{}
if ($Global:NitroUsername) {
    $Global:NitroParams.Add("Username", $Global:NitroUsername)
}
else {
    $Global:NitroParams.Add("Username", (Read-Host -Prompt "Please enter netscaler username"))
}
if ($Global:NitroPassword) {
    $Global:NitroParams.Add("Password", $Global:NitroPassword)
}
else {
    $Global:NitroParams.Add("Password", (Read-Host -Prompt "Please enter netscaler password" -AsSecureString))
}

# blow up if ISE
if ($host.name -ine "consolehost") {
    $msg = "You must run this module from a standard console to get log4net output"
    $Global:logger.Fatal($msg)
    throw $msg
    break
}

# for delayed state changes against edb
$Global:ClusterStateChanges = @()
$Global:WindowsServiceStateChanges = @()
$Global:WebServiceStateChanges = @()