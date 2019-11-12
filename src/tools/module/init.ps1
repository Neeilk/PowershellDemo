
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
# bomb if not admin
if (!(Test-IsAdmin)) {
	Write-Error "You must run this module as an Administrator"
	break
}

# load modules
try {
	#Set-Location -Path "$($PSScriptRoot)"
	#if (!($var = Get-Variable -Name "logger" -Scope Global -ErrorAction SilentlyContinue)) {
	

	$requiredParameters = [ordered]@{
   		Staging = [bool];
	}
	if (Test-Interactive) {
	#		Get-UserParameterChoices -Parameters $requiredParameters
	Write-Host "This is where you prompt user to enter default param values :"
	Get-Variable -Name "Computername" -Scope Global -ErrorAction SilentlyContinue
	Set-Variable -Name "Computername" -Value localhost
	Get-Variable -Name "Computername" -Scope Global -ErrorAction SilentlyContinue
	
	}
	else {
		# set defaults
		$paramCheck = $true
		$requiredParameters.Keys | ForEach-Object {
			if (!($var = Get-Variable -Name $_ -Scope Global -ErrorAction SilentlyContinue)) {
				$paramCheck = $false
				#$Global:logger.Warn("Required global variable '$($_)' is not set.")
				Write-Host "Required global variable '$($_)' is not set." -ForegroundColor Yellow
			}
		}
		if (!($paramCheck)) {
			$err = "Global variable validation failed, cannot continue."
			Write-Host $er -ForegroundColor Cyan
			#$Global:logger.Fatal($err)
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
    #Get-UserParameterChoices -Parameters $requiredParameters
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

# set ebd url
# test dependencies and bomb if not available
# test db connection

#if (!($jiraCheck.TcpTestSucceeded)) {
#    $Global:logger.Warn("JIRA TCP Check failed, this module will not function correctly.")
#}

# set global data for param auto population
try {
	if (!($varCheck = Get-Variable -Name "AllAppGroups" -Scope Global -ErrorAction SilentlyContinue)) {
	 Write-Host " set gloabl data for autopopulation" -ForegroundColor Red
	
	}
}
catch {
   # $Global:logger.Fatal($_.Message)
    throw $_
    break	
}

# set acceptable groups
[array]$Global:ForceGroups = @("MyDomain\Devops", "MyDomain\SysAmdin")

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