function Global:prompt {"STG | DemoModule>"} 

$Global:Staging = $true
$Global:ActionParallelism = 5
$Global:Timeout = 30
$Global:NoPrompt = $false
$Global:RunChecks = $true
$Global:SlwIntegration = $false
Set-Variable -Name "Computername" -Value localhost -Scope Globa

Import-Module DemoModule
$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Gray')
$Host.UI.RawUI.ForegroundColor = 'Blue'
$Host.PrivateData.ErrorForegroundColor = 'Red'
$Host.PrivateData.ErrorBackgroundColor = $bckgrnd
$Host.PrivateData.WarningForegroundColor = 'Magenta'
$Host.PrivateData.WarningBackgroundColor = $bckgrnd
$Host.PrivateData.DebugForegroundColor = 'Black'
$Host.PrivateData.DebugBackgroundColor = $bckgrnd
$Host.PrivateData.VerboseForegroundColor = 'Yellow'
$Host.PrivateData.VerboseBackgroundColor = $bckgrnd
$Host.PrivateData.ProgressForegroundColor = 'Cyan'
$Host.PrivateData.ProgressBackgroundColor = $bckgrnd
[console]::ForegroundColor = "Blue"
[console]::BackgroundColor = "Gray"
Clear-Host
Write-Host ""
Write-Host "STAGING Values Set"
Read-Host "Press Any Key to Continue.."
Clear-Host