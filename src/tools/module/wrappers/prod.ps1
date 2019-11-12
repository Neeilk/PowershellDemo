function Global:prompt {"PROD | PowershellDemo>"} 

$Global:Staging = $false
$Global:ActionParallelism = 3
$Global:Timeout = 120
$Global:NoPrompt = $false
$Global:RunChecks = $true
$Global:SlwIntegration = $false

Import-Module DemoModule
$Host.UI.RawUI.BackgroundColor = ($bckgrnd = 'Black')
$Host.UI.RawUI.ForegroundColor = 'Green'
$Host.PrivateData.ErrorForegroundColor = 'Red'
$Host.PrivateData.ErrorBackgroundColor = $bckgrnd
$Host.PrivateData.WarningForegroundColor = 'Magenta'
$Host.PrivateData.WarningBackgroundColor = $bckgrnd
$Host.PrivateData.DebugForegroundColor = 'Gray'
$Host.PrivateData.DebugBackgroundColor = $bckgrnd
$Host.PrivateData.VerboseForegroundColor = 'Yellow'
$Host.PrivateData.VerboseBackgroundColor = $bckgrnd
$Host.PrivateData.ProgressForegroundColor = 'Cyan'
$Host.PrivateData.ProgressBackgroundColor = $bckgrnd
[console]::ForegroundColor = "Green"
[console]::BackgroundColor = "Black"
Clear-Host
Write-Host "PROD Values Set"
Read-Host "Press Any Key to Continue.."
Clear-Host