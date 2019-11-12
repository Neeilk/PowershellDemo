[CmdletBinding()]
param ( )

end
{
    $modulePath      = Join-Path -Path $env:ProgramFiles -ChildPath WindowsPowerShell\Modules
    $targetDirectory = Join-Path -Path $modulePath -ChildPath PowershellDemo
    $scriptRoot      = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
    $sourceDirectory = Join-Path -Path $scriptRoot -ChildPath Module

    if ($PSVersionTable.PSVersion.Major -ge 5)
    {
        $manifestFile    = Join-Path -Path $sourceDirectory -ChildPath PowershellDemo.psd1
        $manifest        = Test-ModuleManifest -Path $manifestFile -WarningAction Ignore -ErrorAction Stop
        $targetDirectory = Join-Path -Path $targetDirectory -ChildPath $manifest.Version.ToString()
    }

    Update-Directory -Source $sourceDirectory -Destination $targetDirectory

    $binPath = Join-Path -Path $targetDirectory -ChildPath bin
    Install-ChocolateyPath $binPath

    if ($PSVersionTable.PSVersion.Major -lt 4)
    {
        $modulePaths = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') -split ';'
        if ($modulePaths -notcontains $modulePath)
        {
            Write-Verbose -Message "Adding '$modulePath' to PSModulePath."

            $modulePaths = @(
                $modulePath
                $modulePaths
            )

            $newModulePath = $modulePaths -join ';'

            [Environment]::SetEnvironmentVariable('PSModulePath', $newModulePath, 'Machine')
            $env:PSModulePath += ";$modulePath"
        }
    }

    if ([Environment]::UserInteractive) {
        # setup shortcuts
        $devopsFolder = "$($ENV:Public)\desktop\DevOps Modules"
        $devopsIcon = "$($targetDirectory)\icons\folder.ico"
        if (!(Test-Path $devopsFolder)) {
            "Creating DevOps tools folder..." | Out-Host
            New-Item -Path $devopsFolder -ItemType Directory | Out-Null
            Set-FolderIcon -Icon $devopsIcon -Path $devopsFolder
        }
        $desktopFolder = "$($devopsFolder)\PowershellDemo"
        $icon = "$($targetDirectory)\icons\devops.ico"
        if (!(Test-Path $desktopFolder)) {
            "Creating desktop folder for shortcuts..." | Out-Host
            New-Item -Path $desktopFolder -ItemType Directory | Out-Null
            Set-FolderIcon -Icon $icon -Path $desktopFolder
        }
        $psPath = "$($ENV:SystemRoot)\system32\WindowsPowerShell\v1.0\powershell.exe"
        $prodLink = "$($desktopFolder)\PROD.lnk"
        $prodTarget = "$($targetDirectory)\wrappers\prod.ps1"
        $prodIcon = "$($targetDirectory)\icons\prod.ico"
        if (!(Test-Path $prodLink)) {
            "Creating PROD shortcut..." | Out-Host
            $t = New-Shortcut -Path $prodLink -TargetPath $psPath -admin -Icon $prodIcon `
                -Description "Launches EdbInterface with link to PROD EDB." `
                -Arguments "-NoExit -File `"$($prodTarget)`"" -Verbose
        }
        $stgLink = "$($desktopFolder)\STG.lnk"
        $stgTarget = "$($targetDirectory)\wrappers\stg.ps1"
        $stgIcon = "$($targetDirectory)\icons\stg.ico"
        if (!(Test-Path $stgLink)) {
            "Creating STG shortcut..." | Out-Host
            $t = New-Shortcut -Path $stgLink -TargetPath $psPath -admin -Icon $stgIcon `
                -Description "Launches EdbInterface with link to STG EDB." `
                -Arguments "-NoExit -File `"$($stgTarget)`"" -Verbose
        }
        $devLink = "$($desktopFolder)\DEV.lnk"
        $devTarget = "$($targetDirectory)\wrappers\dev.ps1"
        $devIcon = "$($targetDirectory)\icons\DEV.ico"
        if (!(Test-Path $devLink)) {
            "Creating DEV shortcut..." | Out-Host
            $t = New-Shortcut -Path $devLink -TargetPath $psPath -admin -Icon $devIcon `
                -Description "Launches EdbInterface with link to DEV EDB." `
                -Arguments "-NoExit -File `"$($devTarget)`"" -Verbose
        }
    }
}

begin
{
    function Update-Directory
    {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string] $Source,

            [Parameter(Mandatory = $true)]
            [string] $Destination
        )

        $Source = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Source)
        $Destination = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Destination)

        if (-not (Test-Path -LiteralPath $Destination))
        {
            $null = New-Item -Path $Destination -ItemType Directory -ErrorAction Stop
        }

        try
        {
            $sourceItem = Get-Item -LiteralPath $Source -ErrorAction Stop
            $destItem = Get-Item -LiteralPath $Destination -ErrorAction Stop

            if ($sourceItem -isnot [System.IO.DirectoryInfo] -or $destItem -isnot [System.IO.DirectoryInfo])
            {
                throw 'Not Directory Info'
            }
        }
        catch
        {
            throw 'Both Source and Destination must be directory paths.'
        }

        $sourceFiles = Get-ChildItem -Path $Source -Recurse |
                       Where-Object -FilterScript { -not $_.PSIsContainer }

        foreach ($sourceFile in $sourceFiles)
        {
            $relativePath = Get-RelativePath $sourceFile.FullName -RelativeTo $Source
            $targetPath = Join-Path -Path $Destination -ChildPath $relativePath

            $sourceHash = Get-FileHash -Path $sourceFile.FullName
            $destHash = Get-FileHash -Path $targetPath

            if ($sourceHash -ne $destHash)
            {
                $targetParent = Split-Path -Path $targetPath -Parent

                if (-not (Test-Path -Path $targetParent -PathType Container))
                {
                    $null = New-Item -Path $targetParent -ItemType Directory -ErrorAction Stop
                }

                Write-Verbose -Message "Updating file $relativePath to new version."
                Copy-Item -Path $sourceFile.FullName -Destination $targetPath -Force -ErrorAction Stop
            }
        }

        $targetFiles = Get-ChildItem -Path $Destination -Recurse |
                       Where-Object -FilterScript { -not $_.PSIsContainer }

        foreach ($targetFile in $targetFiles)
        {
            $relativePath = Get-RelativePath $targetFile.FullName -RelativeTo $Destination
            $sourcePath = Join-Path -Path $Source -ChildPath $relativePath

            if (-not (Test-Path $sourcePath -PathType Leaf))
            {
                Write-Verbose -Message "Removing unknown file $relativePath from module folder."
                Remove-Item -LiteralPath $targetFile.FullName -Force -ErrorAction Stop
            }
        }

    }

    function Get-RelativePath
    {
        param ( [string] $Path, [string] $RelativeTo )
        return $Path -replace "^$([regex]::Escape($RelativeTo))\\?"
    }

    function Get-FileHash
    {
        param ([string] $Path)

        if (-not (Test-Path -LiteralPath $Path -PathType Leaf))
        {
            return $null
        }

        $item = Get-Item -LiteralPath $Path
        if ($item -isnot [System.IO.FileSystemInfo])
        {
            return $null
        }

        $stream = $null

        try
        {
            $sha = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider
            $stream = $item.OpenRead()
            $bytes = $sha.ComputeHash($stream)
            return [convert]::ToBase64String($bytes)
        }
        finally
        {
            if ($null -ne $stream) { $stream.Close() }
            if ($null -ne $sha)    { $sha.Clear() }
        }
    }

    function New-Shortcut {
        <#   
        .SYNOPSIS   
            This script is used to create a  shortcut.         
        .DESCRIPTION   
            This script uses a Com Object to create a shortcut. 
        .PARAMETER Path 
            The path to the shortcut file.  .lnk will be appended if not specified.  If the folder name doesn't exist, it will be created. 
        .PARAMETER TargetPath 
            Full path of the target executable or file. 
        .PARAMETER Arguments 
            Arguments for the executable or file. 
        .PARAMETER Description 
            Description of the shortcut. 
        .PARAMETER HotKey 
            Hotkey combination for the shortcut.  Valid values are SHIFT+F7, ALT+CTRL+9, etc.  An invalid entry will cause the  
            function to fail. 
        .PARAMETER WorkDir 
            Working directory of the application.  An invalid directory can be specified, but invoking the application from the  
            shortcut could fail. 
        .PARAMETER WindowStyle 
            Windows style of the application, Normal (1), Maximized (3), or Minimized (7).  Invalid entries will result in Normal 
            behavior. 
        .PARAMETER Icon 
            Full path of the icon file.  Executables, DLLs, etc with multiple icons need the number of the icon to be specified,  
            otherwise the first icon will be used, i.e.:  c:\windows\system32\shell32.dll,99 
        .PARAMETER admin 
            Used to create a shortcut that prompts for admin credentials when invoked, equivalent to specifying runas. 
        .NOTES   
            Author        : Rhys Edwards 
            Email        : powershell@nolimit.to   
        .INPUTS 
            Strings and Integer 
        .OUTPUTS 
            True or False, and a shortcut 
        .LINK   
            Script posted over:  N/A   
        .EXAMPLE   
            New-Shortcut -Path c:\temp\notepad.lnk -TargetPath c:\windows\notepad.exe     
            Creates a simple shortcut to Notepad at c:\temp\notepad.lnk 
        .EXAMPLE 
            New-Shortcut "$($env:Public)\Desktop\Notepad" c:\windows\notepad.exe -WindowStyle 3 -admin 
            Creates a shortcut named Notepad.lnk on the Public desktop to notepad.exe that launches maximized after prompting for  
            admin credentials. 
        .EXAMPLE 
            New-Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe -icon "c:\windows\system32\shell32.dll,99" 
            Creates a shortcut named Notepad.lnk on the user's desktop to notepad.exe that has a pointy finger icon (on Windows 7). 
        .EXAMPLE 
            New-Shortcut "$($env:USERPROFILE)\Desktop\Notepad.lnk" c:\windows\notepad.exe C:\instructions.txt 
            Creates a shortcut named Notepad.lnk on the user's desktop to notepad.exe that opens C:\instructions.txt  
        .EXAMPLE 
            New-Shortcut "$($env:USERPROFILE)\Desktop\ADUC" %SystemRoot%\system32\dsa.msc -admin  
            Creates a shortcut named ADUC.lnk on the user's desktop to Active Directory Users and Computers that launches after  
            prompting for admin credentials 
        #> 
        
        [CmdletBinding()] 
        param( 
            [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=0)]  
            [Alias("File","Shortcut")]  
            [string]$Path, 
        
            [Parameter(Mandatory=$True,  ValueFromPipelineByPropertyName=$True,Position=1)]  
            [Alias("Target")]  
            [string]$TargetPath, 
        
            [Parameter(ValueFromPipelineByPropertyName=$True,Position=2)]  
            [Alias("Args","Argument")]  
            [string]$Arguments, 
        
            [Parameter(ValueFromPipelineByPropertyName=$True,Position=3)]   
            [Alias("Desc")] 
            [string]$Description, 
        
            [Parameter(ValueFromPipelineByPropertyName=$True,Position=4)]   
            [string]$HotKey, 
        
            [Parameter(ValueFromPipelineByPropertyName=$True,Position=5)]   
            [Alias("WorkingDirectory","WorkingDir")] 
            [string]$WorkDir, 
        
            [Parameter(ValueFromPipelineByPropertyName=$True,Position=6)]   
            [int]$WindowStyle, 
        
            [Parameter(ValueFromPipelineByPropertyName=$True,Position=7)]   
            [string]$Icon, 
        
            [Parameter(ValueFromPipelineByPropertyName=$True)]   
            [switch]$admin 
        ) 
        
        
        Process { 
        
        If (!($Path -match "^.*(\.lnk)$")) { 
            $Path = "$Path`.lnk" 
        } 
        [System.IO.FileInfo]$Path = $Path 
        Try { 
            If (!(Test-Path $Path.DirectoryName)) { 
            md $Path.DirectoryName -ErrorAction Stop | Out-Null 
            } 
        } Catch { 
            Write-Verbose "Unable to create $($Path.DirectoryName), shortcut cannot be created" 
            Return $false 
            Break 
        } 
        
        
        # Define Shortcut Properties 
        $WshShell = New-Object -ComObject WScript.Shell 
        $Shortcut = $WshShell.CreateShortcut($Path.FullName) 
        $Shortcut.TargetPath = $TargetPath 
        $Shortcut.Arguments = $Arguments 
        $Shortcut.Description = $Description 
        $Shortcut.HotKey = $HotKey 
        $Shortcut.WorkingDirectory = $WorkDir 
        $Shortcut.WindowStyle = $WindowStyle 
        If ($Icon){ 
            $Shortcut.IconLocation = $Icon 
        } 
        
        Try { 
            # Create Shortcut 
            $Shortcut.Save() 
            # Set Shortcut to Run Elevated 
            If ($admin) {      
            $TempFileName = [IO.Path]::GetRandomFileName() 
            $TempFile = [IO.FileInfo][IO.Path]::Combine($Path.Directory, $TempFileName) 
            $Writer = New-Object System.IO.FileStream $TempFile, ([System.IO.FileMode]::Create) 
            $Reader = $Path.OpenRead() 
            While ($Reader.Position -lt $Reader.Length) { 
                $Byte = $Reader.ReadByte() 
                If ($Reader.Position -eq 22) {$Byte = 34} 
                $Writer.WriteByte($Byte) 
            } 
            $Reader.Close() 
            $Writer.Close() 
            $Path.Delete() 
            Rename-Item -Path $TempFile -NewName $Path.Name | Out-Null 
            } 
            Return $True 
        } Catch { 
            Write-Verbose "Unable to create $($Path.FullName)" 
            Write-Verbose $Error[0].Exception.Message 
            Return $False 
        } 
        
        } 
    }

    function Set-FolderIcon 
    { 
        <# 
        .SYNOPSIS 
        This function sets a folder icon on specified folder. 
        .DESCRIPTION 
        This function sets a folder icon on specified folder. Needs the path to the icon file to be used and the path to the folder the icon is to be applied to. This function will create two files in the destination path, both set as Hidden files. DESKTOP.INI and FOLDER.ICO 
        .EXAMPLE 
        Set-FolderIcon -Icon "C:\Users\Mark\Downloads\Radvisual-Holographic-Folder.ico" -Path "C:\Users\Mark" 
        Changes the default folder icon to the custom one I donwloaded from Google Images. 
        .EXAMPLE 
        Set-FolderIcon -Icon "C:\Users\Mark\Downloads\wii_folder.ico" -Path "\\FAMILY\Media\Wii" 
        Changes the default folder icon to custom one for a UNC Path. 
        .EXAMPLE 
        Set-FolderIcon -Icon "C:\Users\Mark\Downloads\Radvisual-Holographic-Folder.ico" -Path "C:\Test" -Recurse 
        Changes the default folder icon to custom one for all folders in specified folder and that folder itself. 
        .NOTES 
        Created by Mark Ince on May 4th, 2014. Contact me at mrince@outlook.com if you have any questions. 
        #> 
        [CmdletBinding()] 
        param 
        (     
            [Parameter(Mandatory=$True, 
            Position=0)] 
            [string[]]$Icon, 
            [Parameter(Mandatory=$True, 
            Position=1)] 
            [string]$Path, 
            [Parameter(Mandatory=$False)] 
            [switch] 
            $Recurse     
        ) 
        BEGIN 
        { 
            $originallocale = $PWD 
            #Creating content of the DESKTOP.INI file. 
            $ini = '[.ShellClassInfo] 
                    IconFile=folder.ico 
                    IconIndex=0 
                    ConfirmFileOp=0' 
            Set-Location $Path 
            Set-Location ..     
            Get-ChildItem | Where-Object {$_.FullName -eq "$Path"} | ForEach {$_.Attributes = 'Directory, System'} 
        }     
        PROCESS 
        { 
            $ini | Out-File $Path\DESKTOP.INI 
            If ($Recurse -eq $True) 
            { 
                Copy-Item -Path $Icon -Destination $Path\FOLDER.ICO     
                $recursepath = Get-ChildItem $Path -r | Where-Object {$_.Attributes -match "Directory"} 
                ForEach ($folder in $recursepath) 
                { 
                    Set-FolderIcon -Icon $Icon -Path $folder.FullName 
                } 
            
            } 
            else 
            { 
                Copy-Item -Path $Icon -Destination $Path\FOLDER.ICO 
            }     
        }     
        END 
        { 
            $inifile = Get-Item $Path\DESKTOP.INI 
            $inifile.Attributes = 'Hidden' 
            $icofile = Get-Item $Path\FOLDER.ICO 
            $icofile.Attributes = 'Hidden' 
            Set-Location $originallocale         
        } 
    }
    function Remove-SetIcon 
    { 
        [CmdletBinding()] 
        param 
        (     
            [Parameter(Mandatory=$True, 
            Position=0)] 
            [string]$Path 
        ) 
        BEGIN 
        { 
            $originallocale = $PWD 
            $iconfiles = Get-ChildItem $Path -Recurse -Force | Where-Object {$_.Name -like "FOLDER.ICO"} 
            $iconfiles = $iconfiles.FullName 
            $inifiles = Get-ChildItem $Path -Recurse -Force | where-Object {$_.Name -like "DESKTOP.INI"} 
            $inifiles = $inifiles.FullName 
        } 
        PROCESS 
        { 
            Remove-Item $iconfiles -Force 
            Remove-Item $inifiles -Force 
            Set-Location $Path 
            Set-Location .. 
            Get-ChildItem | Where-Object {$_.FullName -eq "$Path"} | ForEach {$_.Attributes = 'Directory'}     
        } 
        END 
        { 
            Set-Location $originallocale 
        } 
    }
}
