
 # A Simple Module
 function Get-Info
{
    param($Computername)
    Get-wmiObject -Computername $Computername -Class Win32_BIOS
}

Get-Info -Computername localhost