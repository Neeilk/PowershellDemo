
 # A Simple Module
 function Get-Info
{
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]    
        [string]$Computername 
        )

    $Computername = $Global:Computername
    Get-wmiObject -Computername $Computername -Class Win32_BIOS
}

Export-ModuleMember -Function Get-Info