
 # A Simple Module
 function Get-Info
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]    
        [string]$Computername = $Global:Computername
        )
    Get-wmiObject -Computername $Computername -Class Win32_BIOS
}

Export-ModuleMember -Function Get-Info