
 # A Simple Module
 function Get-Info
{
    [CmdletBinding()]
    param(
        [Parameter(Position = 1)]    
        [string]$Computername 
        )

    if(($Computername -eq $null) -or ($Computername -eq ""))
    {
        $Computername = $Global:Computername
    }
    
    Get-wmiObject -Computername $Computername -Class Win32_BIOS
}

Export-ModuleMember -Function Get-Info