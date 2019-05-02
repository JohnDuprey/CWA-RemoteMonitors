<#
    .SYNOPSIS
	Collects ephemeral port and listening port statistics for each local IP address and outputs the data to a text file log. This script is designed to be used with ConnectWise Automate remote monitors
	.Parameter OutputFilePath
	This must be a file path to write to. This will append to an existing text file. If omitted, .\EphemeralPortStats.log is used.
    .Notes
    Name: EphemeralPorts.ps1
    Author: John Duprey (john.duprey@complete.network), original script by Clint Huffman (clinth@microsoft.com)
    LastEdit: May 2nd, 2019
#>
param([string]$OutputFilePath=(Join-Path $env:windir '\ltsvc\EphemeralPortStats.log'))

#// Argument processing
$global:OutputFilePath = $OutputFilePath

Function Get-TcpDynamicPortRange
{
	$oOutput = Invoke-Expression -Command 'netsh int ipv4 show dynamicportrange tcp'

	$oDynamicPortRange = New-Object pscustomobject
	Add-Member -InputObject $oDynamicPortRange -MemberType NoteProperty -Name StartPort -Value 0
    Add-Member -InputObject $oDynamicPortRange -MemberType NoteProperty -Name EndPort -Value 0
	Add-Member -InputObject $oDynamicPortRange -MemberType NoteProperty -Name NumberOfPorts -Value 0
	
	ForEach ($sLine in $oOutput)
	{
		If ($($sLine.IndexOf('Start Port')) -ge 0)
		{
			$aLine = $sLine.Split(':')
			[System.Int32] $oDynamicPortRange.StartPort = $aLine[1]
		}
		
		If ($($sLine.IndexOf('Number of Ports')) -ge 0)
		{
			$aLine = $sLine.Split(':')
			[System.Int32] $oDynamicPortRange.NumberOfPorts = $aLine[1]
		}
	}
	$oDynamicPortRange.EndPort = ($($oDynamicPortRange.StartPort) + $($oDynamicPortRange.NumberOfPorts)) - 1
	$oDynamicPortRange
}

Function Get-ActiveTcpConnections
{
	$oOutput = Invoke-Expression -Command 'netstat -ano -p tcp'
	
	If ($oOutput -ne $null)
	{
	    $u = $oOutput.GetUpperBound(0)
	    $oOutput = $oOutput[4..$u]
		$aActiveConnections = @()
		ForEach ($sLine in $oOutput)
		{
			$iPropertyIndex = 0
			$aLine = $sLine.Split(' ')
			$oActiveConnection = New-Object System.Object
			For ($c = 0; $c -lt $aLine.Count;$c++)
			{
				If ($aLine[$c] -ne '')
				{
					switch ($iPropertyIndex)
					{
						0 {Add-Member -InputObject $oActiveConnection -MemberType NoteProperty -Name Proto -Value $($aLine[$c])}
						1 {
							$aIpPort = $aLine[$c].Split(':')
							Add-Member -InputObject $oActiveConnection -MemberType NoteProperty -Name LocalAddress -Value $($aIpPort[0])
							Add-Member -InputObject $oActiveConnection -MemberType NoteProperty -Name LocalPort -Value $([System.Int32] $aIpPort[1])
						  }
						2 {
							$aIpPort = $aLine[$c].Split(':')
							Add-Member -InputObject $oActiveConnection -MemberType NoteProperty -Name ForeignAddress -Value $($aIpPort[0])
							Add-Member -InputObject $oActiveConnection -MemberType NoteProperty -Name ForeignPort -Value $([System.Int32] $aIpPort[1])
						  }
						3 {Add-Member -InputObject $oActiveConnection -MemberType NoteProperty -Name State -Value $($aLine[$c])}
						4 {Add-Member -InputObject $oActiveConnection -MemberType NoteProperty -Name PID -Value $([System.Int32] $aLine[$c])}
					}
					$iPropertyIndex++
				}
			}
			$aActiveConnections += $oActiveConnection
		}
		$aActiveConnections
	}
}

$global:htDynamicPortRange = @{}

Function Get-EphemeralPortStats
{
	
	$aLocalAddressStats = @()
	$Computer = $env:computername
		If ($($global:htDynamicPortRange.ContainsKey($Computer)) -eq $false)
		{
			$oDynamicPortRange = Get-TcpDynamicPortRange -Computer $Computer
			[System.Int32] $iDynamicStartPort = $oDynamicPortRange.StartPort
			[System.Int32] $iDynamicEndPort = $oDynamicPortRange.EndPort
			[System.Int32] $iDynamicNumberOfPorts = $oDynamicPortRange.NumberOfPorts
			[Void] $global:htDynamicPortRange.Add($Computer,$oDynamicPortRange)
		}
		Else
		{
			$oDynamicPortRange = $global:htDynamicPortRange[$Computer]
			[System.Int32] $iDynamicStartPort = $oDynamicPortRange.StartPort
			[System.Int32] $iDynamicEndPort = $oDynamicPortRange.EndPort
			[System.Int32] $iDynamicNumberOfPorts = $oDynamicPortRange.NumberOfPorts		
		}


		$oActiveConnections = Get-ActiveTcpConnections -Computer $Computer | Sort-Object LocalPort -Descending
		$aUniqueLocalAddresses = $oActiveConnections | Sort-Object -Property LocalAddress | Select LocalAddress | Get-Unique -AsString
		$aDynamicPortRangeConnections = $oActiveConnections | Where-Object -FilterScript {($_.LocalPort -ge $iDynamicStartPort) -and ($_.LocalPort -le $iDynamicEndPort)}

		ForEach ($oUniqueLocalAddress in $aUniqueLocalAddresses)
		{
			If ($($oUniqueLocalAddress.LocalAddress) -ne '0.0.0.0')
			{
				#// Ephemeral ports of each LocalAddress
				[string] $sUniqueLocalAddress = $oUniqueLocalAddress.LocalAddress
				$aIpEphemeralPortConnections = @($aDynamicPortRangeConnections | Where-Object -FilterScript {($_.LocalAddress -eq $sUniqueLocalAddress)} | Select LocalPort, PID | Sort-Object | Get-Unique -AsString)
				If ($aIpEphemeralPortConnections -ne $null)
				{	
					$oStats = New-Object System.Object
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Computer' -Value $Computer
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'DateTime' -Value $(Get-Date)
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'LocalAddress' -Value $sUniqueLocalAddress
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'InUse' -Value $([System.Int32] $aIpEphemeralPortConnections.Count)
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Max' -Value $([System.Int32] $oDynamicPortRange.NumberOfPorts)
					$iPercentage = ($([System.Int32] $aIpEphemeralPortConnections.Count) / $([System.Int32] $oDynamicPortRange.NumberOfPorts)) * 100
					$iPercentage = [Math]::Round($iPercentage,1)
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Percent' -Value $iPercentage
				}
				Else
				{
					$oStats = New-Object System.Object
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Computer' -Value $Computer
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'DateTime' -Value $(Get-Date)
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'LocalAddress' -Value $sUniqueLocalAddress
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'InUse' -Value 0
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Max' -Value $([System.Int32] $oDynamicPortRange.NumberOfPorts)
					$iPercentage = 0
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Percent' -Value $iPercentage		
				}
				#// Listening ports of each LocalAddress
				$aIpListeningPorts = $oActiveConnections | Where-Object -FilterScript {($_.State -eq 'LISTENING') -and (($_.LocalAddress -eq $sUniqueLocalAddress) -or ($_.LocalAddress -eq '0.0.0.0'))} | Select LocalPort | Sort-Object LocalPort | Get-Unique -AsString

				If ($aIpListeningPorts -ne $null)
				{	
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Listening' -Value $([System.Int32] $aIpListeningPorts.Count)
				}
				Else
				{
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'Listening' -Value 0
				}
				
				#// Number of PIDs
				$aIpPids = $oActiveConnections | Where-Object -FilterScript {($_.LocalAddress -eq $sUniqueLocalAddress) -or ($_.LocalAddress -eq '0.0.0.0')} | Select PID | Sort-Object PID
                $aUniquePids = $aIpPids | Get-Unique -AsString
				If ($aUniquePids -ne $null)
				{	
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'NumOfPids' -Value $([System.Int32] $aUniquePids.Count)
				}
				Else
				{
					Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'NumOfPids' -Value 0
				}

                $aPidStats = @()
                ForEach ($iPid in $aUniquePids)
                {
                    $iPidCount = @($aIpPids | Where-Object -FilterScript {$_.PID -eq $iPid.PID}).Count
                    $oPidStats = New-Object System.Object
					Add-Member -InputObject $oPidStats -MemberType NoteProperty -Name 'PID' -Value $iPid.PID
                    Add-Member -InputObject $oPidStats -MemberType NoteProperty -Name 'Count' -Value $iPidCount
                    $aPidStats += $oPidStats
                }
                Add-Member -InputObject $oStats -MemberType NoteProperty -Name 'PidStats' -Value $aPidStats
                $aLocalAddressStats += $oStats
			}
		}
	$aLocalAddressStats
}

$oPortStats = Get-EphemeralPortStats
#$oPortStats | Select-Object Computer, DateTime, LocalAddress, InUse, Max, Percent, Listening | Format-Table -AutoSize
$iCount = @($oPortStats | Where-Object {$_.Percent -ge 10}).Count
If ($iCount -gt 0)
{
	$oPortStats | Select Computer, DateTime, LocalAddress, InUse, Max, Percent, Listening | Format-Table -AutoSize >> $OutputFilePath
    ForEach ($oItem in $oPortStats)
    {
		Write-Output "WARNING: TCP ephemeral port usage has exceeded 10% on $($oItem.LocalAddress), review the log file in $OutputFilePath."
        $oItem.LocalAddress >> $OutputFilePath
		$oItem.PidStats | Sort-Object Count -Descending | ft -AutoSize >> $OutputFilePath
		
        ForEach ($oPid in $oItem.PidStats)
        {
            If ($oPid.Count -ge 1000)
            {
                Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Handle = $($oPid.PID)" | Select-Object Name, ProcessId, HandleCount, Path | Format-List >> $OutputFilePath
                Get-WmiObject -Query "ASSOCIATORS OF {Win32_Process.Handle=$($oPid.PID)} WHERE ResultClass = CIM_DataFile" | Select-Object Caption, LastModified, Manufacturer, Version | Format-List >> $OutputFilePath
            }
        }
    }
}
else {
	Write-Output "SUCCESS: TCP ephemeral port usage below 10% on all interfaces"
}