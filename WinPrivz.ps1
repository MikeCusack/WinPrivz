Write-Host @"

 █████   ███   █████  ███             ███████████             ███                        
░░███   ░███  ░░███  ░░░             ░░███░░░░░███           ░░░                         
 ░███   ░███   ░███  ████  ████████   ░███    ░███ ████████  ████  █████ █████  █████████
 ░███   ░███   ░███ ░░███ ░░███░░███  ░██████████ ░░███░░███░░███ ░░███ ░░███  ░█░░░░███ 
 ░░███  █████  ███   ░███  ░███ ░███  ░███░░░░░░   ░███ ░░░  ░███  ░███  ░███  ░   ███░  
  ░░░█████░█████░    ░███  ░███ ░███  ░███         ░███      ░███  ░░███ ███     ███░   █
    ░░███ ░░███      █████ ████ █████ █████        █████     █████  ░░█████     █████████
     ░░░   ░░░      ░░░░░ ░░░░ ░░░░░ ░░░░░        ░░░░░     ░░░░░    ░░░░░     ░░░░░░░░░ 
     

By: Mike Cusack (@m1xus)

"@


function Check-Accesschk {
 
    $Path = $env:Path
    
    $CurrentDir = (Get-Location).Path
    $files = (gci -Path $CurrentDir ).Name

    if ($files -like "*accesschk.exe*" -or $files -like "*Accesschk.exe*") {
        Write-Host -ForegroundColor Yellow "Found Accesschk in the current directory!`n"
        Get-ServiceInfo

    } else {
    
        Write-Host -ForegroundColor RED "[ERROR]    Can't find Accesschk in the current directory!`n"
        Exit

    }

}


function Get-ServiceInfo {
    $garbage = @()
    Write-Host -ForegroundColor Yellow "Gathering Service information...`n"
    $serviceDict = @{}
    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname -and $_.pathname -notlike "C:\Windows\System32*"} | foreach-object {
        $key = $_.name
        $path = $_.pathname
        $path = $path -replace('"',"")
        
        if ($path -like "*.exe*") {
            $path = $path.toLower()
            $path = $path.Substring(0, $path.IndexOf(".exe") + 4)
            


            if (-not $path.StartsWith('c:\')) {
                
                $start = 'C:\WINDOWS\'
                
                $path = '"' + $start + $path + '"'
                $serviceDict += @{$key=@()}
                $serviceDict.$key += $path
                $serviceDict.$key += $_.startmode
                $serviceDict.$key += $_.startname
                $serviceDict.$key += $_.state
            
            } else {
            $path = '"' + $path + '"'
            $serviceDict += @{$key=@()}
            $serviceDict.$key += $path
            $serviceDict.$key += $_.startmode
            $serviceDict.$key += $_.startname
            $serviceDict.$key += $_.state
            }
            
        }  else {
        
            $garbage.Add($path)
        
        }
    }
    
    Get-ModifiableService -ArgumentList $serviceDict  
    Get-UnquotedServicePaths -ArgumentList $serviceDict
    Get-WeakRegistryPermissions -ArgumentList $serviceDict
    Get-InsecureServiceBinaries -ArgumentList $serviceDict
    Get-DLLHijacking
    Get-AutoRunsPermissions
    Get-AlwaysInstallElevated
    Get-AutoLogonCredentials
}


function Get-ModifiableService {

    [CmdletBinding()]
    Param(
        [Alias('serviceDict')]
        [string[]]
        $ArgumentList
    )

    Write-Host -ForegroundColor Yellow "Checking for Modifiable Services...`n"

    $everyone = @{}
    $users = @{}
    $authUsers = @{}
    $interactiveUsers = @{}
    $domainUsers = @{}

    $garbage = @{}

    foreach ($key in $serviceDict.GetEnumerator()) {

        $path = $key.value[0]
        $startMode = $key.value[1]
        $startName = $key.value[2]
        $state = $key.value[3]
           
        $evry1 = .\accesschk.exe /accepteula -quvc "Everyone" $key.Name -nobanner -w


        if ($evry1 -like "Access is denied.") {
        
            $garbage = @{Name=$evry1}

        } elseif ($evry1 -notlike "No matching objects found.") {
            
            $keyy = $key.Name
            $everyone += @{$keyy=@()}
            $val = $evry1.Trim("RW ")
            $everyone.$keyy += $val      
        } 
          
    } 
    if ($everyone.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Everyone group can't modify any services!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Everyone group can modify the following services: "
        
        foreach ($key in $serviceDict.GetEnumerator()) {
            
            foreach ($keyz in $everyone.GetEnumerator()) {
            
                $sName = $keyz.Name
                $val = $keyz.value
                $sAccess = $val[1..($val.length -1)]
            
                if ($key.Name -eq $sName) {
                    
                    $sAccess = $sAccess -replace("`t","")
                                   
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $key.name
                    $Out | Add-Member Noteproperty 'Path' $key.value[0]
                    $Out | Add-Member Noteproperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permission' $sAccess 
                    $Out
                    
                }                        
            } 
        }
    } 
    
    foreach ($key in $serviceDict.GetEnumerator()) {

        $path = $key.value[0]
        $startMode = $key.value[1]
        $startName = $key.value[2]
        $state = $key.value[3]
           
        $authy = .\accesschk.exe /accepteula -quvc "Authenticated Users" $key.Name -nobanner -w


        if ($authy -like "Access is denied.") {
        
            $garbage = @{Name=$authy}

        } elseif ($authy -notlike "No matching objects found.") {
            
            $keyy = $key.Name
            $authUsers += @{$keyy=@()}
            $val = $authy.Trim("RW ")
            $authUsers.$keyy += $val      
        } 
          
    } 
    if ($authUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Authenticated Users group can't modify any services!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Authenticated Users group can modify the following services: "
        
        foreach ($key in $serviceDict.GetEnumerator()) {
            
            foreach ($keyz in $authUsers.GetEnumerator()) {
            
                $sName = $keyz.Name
                $val = $keyz.value
                $sAccess = $val[1..($val.length -1)]
            
                if ($key.Name -eq $sName) {
                    
                    $sAccess = $sAccess -replace("`t","")
                                   
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $key.name
                    $Out | Add-Member Noteproperty 'Path' $key.value[0]
                    $Out | Add-Member Noteproperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permission' $sAccess 
                    $Out
                    
                }                        
            } 
        }
    } 
    
    $domainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined -eq "True") {

        foreach ($key in $serviceDict.GetEnumerator()) {

            $path = $key.value[0]
            $startMode = $key.value[1]
            $startName = $key.value[2]
            $state = $key.value[3]
           
            $domUsers = .\accesschk.exe /accepteula -quvc "Domain Users" $key.Name -nobanner -w


            if ($domUsers -like "Access is denied.") {
        
                $garbage = @{Name=$domUsers}

            } elseif ($domUsers -notlike "No matching objects found.") {
            
                $keyy = $key.Name
                $domainUsers += @{$keyy=@()}
                $val = $domUsers.Trim("RW ")
                $domainUsers.$keyy += $val      
            } 
          
        } 
        if ($domainUsers.Count -eq 0) {
        
            Write-Host -ForegroundColor Red "[X]    Domains Users group can't modify any services!`n"
    
        } else {
        
            Write-Host -ForegroundColor Green "[!]    Domain Users group can modify the following services: "
        
            foreach ($key in $serviceDict.GetEnumerator()) {
            
                foreach ($keyz in $domainUsers.GetEnumerator()) {
            
                    $sName = $keyz.Name
                    $val = $keyz.value
                    $sAccess = $val[1..($val.length -1)]
            
                    if ($key.Name -eq $sName) {
                    
                        $sAccess = $sAccess -replace("`t","")
                                   
                        $Out = New-Object PSObject 
                        $Out | Add-Member Noteproperty 'ServiceName' $key.name
                        $Out | Add-Member Noteproperty 'Path' $key.value[0]
                        $Out | Add-Member Noteproperty 'StartName' $key.value[2]
                        $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                        $Out | Add-Member NoteProperty 'State' $key.value[3]
                        $Out | Add-Member NoteProperty 'Permission' $sAccess 
                        $Out
                    
                    }                        
                } 
            }
        }
    }

    foreach ($key in $serviceDict.GetEnumerator()) {

        $path = $key.value[0]
        $startMode = $key.value[1]
        $startName = $key.value[2]
        $state = $key.value[3]
           
        $inty = .\accesschk.exe /accepteula -quvc "NT AUTHORITY\INTERACTIVE" $key.Name -nobanner -w


        if ($inty -like "Access is denied.") {
        
            $garbage = @{Name=$inty}

        } elseif ($inty -notlike "No matching objects found.") {
            
            $keyy = $key.Name
            $interactiveUsers += @{$keyy=@()}
            $val = $inty.Trim("RW ")
            $interactiveUsers.$keyy += $val      
        } 
          
    } 
    if ($interactiveUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    NT AUTHORITY\INTERACTIVE group can't modify any services!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    NT AUTHORITY\INTERACTIVE group can modify the following services: "
        
        foreach ($key in $serviceDict.GetEnumerator()) {
            
            foreach ($keyz in $interactiveUsers.GetEnumerator()) {
            
                $sName = $keyz.Name
                $val = $keyz.value
                $sAccess = $val[1..($val.length -1)]
            
                if ($key.Name -eq $sName) {
                    
                    $sAccess = $sAccess -replace("`t","")
                                   
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $key.name
                    $Out | Add-Member Noteproperty 'Path' $key.value[0]
                    $Out | Add-Member Noteproperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permission' $sAccess 
                    $Out
                    
                }                        
            } 
        }
    } 
    
    foreach ($key in $serviceDict.GetEnumerator()) {

        $path = $key.value[0]
        $startMode = $key.value[1]
        $startName = $key.value[2]
        $state = $key.value[3]
           
        $uzers = .\accesschk.exe /accepteula -quvc "BUILTIN\Users" $key.Name -nobanner -w


        if ($uzers -like "Access is denied.") {
        
            $garbage = @{Name=$uzers}

        } elseif ($uzers -notlike "No matching objects found.") {
            
            $keyy = $key.Name
            $users += @{$keyy=@()}
            $val = $uzers.Trim("RW ")
            $users.$keyy += $val      
        } 
          
    } 
    if ($users.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    BUILTIN\Users group can't modify any services!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    BUILTIN\Users group can modify the following services: "
        
        foreach ($key in $serviceDict.GetEnumerator()) {
            
            foreach ($keyz in $users.GetEnumerator()) {
            
                $sName = $keyz.Name
                $val = $keyz.value
                $sAccess = $val[1..($val.length -1)]
            
                if ($key.Name -eq $sName) {
                    
                    $sAccess = $sAccess -replace("`t","")
                                   
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $key.name
                    $Out | Add-Member Noteproperty 'Path' $key.value[0]
                    $Out | Add-Member Noteproperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permission' $sAccess 
                    $Out
                    
                }                        
            } 
        }
    }   
}     


function Get-UnquotedServicePaths {

    [CmdletBinding()]
    Param(
        [Alias('serviceDict')]
        [string[]]
        $ArgumentList
    )
    
    Write-Host -ForegroundColor Yellow "`nChecking for Unquoted Service Paths...`n"
    $unquoted = @()
    $unquoted += cmd.exe /c 'wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """' | select -Skip 1
    
    if ($unquoted.Count -eq 0) {
         
         write-host -ForegroundColor Red "[X]    No unquoted service paths."
    
    } else {

        write-host -ForegroundColor Green "[!]    Unquoted service paths were found!`n"
        for($i; $i -lt $unquoted.Length; $i++) {
    
            $val = $unquoted[$i]
            $val = [string]$val

            if (-not [string]::IsNullOrEmpty($val)) {
        
                $val = $val -replace '\s+', ' '
                $exe = $val.IndexOf(".exe")
                if ($exe -ne "-1") {
               
                    $firstSpace = $val.IndexOf(" ")
                    $serv = $val.Substring(0,$firstSpace)
                    $val = $val.Trim($serv)
                    $val = $val.TrimStart(" ")
                    $end = $val.IndexOf(".exe ")
                    $path = $val.Substring(0,$end + 4)
                    $startmode = $end + 5
                    $mode = $val.Substring($startmode)
                
                    
                    foreach ($key in $serviceDict.GetEnumerator()) {
                    
                        if ($serv -eq $key.Name) {
                        
                            $Out = New-Object PSObject 
                            $Out | Add-Member Noteproperty 'ServiceName' $key.name
                            $Out | Add-Member Noteproperty 'Path' $path
                            $Out | Add-Member Noteproperty 'StartName' $key.value[2]
                            $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                            $Out | Add-Member NoteProperty 'State' $key.value[3]
                            $Out
                        }  

                    }
        
                }
    
            }

        }
    
    }
}


function Get-WeakRegistryPermissions {

    [CmdletBinding()]
        Param(
            [Alias('serviceDict')]
            [string[]]
            $ArgumentList
    )
    
    Write-Host -ForegroundColor Yellow "`nChecking for Weak Registry Permissions...`n"
    $oldE = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    $regDict = @{}
    $regServices = reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\
    foreach ($regServ in $regServices) {
        $regName = $regServ.split("\")[4] 
        #$regDict += @{$regServ=@()}
        $regPath = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$regName" -Name ImagePath
        if ($regPath -notlike "*system32*" -and $regPath -like "*.exe*" -and $regPath -like "*\*") {
            $regPath = $regpath -replace('"',"")
            $regpath = $regPath.ToLower()
            $regPath = $regPath.Substring(0, $regPath.IndexOf(".exe") + 4)
            $regPath = '"' + $regPath + '"'
            $regDict += @{$regName=@()}
            $regDict.$regName += $regPath
            $regDict.$regName += "HKLM:\SYSTEM\CurrentControlSet\Services\$regName"
           }
    }

    $everyone = @{}
    $users = @{}
    $authUsers = @{}
    $interactiveUsers = @{}
    domainUsers = @{}
    
    foreach ($key in $regDict.GetEnumerator()) {
        $servName = $key.Name 
        $regPerms = .\accesschk.exe /accepteula Everyone -uvwqkd HKLM\SYSTEM\CurrentControlSet\Services\$servName -nobanner
        
    
        if ($regPerms -notlike "No matching objects found.") {
                               
            $regPerms = $regPerms.TrimStart("RW ")
            $regPerms = $regPerms[1..($regPerms.length -1)]
            $regPerms = $regPerms -replace("`t", "")
            $everyone += @{$servName=@()}
            $everyone.$servName += $key.value[0]
            $everyone.$servName += $key.value[1]
            $everyone.$servName += $regPerms
        }
    }

    if ($everyone.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Everyone group can't modify registry ImagePaths!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Everyone group can modify the following registry ImagePaths: "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $everyone.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    $perms = $keyz.Value[2..($keyz.Value[2].length -1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'ImagePath' $key.value[0]
                    $Out | Add-Member Noteproperty 'RegistryPath' $keyz.value[1]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    }
    
    foreach ($key in $regDict.GetEnumerator()) {
        $servName = $key.Name 
        $regPerms = .\accesschk.exe /accepteula "Authenticated Users" -uvwqkd HKLM\SYSTEM\CurrentControlSet\Services\$servName -nobanner
        
    
        if ($regPerms -notlike "No matching objects found.") {
                               
            $regPerms = $regPerms.TrimStart("RW ")
            $regPerms = $regPerms[1..($regPerms.length -1)]
            $regPerms = $regPerms -replace("`t", "")
            $authUsers += @{$servName=@()}
            $authUsers.$servName += $key.value[0]
            $authUsers.$servName += $key.value[1]
            $authUsers.$servName += $regPerms
        }
    }

    if ($authUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Authenticated Users group can't modify registry ImagePaths!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Authenticated Users group can modify the following registry ImagePaths: "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $authUsers.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    $perms = $keyz.Value[2..($keyz.Value[2].length -1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'ImagePath' $key.value[0]
                    $Out | Add-Member Noteproperty 'RegistryPath' $keyz.value[1]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    }

    $domainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined -eq "True") {

        foreach ($key in $regDict.GetEnumerator()) {
            $servName = $key.Name 
            $regPerms = .\accesschk.exe /accepteula "Domain Users" -uvwqkd HKLM\SYSTEM\CurrentControlSet\Services\$servName -nobanner
        
    
            if ($regPerms -notlike "No matching objects found.") {
                               
                $regPerms = $regPerms.TrimStart("RW ")
                $regPerms = $regPerms[1..($regPerms.length - 1)]
                $regPerms = $regPerms -replace("`t", "")
                $domainUsers += @{$servName=@()}
                $domainUsers.$servName += $key.value[0]
                $domainUsers.$servName += $key.value[1]
                $domainUsers.$servName += $regPerms
            }
        }
    

        if ($domainUsers.Count -eq 0) {
        
            Write-Host -ForegroundColor Red "[X]    Domain Users can't modify registry ImagePaths!`n"
    
        } else {
        
            Write-Host -ForegroundColor Green "[!]    Domain Users can modify the following registry ImagePaths:`n "
            foreach ($key in $serviceDict.GetEnumerator()) {
                $servName = $key.Name 
                foreach ($keyz in $domainUsers.GetEnumerator()) {
                
                    if ($keyz.Name -eq $servName) {
                    
                        $perms = $keyz.Value[2..($keyz.Value[2].length - 1)]
                        $Out = New-Object PSObject 
                        $Out | Add-Member Noteproperty 'ServiceName' $servName
                        $Out | Add-Member Noteproperty 'ImagePath' $key.value[0]
                        $Out | Add-Member Noteproperty 'RegistryPath' $keyz.value[1]
                        $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                        $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                        $Out | Add-Member NoteProperty 'State' $key.value[3]
                        $Out | Add-Member NoteProperty 'Permissions' $perms
                        $Out
                    }

                }
            }

        }
    }

    foreach ($key in $regDict.GetEnumerator()) {
        $servName = $key.Name 
        $regPerms = .\accesschk.exe /accepteula "NT AUTHORITY\INTERACTIVE" -uvwqkd HKLM\SYSTEM\CurrentControlSet\Services\$servName -nobanner
        
    
        if ($regPerms -notlike "No matching objects found.") {
                               
            $regPerms = $regPerms.TrimStart("RW ")
            $regPerms = $regPerms[1..($regPerms.length -1)]
            $regPerms = $regPerms -replace("`t", "")
            $interactiveUsers += @{$servName=@()}
            $interactiveUsers.$servName += $key.value[0]
            $interactiveUsers.$servName += $key.value[1]
            $interactiveUsers.$servName += $regPerms
        }
    }

    if ($interactiveUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    NT AUTHORITY\INTERACTIVE group can't modify registry ImagePaths!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    NT AUTHORITY\INTERACTIVE group can modify the following registry ImagePaths: "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $interactiveUsers.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    $perms = $keyz.Value[2..($keyz.Value[2].length -1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'ImagePath' $key.value[0]
                    $Out | Add-Member Noteproperty 'RegistryPath' $keyz.value[1]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    }

    foreach ($key in $regDict.GetEnumerator()) {
        $servName = $key.Name 
        $regPerms = .\accesschk.exe /accepteula Users -uvwqkd HKLM\SYSTEM\CurrentControlSet\Services\$servName -nobanner
        
    
        if ($regPerms -notlike "No matching objects found.") {
                               
            $regPerms = $regPerms.TrimStart("RW ")
            $regPerms = $regPerms[1..($regPerms.length -1)]
            $regPerms = $regPerms -replace("`t", "")
            $users += @{$servName=@()}
            $users.$servName += $key.value[0]
            $users.$servName += $key.value[1]
            $users.$servName += $regPerms
        }
    }

    if ($users.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    BUILTIN\Users group can't modify registry ImagePaths!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    BUILTIN\Users group can modify the following registry ImagePaths: "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $users.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    $perms = $keyz.Value[2..($keyz.Value[2].length -1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'ImagePath' $key.value[0]
                    $Out | Add-Member Noteproperty 'RegistryPath' $keyz.value[1]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    }
}


function Get-InsecureServiceBinaries {
   
   [CmdletBinding()]
    Param(
        [Alias('serviceDict')]
        [string[]]
        $ArgumentList
    )
    
    Write-Host -ForegroundColor Yellow "`nChecking for Insecure Service Binary Permissions...`n"

    $serviceBinaries = @{}
    
    foreach ($service in $serviceDict.GetEnumerator()) {
        
        $serviceName = $service.Name
        $serviceBinaries += @{$serviceName=@()}

        $binaryPath = $service.value[0]
 
      
        $serviceBinaries.$serviceName += $binaryPath


    }
               
    $everyone = @{}
    $users = @{}
    $authUsers = @{}
    $interactiveUsers = @{}
    $domainUsers = @{}
    
    foreach ($binary in $serviceBinaries.GetEnumerator()) {
        $serviceName = $binary.Name
        $binaryPath = $binary.value[0]
        $binaryPerms = .\accesschk.exe /accepteula -quvw "Everyone" $binaryPath -nobanner
        
        if ($binaryPerms -notlike "No matching objects found.") {
                               
            $binaryPerms = $binaryPerms.TrimStart("RW ")
            $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
            $binaryPerms = $binaryPerms -replace("`t", "")
            $everyone += @{$serviceName=@()}
            $everyone.$serviceName += $binaryPath
            $everyone.$serviceName += $binaryPerms
        } 
    }
    
    if ($everyone.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Everyone group can't modify service binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Everyone group can modify the following service binaries:`n "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $everyone.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    
                    $perms = $keyz.Value[1..($keyz.Value[1].length - 1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'BinaryPath' $keyz.value[0]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    }
    
    foreach ($binary in $serviceBinaries.GetEnumerator()) {
        $serviceName = $binary.Name
        $binaryPath = $binary.value[0]
        $binaryPerms = .\accesschk.exe /accepteula -quvw "Authenticated Users" $binaryPath -nobanner
        
        if ($binaryPerms -notlike "No matching objects found.") {
                               
            $binaryPerms = $binaryPerms.TrimStart("RW ")
            $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
            $binaryPerms = $binaryPerms -replace("`t", "")
            $authUsers += @{$serviceName=@()}
            $authUsers.$serviceName += $binaryPath
            $authUsers.$serviceName += $binaryPerms
        } 
    }
    
    if ($authUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Authenticated Users group can't modify service binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Authenticated Users can modify the following service binaries:`n "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $authUsers.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    
                    $perms = $keyz.Value[1..($keyz.Value[1].length - 1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'BinaryPath' $keyz.value[0]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    }

    $domainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined -eq "True") {

        foreach ($binary in $serviceBinaries.GetEnumerator()) {
            $serviceName = $binary.Name
            $binaryPath = $binary.value[0]
            $binaryPerms = .\accesschk.exe /accepteula -quvw "Domain Users" $binaryPath -nobanner
        
            if ($binaryPerms -notlike "No matching objects found.") {
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $domainUsers += @{$serviceName=@()}
                $domainUsers.$serviceName += $binaryPath
                $domainUsers.$serviceName += $binaryPerms
            } 
        }
    
        if ($domainUsers.Count -eq 0) {
        
            Write-Host -ForegroundColor Red "[X]    Domain Users can't modify service binaries!`n"
    
        } else {
        
            Write-Host -ForegroundColor Green "[!]    Domain Users can modify the following service binaries:`n "
            foreach ($key in $serviceDict.GetEnumerator()) {
                $servName = $key.Name 
                foreach ($keyz in $domainUsers.GetEnumerator()) {
                
                    if ($keyz.Name -eq $servName) {
                    
                        $perms = $keyz.Value[1..($keyz.Value[1].length - 1)]
                        $Out = New-Object PSObject 
                        $Out | Add-Member Noteproperty 'ServiceName' $servName
                        $Out | Add-Member Noteproperty 'BinaryPath' $keyz.value[0]
                        $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                        $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                        $Out | Add-Member NoteProperty 'State' $key.value[3]
                        $Out | Add-Member NoteProperty 'Permissions' $perms
                        $Out
                    }

                }
            }

        }
    }

    foreach ($binary in $serviceBinaries.GetEnumerator()) {
        $serviceName = $binary.Name
        $binaryPath = $binary.value[0]
        $binaryPerms = .\accesschk.exe /accepteula -quvw "NT AUTHORITY\INTERACTIVE" $binaryPath -nobanner
        
        if ($binaryPerms -notlike "No matching objects found.") {
                               
            $binaryPerms = $binaryPerms.TrimStart("RW ")
            $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
            $binaryPerms = $binaryPerms -replace("`t", "")
            $interactiveUsers += @{$serviceName=@()}
            $interactiveUsers.$serviceName += $binaryPath
            $interactiveUsers.$serviceName += $binaryPerms
        } 
    }
    
    if ($interactiveUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    NT AUTHORITY\INTERACTIVE group can't modify service binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    NT AUTHORITY\INTERACTIVE group can modify the following service binaries:`n "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $interactiveUsers.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    
                    $perms = $keyz.Value[1..($keyz.Value[1].length - 1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'BinaryPath' $keyz.value[0]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    }

    foreach ($binary in $serviceBinaries.GetEnumerator()) {
        $serviceName = $binary.Name
        $binaryPath = $binary.value[0]
        $binaryPerms = .\accesschk.exe /accepteula -quvw "BUILTIN\Users" $binaryPath -nobanner
        
        if ($binaryPerms -notlike "No matching objects found.") {
                               
            $binaryPerms = $binaryPerms.TrimStart("RW ")
            $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
            $binaryPerms = $binaryPerms -replace("`t", "")
            $users += @{$serviceName=@()}
            $users.$serviceName += $binaryPath
            $users.$serviceName += $binaryPerms
        } 
    }
    
    if ($users.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    BUILTIN\Users group can't modify service binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    BUILTIN\Users group can modify the following service binaries:`n "
        foreach ($key in $serviceDict.GetEnumerator()) {
            $servName = $key.Name 
            foreach ($keyz in $users.GetEnumerator()) {
                
                if ($keyz.Name -eq $servName) {
                    
                    $perms = $keyz.Value[1..($keyz.Value[1].length - 1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'ServiceName' $servName
                    $Out | Add-Member Noteproperty 'BinaryPath' $keyz.value[0]
                    $Out | Add-Member NoteProperty 'StartName' $key.value[2]
                    $Out | Add-Member NoteProperty 'StartMode' $key.value[1]
                    $Out | Add-Member NoteProperty 'State' $key.value[3]
                    $Out | Add-Member NoteProperty 'Permissions' $perms
                    $Out
                }

            }
        }

    } 
}


function Get-DLLHijacking {
    
    Write-Host -ForegroundColor Yellow "`nChecking for Potentail DLL Hijack Locations in PATH...`n"
    $FormatEnumerationLimit = 16
    $pathz = $env:PATH -split(";")
    $pathList = @()
    foreach ($entry in $pathz) {
        
        if ($entry -notlike "*C:\WINDOWS\System32*" -and -not [string]::IsNullOrEmpty($entry)) {
          
            $pathList += $entry  

        }
    }

    $pathList = $pathList| Sort-Object -Unique

    $everyone = @{}
    $users = @{}
    $authUsers = @{}
    $interactiveUsers = @{}
    $domainUsers = @{}
    $garbage = @{}

    foreach ($path in $pathList) {

       $ev = .\accesschk.exe /accepteula -nobanner -uvwd "Everyone" "$path" 

       if ($ev -like "Access is denied.") {
        
            $garbage = @{Name=$ev}

        } elseif ($ev -notlike "No matching objects found.") {
                               
            $perms = $ev.TrimStart("RW ")
            $perms = $perms[1..($perms.length -1)]
            $perms = $perms -replace("`t", "")
            $everyone.Add($path, $perms)

        } 
    }
        
    
    if ($everyone.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    No possible DLL Hijack locations found in PATH for Everyone group!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]     DLL Hijack locations found in PATH for Everyone group!`n "

        foreach ($location in $everyone.GetEnumerator()) {
            
            $addQuotes = $location.Name
            
            if (-not $addQuotes.StartsWith('"')) {
            
                $addQuotes = '"' + $addQuotes + '"'
                $finalPath = $addQuotes                            
                $finalPerms = $location.Value[0..($location.Value[0].length - 1)]

                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'Path' $finalPath
                $Out | Add-Member Noteproperty 'Permissions' $finalPerms
                $Out | FL 
              
            }
        }
    }
    
    foreach ($path in $pathList) {

       $auth = .\accesschk.exe /accepteula -nobanner -uvwd "Authenticated Users" "$path" 

       if ($auth -like "Access is denied.") {
        
            $garbage = @{Name=$auth}

        } elseif ($auth -notlike "No matching objects found.") {
                               
            $perms = $auth.TrimStart("RW ")
            $perms = $perms[1..($perms.length -1)]
            $perms = $perms -replace("`t", "")
            $authUsers.Add($path, $perms)

        } 
    }
        
    
    if ($authUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    No possible DLL Hijack locations found in PATH for Authenticated Users group!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]     DLL Hijack locations found in PATH for Authenticated Users group!`n "

        foreach ($location in $authUsers.GetEnumerator()) {
            
            $addQuotes = $location.Name
            
            if (-not $addQuotes.StartsWith('"')) {
            
                $addQuotes = '"' + $addQuotes + '"'
                $finalPath = $addQuotes                            
                $finalPerms = $location.Value[0..($location.Value[0].length - 1)]

                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'Path' $finalPath
                $Out | Add-Member Noteproperty 'Permissions' $finalPerms
                $Out | FL 
              
            }
        }
    }

    $domainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined -eq "True") {

        foreach ($path in $pathList) {

           $dom = .\accesschk.exe /accepteula -nobanner -uvwd "Domain Users" "$path" 

           if ($dom -like "Access is denied.") {
        
                $garbage = @{Name=$dom}

            } elseif ($dom -notlike "No matching objects found.") {
                               
                $perms = $dom.TrimStart("RW ")
                $perms = $perms[1..($perms.length -1)]
                $perms = $perms -replace("`t", "")
                $domainUsers.Add($path, $perms)

            } 
        }
          
        if ($domainUsers.Count -eq 0) {
        
            Write-Host -ForegroundColor Red "[X]    No possible DLL Hijack locations found in PATH for Domain Users group!`n"
    
        } else {
        
            Write-Host -ForegroundColor Green "[!]     DLL Hijack locations found in PATH for Domain Users group!`n "

            foreach ($location in $domainUsers.GetEnumerator()) {
            
                $addQuotes = $location.Name
            
                if (-not $addQuotes.StartsWith('"')) {
            
                    $addQuotes = '"' + $addQuotes + '"'
                    $finalPath = $addQuotes                            
                    $finalPerms = $location.Value[0..($location.Value[0].length - 1)]

                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'Path' $finalPath
                    $Out | Add-Member Noteproperty 'Permissions' $finalPerms
                    $Out | FL 
              
                }
            }
        }
    }

    foreach ($path in $pathList) {

       $i = .\accesschk.exe /accepteula -nobanner -uvwd "NT AUTHORITY\INTERACTIVE" "$path" 

       if ($i -like "Access is denied.") {
        
            $garbage = @{Name=$i}

        } elseif ($i -notlike "No matching objects found.") {
                               
            $perms = $i.TrimStart("RW ")
            $perms = $perms[1..($perms.length -1)]
            $perms = $perms -replace("`t", "")
            $interactiveUsers.Add($path, $perms)

        } 
    }
        
    
    if ($interactiveUsers.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    No possible DLL Hijack locations found in PATH for NT AUTHORITY\INTERACTIVE group!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]     DLL Hijack locations found in PATH for NT AUTHORITY\INTERACTIVE group!`n "

        foreach ($location in $interactiveUsers.GetEnumerator()) {
            
            $addQuotes = $location.Name
            
            if (-not $addQuotes.StartsWith('"')) {
            
                $addQuotes = '"' + $addQuotes + '"'
                $finalPath = $addQuotes                            
                $finalPerms = $location.Value[0..($location.Value[0].length - 1)]

                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'Path' $finalPath
                $Out | Add-Member Noteproperty 'Permissions' $finalPerms
                $Out | FL 
              
            }
        }
    }

    foreach ($path in $pathList) {

       $uz = .\accesschk.exe /accepteula -nobanner -uvwd "BUILTIN\Users" "$path" 

       if ($uz -like "Access is denied.") {
        
            $garbage = @{Name=$uz}

        } elseif ($uz -notlike "No matching objects found.") {
                               
            $perms = $uz.TrimStart("RW ")
            $perms = $perms[1..($perms.length -1)]
            $perms = $perms -replace("`t", "")
            $users.Add($path, $perms)

        } 
    }
          
    if ($users.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    No possible DLL Hijack locations found in PATH for BUILTIN\Users group!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]     DLL Hijack locations found in PATH for BUILTIN\Users group!`n "

        foreach ($location in $users.GetEnumerator()) {
            
            $addQuotes = $location.Name
            
            if (-not $addQuotes.StartsWith('"')) {
            
                $addQuotes = '"' + $addQuotes + '"'
                $finalPath = $addQuotes                            
                $finalPerms = $location.Value[0..($location.Value[0].length - 1)]

                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'Path' $finalPath
                $Out | Add-Member Noteproperty 'Permissions' $finalPerms
                $Out | FL 
              
            }
        }
    }
}


function Get-AutoRunsPermissions {

    Write-Host -ForegroundColor Yellow "`nChecking for Insecure Registry AutoRun Hive Permissions...`n"
    #$ErrorActionPreference = 'SilentlyContinue'
    $garbage = @{}
    $regDict = @{}
    $hiveAccess = @{}
    $binaryAccess = @{}
    $regLocations = @("HKLM\Software\Microsoft\Windows\CurrentVersion\Run","HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run","HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce","HKLM\Software\Microsoft\Windows NT\CurrentVersion\TerminalServer\Install\Software\Microsoft\Windows\CurrentVersion\Run","HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce","HKLM\Software\Microsoft\Windows NT\CurrentVersion\TerminalServer\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx","HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices","HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices","HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx","HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")
    $regLocations2 = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\TerminalServer\Install\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\TerminalServer\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices","HKEY_LOCAL_MACHINE:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx","HKEY_LOCAL_MACHINE:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")
    
    foreach ($regg in $regLocations2) {

        $regAutoRun = (Get-Item -Path $regg).Name
        $count = (Get-Item -Path $regg).ValueCount
        
        if ($count -gt 0) {
        
           for ($i = 0; $i -lt $count; $i++) {

                $regPropName = (Get-Item -Path $regg).Property[$i]
                $regPropPath = (Get-ItemProperty -Path $regg).$regPropName
                
                $regDict += @{$regPropName=@()}
                $regDict.$regPropName += $regAutoRun
                $regDict.$regPropName += $regPropPath

                $autos = .\accesschk.exe /accepteula -uvwqkd "Everyone" "$regAutoRun" -nobanner
        
                if ($autos -like "Access is denied.") {
        
                    $garbage = @{Name=$autos}

                } elseif ($autos -notlike "No matching objects found.") {
             
                    $path = $autos.TrimStart("RW ")
                    $path = $path -replace("HKLM","HKEY_LOCAL_MACHINE")
                    $path = $path[0]                
                    $perms = $autos.TrimStart("RW ")
                    $perms = $perms[1..($perms.length -1)]
                    $perms = $perms -replace("`t", "") 

                   if ($regAutoRun -eq $path) {

                        $hiveAccess += @{$regPropName=@()}
                        $hiveAccess.$regPropName += $regPropPath
                        $hiveAccess.$regPropName += $regAutoRun  
                        $hiveAccess.$regPropName += $perms
                   }
               }
           }
        }
    }

    if ($hiveAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Everyone group can't modify registry AutoRun hives!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Everyone group can modify the following registry AutoRun hives:`n "
        foreach ($keyz in $hiveAccess.GetEnumerator()) {
            $ImageName = $keyz.Name 
                               
            $perms = $keyz.Value[2..($keyz.Value[2].length - 1)]
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'AutoRun' $ImageName
            $Out | Add-Member Noteproperty 'AutoRun Location' $keyz.value[1]
            $Out | Add-Member NoteProperty 'ImagePath' $keyz.value[0]
            $Out | Add-Member NoteProperty 'Permissions' $keyz.value[2]
            $Out | FL               
        }
    }
    $hiveAccess = @{}
    foreach ($regg in $regLocations2) {

        $regAutoRun = (Get-Item -Path $regg).Name
        $count = (Get-Item -Path $regg).ValueCount
        
        if ($count -gt 0) {
        
           for ($i = 0; $i -lt $count; $i++) {

                $regPropName = (Get-Item -Path $regg).Property[$i]
                $regPropPath = (Get-ItemProperty -Path $regg).$regPropName

                $autos = .\accesschk.exe /accepteula -uvwqkd "Authenticated Users" "$regAutoRun" -nobanner
        
                if ($autos -like "Access is denied.") {
        
                    $garbage = @{Name=$autos}

                } elseif ($autos -notlike "No matching objects found.") {
             
                    $path = $autos.TrimStart("RW ")
                    $path = $path -replace("HKLM","HKEY_LOCAL_MACHINE")
                    $path = $path[0]                
                    $perms = $autos.TrimStart("RW ")
                    $perms = $perms[1..($perms.length -1)]
                    $perms = $perms -replace("`t", "") 

                   if ($regAutoRun -eq $path) {

                        $hiveAccess += @{$regPropName=@()}
                        $hiveAccess.$regPropName += $regPropPath
                        $hiveAccess.$regPropName += $regAutoRun  
                        $hiveAccess.$regPropName += $perms
                   }
               }
           }
        }
    }
    if ($hiveAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Authenticated Users group can't modify registry AutoRun hives!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Authenticated Users group can modify the following registry AutoRun hives:`n "
        foreach ($keyz in $hiveAccess.GetEnumerator()) {
            $ImageName = $keyz.Name 
                               
            $perms = $keyz.Value[2..($keyz.Value[2].length - 1)]
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'AutoRun' $ImageName
            $Out | Add-Member Noteproperty 'AutoRun Location' $keyz.value[1]
            $Out | Add-Member NoteProperty 'ImagePath' $keyz.value[0]
            $Out | Add-Member NoteProperty 'Permissions' $keyz.value[2]
            $Out | FL               
        }
    }
    
    $domainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined -eq "True") {
        $hiveAccess = @{}
        foreach ($regg in $regLocations2) {

            $regAutoRun = (Get-Item -Path $regg).Name
            $count = (Get-Item -Path $regg).ValueCount
        
            if ($count -gt 0) {
        
               for ($i = 0; $i -lt $count; $i++) {

                    $regPropName = (Get-Item -Path $regg).Property[$i]
                    $regPropPath = (Get-ItemProperty -Path $regg).$regPropName

                    $autos = .\accesschk.exe /accepteula -uvwqkd "Domain Users" "$regAutoRun" -nobanner
        
                    if ($autos -like "Access is denied.") {
        
                        $garbage = @{Name=$autos}

                    } elseif ($autos -notlike "No matching objects found.") {
             
                        $path = $autos.TrimStart("RW ")
                        $path = $path -replace("HKLM","HKEY_LOCAL_MACHINE")
                        $path = $path[0]                
                        $perms = $autos.TrimStart("RW ")
                        $perms = $perms[1..($perms.length -1)]
                        $perms = $perms -replace("`t", "") 

                       if ($regAutoRun -eq $path) {

                            $hiveAccess += @{$regPropName=@()}
                            $hiveAccess.$regPropName += $regPropPath
                            $hiveAccess.$regPropName += $regAutoRun  
                            $hiveAccess.$regPropName += $perms
                       }
                   }
               }
            }
        }
        if ($hiveAccess.Count -eq 0) {
        
            Write-Host -ForegroundColor Red "[X]    Domain Users group can't modify registry AutoRun hives!`n"
    
        } else {
        
            Write-Host -ForegroundColor Green "[!]    Domain Users group can modify the following registry AutoRun hives:`n "
            foreach ($keyz in $hiveAccess.GetEnumerator()) {
                $ImageName = $keyz.Name 
                               
                $perms = $keyz.Value[2..($keyz.Value[2].length - 1)]
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'AutoRun' $ImageName
                $Out | Add-Member Noteproperty 'AutoRun Location' $keyz.value[1]
                $Out | Add-Member NoteProperty 'ImagePath' $keyz.value[0]
                $Out | Add-Member NoteProperty 'Permissions' $keyz.value[2]
                $Out | FL               
            }
        }
    }

    $hiveAccess = @{}
    foreach ($regg in $regLocations2) {

        $regAutoRun = (Get-Item -Path $regg).Name
        $count = (Get-Item -Path $regg).ValueCount
        
        if ($count -gt 0) {
        
           for ($i = 0; $i -lt $count; $i++) {

                $regPropName = (Get-Item -Path $regg).Property[$i]
                $regPropPath = (Get-ItemProperty -Path $regg).$regPropName

                $autos = .\accesschk.exe /accepteula -uvwqkd "NT AUTHORITY\INTERACTIVE" "$regAutoRun" -nobanner
        
                if ($autos -like "Access is denied.") {
        
                    $garbage = @{Name=$autos}

                } elseif ($autos -notlike "No matching objects found.") {
             
                    $path = $autos.TrimStart("RW ")
                    $path = $path -replace("HKLM","HKEY_LOCAL_MACHINE")
                    $path = $path[0]                
                    $perms = $autos.TrimStart("RW ")
                    $perms = $perms[1..($perms.length -1)]
                    $perms = $perms -replace("`t", "") 

                   if ($regAutoRun -eq $path) {

                        $hiveAccess += @{$regPropName=@()}
                        $hiveAccess.$regPropName += $regPropPath
                        $hiveAccess.$regPropName += $regAutoRun  
                        $hiveAccess.$regPropName += $perms
                   }
               }
           }
        }
    }
    if ($hiveAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    NT AUTHORITY\INTERACTIVE group can't modify registry AutoRuns hives!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    NT AUTHORITY\INTERACTIVE group can modify the following registry AutoRun hives:`n "
        foreach ($keyz in $hiveAccess.GetEnumerator()) {
            $ImageName = $keyz.Name 
                               
            $perms = $keyz.Value[2..($keyz.Value[2].length - 1)]
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'AutoRun' $ImageName
            $Out | Add-Member Noteproperty 'AutoRun Location' $keyz.value[1]
            $Out | Add-Member NoteProperty 'ImagePath' $keyz.value[0]
            $Out | Add-Member NoteProperty 'Permissions' $keyz.value[2]
            $Out | FL               
        }
    }
    $hiveAccess = @{}
    foreach ($regg in $regLocations2) {

        $regAutoRun = (Get-Item -Path $regg).Name
        $count = (Get-Item -Path $regg).ValueCount
        
        if ($count -gt 0) {
        
           for ($i = 0; $i -lt $count; $i++) {

                $regPropName = (Get-Item -Path $regg).Property[$i]
                $regPropPath = (Get-ItemProperty -Path $regg).$regPropName

                $autos = .\accesschk.exe /accepteula -uvwqkd "BUILTIN\Users" "$regAutoRun" -nobanner
        
                if ($autos -like "Access is denied.") {
        
                    $garbage = @{Name=$autos}

                } elseif ($autos -notlike "No matching objects found.") {
             
                    $path = $autos.TrimStart("RW ")
                    $path = $path -replace("HKLM","HKEY_LOCAL_MACHINE")
                    $path = $path[0]                
                    $perms = $autos.TrimStart("RW ")
                    $perms = $perms[1..($perms.length -1)]
                    $perms = $perms -replace("`t", "") 

                   if ($regAutoRun -eq $path) {

                        $hiveAccess += @{$regPropName=@()}
                        $hiveAccess.$regPropName += $regPropPath
                        $hiveAccess.$regPropName += $regAutoRun  
                        $hiveAccess.$regPropName += $perms
                   }
               }
           }
        }
    }
    if ($hiveAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    BUILTIN\Users group can't modify registry AutoRun hives!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    BUILTIN\Users group can modify the following registry AutoRun hives:`n "
        foreach ($keyz in $hiveAccess.GetEnumerator()) {
            $ImageName = $keyz.Name 
                               
            $perms = $keyz.Value[2..($keyz.Value[2].length - 1)]
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'AutoRun' $ImageName
            $Out | Add-Member Noteproperty 'AutoRun Location' $keyz.value[1]
            $Out | Add-Member NoteProperty 'ImagePath' $keyz.value[0]
            $Out | Add-Member NoteProperty 'Permissions' $keyz.value[2]
            $Out | FL               
        }
    }
    
    
        
    Write-Host -ForegroundColor Yellow "`nChecking for Insecure Registry AutoRun Binary Permissions...`n"
    $regDict2 = @{}
    foreach ($thing in $regDict.GetEnumerator()) {
        
        $binaryName = $thing.Name
        $binaryPath = $thing.value[1]     
        
        $binaryPath = $binaryPath.Substring(0,$binaryPath.LastIndexOf(".") + 4)

        $count = Select-String -InputObject $binaryPath -Pattern ".exe" -AllMatches

        if ($count.Matches.Count -gt 1) {

            $first = $binaryPath.IndexOf('"')
            $last = $binaryPath.LastIndexOf('"')
            $len = $binaryPath.Length
            $newPath = $binaryPath.Substring($first,$len-$last)
            
            $newPath = $newPath -replace('"',"")
            $newPath = '"' + $newPath + '"'

            $binaryPerms =  .\accesschk.exe /accepteula -quvw "Everyone" $newPath -nobanner


            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $binaryAccess.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 

        } else {

            $binaryPath = $binaryPath -replace('"',"")
            $binaryPath = '"' + $binaryPath + '"'


            $binaryPerms = .\accesschk.exe /accepteula -quvw "Everyone" $binaryPath -nobanner

        
            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $regDict2.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 
        }
    }

    if ($binaryAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Everyone group can't modify AutoRun binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Everyone group can modify the following AutoRun binaries:`n "
 
        foreach ($stuff in $binaryAccess.GetEnumerator()) {
                $ImageName = $stuff.Name
                    
                $perms = $stuff.Value[2..($key.Value[2].length - 1)]
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'AutoRunBinary' $ImageName
                $Out | Add-Member Noteproperty 'BinaryPath' $stuff.value[0]
                $Out | Add-Member NoteProperty 'Permissions' $stuff.value[1]
                $Out | FL
        }
    }
    $binaryAccess = @{}
    foreach ($thing in $regDict.GetEnumerator()) {
        
        $binaryName = $thing.Name
        $binaryPath = $thing.value[1]     
        
        $binaryPath = $binaryPath.Substring(0,$binaryPath.LastIndexOf(".") + 4)

        $count = Select-String -InputObject $binaryPath -Pattern ".exe" -AllMatches

        if ($count.Matches.Count -gt 1) {

            $first = $binaryPath.IndexOf('"')
            $last = $binaryPath.LastIndexOf('"')
            $len = $binaryPath.Length
            $newPath = $binaryPath.Substring($first,$len-$last)
            
            $newPath = $newPath -replace('"',"")
            $newPath = '"' + $newPath + '"'

            $binaryPerms =  .\accesschk.exe /accepteula -quvw "Authenticated Users" $newPath -nobanner


            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $binaryAccess.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 

        } else {

            $binaryPath = $binaryPath -replace('"',"")
            $binaryPath = '"' + $binaryPath + '"'


            $binaryPerms = .\accesschk.exe /accepteula -quvw "Authenticated Users" $binaryPath -nobanner

        
            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $regDict2.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 
        }
    }

    if ($binaryAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    Authenticated Users group can't modify AutoRun binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    Authenticated Users group can modify the following AutoRun binaries:`n "
 
        foreach ($stuff in $binaryAccess.GetEnumerator()) {
                $ImageName = $stuff.Name
                    
                $perms = $stuff.Value[2..($key.Value[2].length - 1)]
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'AutoRunBinary' $ImageName
                $Out | Add-Member Noteproperty 'BinaryPath' $stuff.value[0]
                $Out | Add-Member NoteProperty 'Permissions' $stuff.value[1]
                $Out | FL
        }
    }

    $domainJoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined -eq "True") {

        $binaryAccess = @{}
        foreach ($thing in $regDict.GetEnumerator()) {
        
            $binaryName = $thing.Name
            $binaryPath = $thing.value[1]     
        
            $binaryPath = $binaryPath.Substring(0,$binaryPath.LastIndexOf(".") + 4)

            $count = Select-String -InputObject $binaryPath -Pattern ".exe" -AllMatches

            if ($count.Matches.Count -gt 1) {

                $first = $binaryPath.IndexOf('"')
                $last = $binaryPath.LastIndexOf('"')
                $len = $binaryPath.Length
                $newPath = $binaryPath.Substring($first,$len-$last)
            
                $newPath = $newPath -replace('"',"")
                $newPath = '"' + $newPath + '"'

                $binaryPerms =  .\accesschk.exe /accepteula -quvw "Domain Users" $newPath -nobanner


                if ($binaryPerms -like "Access is denied.") {
        
                    $garbage = @{Name=$binaryPerms}

                } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                    $binaryAccess += @{$binaryName=@()}
                    $binaryAccess.$binaryName += $binaryPath
                               
                    $binaryPerms = $binaryPerms.TrimStart("RW ")
                    $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                    $binaryPerms = $binaryPerms -replace("`t", "")
                    $binaryAccess.$binaryName += $binaryPath
                    $binaryAccess.$binaryName += $binaryPerms
                } 

            } else {

                $binaryPath = $binaryPath -replace('"',"")
                $binaryPath = '"' + $binaryPath + '"'


                $binaryPerms = .\accesschk.exe /accepteula -quvw "Domain Users" $binaryPath -nobanner

        
                if ($binaryPerms -like "Access is denied.") {
        
                    $garbage = @{Name=$binaryPerms}

                } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                    $binaryAccess += @{$binaryName=@()}
                    $regDict2.$binaryName += $binaryPath
                               
                    $binaryPerms = $binaryPerms.TrimStart("RW ")
                    $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                    $binaryPerms = $binaryPerms -replace("`t", "")
                    $binaryAccess.$binaryName += $binaryPath
                    $binaryAccess.$binaryName += $binaryPerms
                } 
            }
        }

        if ($binaryAccess.Count -eq 0) {
        
            Write-Host -ForegroundColor Red "[X]    Domain Users group can't modify AutoRun binaries!`n"
    
        } else {
        
            Write-Host -ForegroundColor Green "[!]    Domain Users group can modify the following AutoRun binaries:`n "
 
            foreach ($stuff in $binaryAccess.GetEnumerator()) {
                    $ImageName = $stuff.Name
                    
                    $perms = $stuff.Value[2..($key.Value[2].length - 1)]
                    $Out = New-Object PSObject 
                    $Out | Add-Member Noteproperty 'AutoRunBinary' $ImageName
                    $Out | Add-Member Noteproperty 'BinaryPath' $stuff.value[0]
                    $Out | Add-Member NoteProperty 'Permissions' $stuff.value[1]
                    $Out | FL
            }
        }
    }

    $binaryAccess = @{}
    foreach ($thing in $regDict.GetEnumerator()) {
        
        $binaryName = $thing.Name
        $binaryPath = $thing.value[1]     
        
        $binaryPath = $binaryPath.Substring(0,$binaryPath.LastIndexOf(".") + 4)

        $count = Select-String -InputObject $binaryPath -Pattern ".exe" -AllMatches

        if ($count.Matches.Count -gt 1) {

            $first = $binaryPath.IndexOf('"')
            $last = $binaryPath.LastIndexOf('"')
            $len = $binaryPath.Length
            $newPath = $binaryPath.Substring($first,$len-$last)
            
            $newPath = $newPath -replace('"',"")
            $newPath = '"' + $newPath + '"'

            $binaryPerms =  .\accesschk.exe /accepteula -quvw "NT AUTHORITY\INTERACTIVE" $newPath -nobanner


            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $binaryAccess.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 

        } else {

            $binaryPath = $binaryPath -replace('"',"")
            $binaryPath = '"' + $binaryPath + '"'


            $binaryPerms = .\accesschk.exe /accepteula -quvw "NT AUTHORITY\INTERACTIVE" $binaryPath -nobanner

        
            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $regDict2.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 
        }
    }

    if ($binaryAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    NT AUTHORITY\INTERACTIVE group can't modify AutoRun binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    NT AUTHORITY\INTERACTIVE group can modify the following AutoRun binaries:`n "
 
        foreach ($stuff in $binaryAccess.GetEnumerator()) {
                $ImageName = $stuff.Name
                    
                $perms = $stuff.Value[2..($key.Value[2].length - 1)]
                $Out = New-Object PSObject 
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'AutoRunBinary' $ImageName
                $Out | Add-Member Noteproperty 'BinaryPath' $stuff.value[0]
                $Out | Add-Member NoteProperty 'Permissions' $stuff.value[1]
                $Out | FL
        }
    }
    $binaryAccess = @{}
    foreach ($thing in $regDict.GetEnumerator()) {
        
        $binaryName = $thing.Name
        $binaryPath = $thing.value[1]     
        
        $binaryPath = $binaryPath.Substring(0,$binaryPath.LastIndexOf(".") + 4)

        $count = Select-String -InputObject $binaryPath -Pattern ".exe" -AllMatches

        if ($count.Matches.Count -gt 1) {

            $first = $binaryPath.IndexOf('"')
            $last = $binaryPath.LastIndexOf('"')
            $len = $binaryPath.Length
            $newPath = $binaryPath.Substring($first,$len-$last)
            
            $newPath = $newPath -replace('"',"")
            $newPath = '"' + $newPath + '"'

            $binaryPerms =  .\accesschk.exe /accepteula -quvw "BUILTIN\Users" $newPath -nobanner


            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $binaryAccess.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 

        } else {

            $binaryPath = $binaryPath -replace('"',"")
            $binaryPath = '"' + $binaryPath + '"'


            $binaryPerms = .\accesschk.exe /accepteula -quvw "BUILTIN\Users" $binaryPath -nobanner

        
            if ($binaryPerms -like "Access is denied.") {
        
                $garbage = @{Name=$binaryPerms}

            } elseif ($binaryPerms -notlike "No matching objects found.") {
            
                $binaryAccess += @{$binaryName=@()}
                $regDict2.$binaryName += $binaryPath
                               
                $binaryPerms = $binaryPerms.TrimStart("RW ")
                $binaryPerms = $binaryPerms[1..($binaryPerms.length -1)]
                $binaryPerms = $binaryPerms -replace("`t", "")
                $binaryAccess.$binaryName += $binaryPath
                $binaryAccess.$binaryName += $binaryPerms
            } 
        }
    }
    $binaryAccess = @{}
    if ($binaryAccess.Count -eq 0) {
        
        Write-Host -ForegroundColor Red "[X]    BUILTIN\Users group can't modify AutoRun binaries!`n"
    
    } else {
        
        Write-Host -ForegroundColor Green "[!]    BUILTIN\Users group can modify the following AutoRun binaries:`n "
 
        foreach ($stuff in $binaryAccess.GetEnumerator()) {
                $ImageName = $stuff.Name
                    
                $perms = $stuff.Value[2..($key.Value[2].length - 1)]
               $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'AutoRunBinary' $ImageName
                $Out | Add-Member Noteproperty 'BinaryPath' $stuff.value[0]
                $Out | Add-Member NoteProperty 'Permissions' $stuff.value[1]
                $Out | FL
        }
    }   
}


function Get-AlwaysInstallElevated {

    Write-Host -ForegroundColor Yellow "Checking for AlwaysInstallElevated Registry Keys...`n"
    $ErrorActionPreference = 'SilentlyContinue'

    $big = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1"
    $small = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallEvelated = 1"

    $lm = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
    $cu = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated

    if ($lm.count -eq 1 -and $cu.count -eq 1 -and $lm -eq 1 -and $cu -eq 1) {
    
        Write-Host -ForegroundColor Green "[!]    Both AlwaysInstallElevated Registry Keys Found and Enabled !`n"
        $big
        $small
    } else {
    
        Write-Host -ForegroundColor Red "[X]    Missing Enabled AlwaysInstallElevated Registry Keys!`n"
    
    }
}


function Get-AutoLogonCredentials {
    
    $ErrorActionPreference = 'SilentlyContinue'

    Write-Host -ForegroundColor Yellow "`nChecking for Registry Passwords and SSH Keys...`n"
    
    $winlogon = @{}
    $winlogonPass = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword

    if ([string]::IsNullOrEmpty($winlogonPass)) {
        
        Write-Host -ForegroundColor Red "[X]    No Auto Logon Credentials Found!`n"
    
    } else {

        Write-Host -ForegroundColor Green "[!]    Windows Auto Logon Credentials Found!`n"

        $winlogonUser = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
        $winlogonDomain = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName

    }

    if (-not [string]::IsNullOrEmpty($winlogonUser) -and -not [string]::IsNullOrEmpty($winlogonDomain)) {
    
        $winlogon += @{$winlogonUser=@()}
        $winlogon.$winlogonUser += $winlogonPass
        $winlogon.$winlogonUser += $winlogonDomain

        foreach ($win in $winlogon.GetEnumerator()) {
        
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'Username' $win.Name
            $Out | Add-Member Noteproperty 'Password' $win.value[0]
            $Out | Add-Member NoteProperty 'Domain' $win.value[1]
            $Out | FL 
        }
    }
    
    $putty = @{}

    $garbage = @()

    $exists = Test-Path -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions"
    
    if ($exists -eq "True") {
    
        $sessionCount = (get-item "HKCU:\Software\SimonTatham\PuTTY\Sessions").SubKeyCount

        if ($sessionCount -ne 0) {
    
            Write-Host -ForegroundColor Green "[!]    Stored PuTTY Sessions Found in the Registry!`n"
        
            $sessionGrab = reg query HKCU\Software\SimonTatham\PuTTY\Sessions

            foreach ($i in $sessionGrab) {

                $i = $i.ToString()
                $i = $i.Split("\")[5]
            
                $hostname = (Get-ItemProperty -Path HKCU:\Software\SimonTatham\PuTTY\Sessions\$i).Hostname
                $port = (Get-ItemProperty -Path HKCU:\Software\SimonTatham\PuTTY\Sessions\$i).PortNumber
                $username = (Get-ItemProperty -Path HKCU:\Software\SimonTatham\PuTTY\Sessions\$i).UserName
                $publicKey = (Get-ItemProperty -Path HKCU:\Software\SimonTatham\PuTTY\Sessions\$i).PublicKeyFile
                $proxyPassword = (Get-ItemProperty -Path HKCU:\Software\SimonTatham\PuTTY\Sessions\$i).ProxyPassword
                $proxyUsername = (Get-ItemProperty -Path HKCU:\Software\SimonTatham\PuTTY\Sessions\$i).ProxyUsername

                $putty += @{$i=@()}
            
                if (-not [string]::IsNullOrEmpty($hostname)) {

                    $putty.$i += $hostname

                }
                if (-not [string]::IsNullOrEmpty($port)) {

                    $putty.$i += $port

                }
                if (-not [string]::IsNullOrEmpty($publicKey)) {

                    $putty.$i += $publicKey

                }
                if (-not [string]::IsNullOrEmpty($username)) {

                    $putty.$i += $username

                }
                if (-not [string]::IsNullOrEmpty($proxyUsername)) {

                    $putty.$i += $proxyUsername

                }
                if (-not [string]::IsNullOrEmpty($proxyPassword)) {

                    $putty.$i += $proxyPassword

                }
                
            }

            foreach ($sess in $putty.GetEnumerator()) {
        
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'SessionHost' $sess.Name
                $Out | Add-Member Noteproperty 'Port' $sess.value[0]
                $Out | Add-Member Noteproperty 'PublicKeyFile' $sess.value[1]
                $Out | Add-Member Noteproperty 'UserName' $sess.value[2]
                $Out | Add-Member Noteproperty 'AltUserName' $sess.value[3]
                $Out | Add-Member NoteProperty 'AltPassword' $sess.value[4]
                $Out | FL 
            }
        }

    $garbage = @()

    } else {
    
        Write-Host -ForegroundColor Red "[X]    No Stored PuTTY Sessions Found in the Registry!`n"
    
    }


    $savedCreds = cmdkey.exe /list | Select-String -Pattern "Domain" -Context 0,1
    $cmdkey = @{}
    
    if ($savedCreds.Length -eq 0 ) {
    
        Write-Host -ForegroundColor Red "[X]    No Domain Passwords Stored in the Credential Manager!`n"
    
    } else {

        Write-Host -ForegroundColor Green "[!]    Domain Passwords Stored in the Credential Manager`n"

        for ($cred=0; $cred -lt $savedCreds.length; $cred++){
        
            $counter1 = $savedCreds[$cred+1]
            $user = $counter1
            $user = $user -replace("`n","|")
            $user = $user -replace("     ","")
            $user = $user -replace(">","")
            $user = $user -replace("Type: Domain Password","")
            $user = $user.Substring(9)
            $cmdkey += @{$user=@()}
        

            $counter2 = $savedCreds[$cred+1]
            $type = $counter2 
            $type = $type -replace("`n","|")
            $type = $type.substring(0,$type.IndexOf("|"))
            $type = $type -replace(">","")
            $type = $type -replace("Type: ","")
            $type = $type -replace("     ","")
            $cmdkey.$user += $type
        
            $domain = $savedCreds[$cred]
            $cred= $cred+1
            $domain = $domain -replace(">","")
            $domain = $domain -replace("     ","")
            $domain = $domain -replace("Target: ","")
            $domain = $domain -replace("target="," ")
            $domain = $domain.Substring(8)
            $cmdkey.$user += $domain
        
        }

        foreach ($save in $cmdkey.GetEnumerator()) {
        
            $Out = New-Object PSObject 
            $Out | Add-Member Noteproperty 'UserName' $save.Name
            $Out | Add-Member Noteproperty 'Type' $save.value[0]
            $Out | Add-Member Noteproperty 'Domain' $save.value[1]
            $Out | FL 
        }
    } 
}   

$FormatEnumerationLimit = 16
$ErrorActionPreference = 'SilentlyContinue'
$user = $env:USERNAME
Check-Accesschk