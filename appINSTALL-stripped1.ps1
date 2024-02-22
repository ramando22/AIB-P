
<#
##AZ -REMOVED FROM TEST
New-Item -ItemType Directory -Force -Path C:\temp

invoke-webrequest -uri 'https://aka.ms/downloadazcopy-v10-windows' -OutFile c:\temp\azcopy.zip
Expand-Archive 'c:\temp\azcopy.zip' c:\temp
copy-item "C:\temp\azcopy_*\azcopy.exe" "C:\temp\"


Write-Output "###################### Obtain token ################################"
 $sasUriFromFile = Get-Content 'c:\temp\sasToken.txt' 

Start-Process 'c:\temp\azcopy.exe' -ArgumentList 'copy', $sasUriFromFile , "C:\temp", "--recursive" -wait


Get-ChildItem -recurse "C:\temp\binaries" -Filter *.zip | 
Foreach-Object {

    echo $_.FullName
    echo $_.Directory
    Expand-Archive $_.FullName $_.Directory

   
}
#>

#Turn off Windows Installer RDS Compatibility.

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\TSMSI" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\TSMSI" -Name "Enable" -PropertyType DWORD -Value 0 -Force


### Install Windows 10 (20H2) AVD Langauge Pack - ENGB ###
Write-Output "#### Install Windows 10 (20H2) AVD Langauge Pack - ENGB ####"

$W10PSScript = Get-ChildItem -recurse "C:\temp\binaries\software\W10_Language_Pack_ENGB"  -Filter "Install_LanguagePack.ps1"
$W10PSScriptName = $W10PSScript.FullName

echo $W10PSScriptName

$p = Start-Process """C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe""" -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""C:\temp\binaries\W10_Language_Pack_ENGB\W10_AVD_ENGB_05112021\Install_LanguagePack.ps1""' -wait -RedirectStandardOutput "C:\Temp\binaries\W10_Language_Pack_ENGB\W10_AVD_ENGB_05112021\stdout.txt"

$stdout = Get-Content "C:\Temp\binaries\W10_Language_Pack_ENGB\W10_AVD_ENGB_05112021\stdout.txt"
echo $stdout

### Create registry to disable BlockCleanupOfUnusedPreinstalledLangPacks ###
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel" -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockCleanupOfUnusedPreinstalledLangPacks" -PropertyType DWORD -Value 1 -Force


# Enable Windows Installer RDS Compatibility now installation of Microsoft 365 is complete.

Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv" -Force -Recurse 

Start-Sleep -s 10

#### Install 7-Zip ####
Write-Output "#### Install 7-Zip ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\software"  -Filter *.msi

$binaryFullName = $binary.FullName

$p = Start-Process 'msiexec.exe' -ArgumentList '/i', """$binaryFullName""", "/quiet" -wait

Write-Output $p


#### Optimisations ####

Write-Output "#### Optimisations ####"

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name "fEnableTimeZoneRedirection" -PropertyType Dword -Value '1' -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name "AllowTelemetry" -PropertyType Dword -Value '3' -Force

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "MaxMonitors" -PropertyType Dword -Value '4' -Force

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "MaxXResolution" -PropertyType Dword -Value '5120' -Force

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "MaxYResolution" -PropertyType Dword -Value '2880' -Force

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs\" -Force 

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs\" -Name "MaxMonitors" -PropertyType Dword -Value '4' -Force

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs\" -Name "MaxXResolution" -PropertyType Dword -Value '5120' -Force

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs\" -Name "MaxYResolution" -PropertyType Dword -Value '2880' -Force

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\" -Name HubMode -PropertyType Dword -Value '1' -Force 

Write-Output "#### HKCU Optimisations ####"
reg Load HKLM\Temp C:\Users\Default\NTUSER.DAT
New-Item -Path HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects -Force
New-ItemProperty -Path "HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -PropertyType Dword -Value '00000003'-Force

New-Item -Path HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\ -Force
New-ItemProperty -Path "HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy\" -Name "01" -PropertyType Dword -Value '0' -Force
[GC]::Collect()
reg Unload HKLM\Temp  

# Remove unwanted AppX packages
Write-Output "#### Remove unwanted AppX packages ####"
   $AppList = "3dbuilder",           
               "officehub",
               "skypeapp",
               "getstarted",
                  "solitairecollection",
                  "bingfinance",
                  "bingnews",
                  "OneConnect",
                  "windowsphone",
                  "bingsports",
                  "Office.Sway",
                  "Microsoft.GetHelp",
                  "Microsoft.WindowsMaps",
                  "Microsoft.Messaging",
                  "Microsoft.Microsoft3DViewer",
                  "Microsoft.Print3D",
                  "Microsoft.WindowsStore",
                  "Microsoft.StorePurchaseApp",
                  "Microsoft.windowscommunicationsapps",
                  "Xbox",
                  "bingweather",
                  "Zune",
                  "YourPhone"

    $AppListCount = $AppList.Count
    $AppRemovalProgress = 1

    ForEach ($App in $AppList)
    {
        Write-Host "Removing App: $App."
        Write-Progress -Id 2 -Activity "Removing AppxPackages." -PercentComplete ($AppRemovalProgress/$AppListCount * 100) -Status "Removing App: $App."

        Get-AppxProvisionedPackage -Online | where {$_.Displayname -like "*$App*"} | Remove-AppxProvisionedPackage -Online -AllUsers

        $AppRemovalProgress++
    } 

#Remove from registry
$listGUIDs = @(
'{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}',
'{d3162b92-9365-467a-956b-92703aca08af}',
'{1CF1260C-4DD0-4ebb-811F-33C572699FDE}',
'{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}',
'{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}',
'{24ad3ad4-a569-4530-98e1-ab02f9417aa8}',
'{A0953C92-50DC-43bf-BE83-3742FED03C9C}',
'{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}'
)

cd HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\

foreach ($GUID in $listGUIDs)
{
Remove-item .\$GUID\ -Force #-Recurse
Write-Host "Removed $GUID"
}

cd HKLM:\SOFTWARE\Wow6432Node\Microsoft\WIndows\CurrentVersion\Explorer\MyComputer\NameSpace\

foreach ($GUID in $listGUIDs)
{
Remove-item .\$GUID\ -Force #-Recurse
Write-Host "Removed $GUID"
}

#### Prevents AIB build process sticking on certain base images

Write-Output "#### AIB Related Entries ####"
New-Item -Path "HKLM:\Software\Microsoft\DesiredStateConfiguration"
New-ItemProperty -Path "HKLM:\Software\Microsoft\DesiredStateConfiguration" -Name "AgentId" -PropertyType STRING -Force



#### Removing local drives as the last step

Write-Output "#### Removing local drives as the last step ####"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -PropertyType Dword -Value '67108863' -Force
