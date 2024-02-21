
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

$W10PSScript = Get-ChildItem -recurse "C:\temp\binaries\W10_Language_Pack_ENGB"  -Filter "Install_LanguagePack.ps1"
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
$binary = Get-ChildItem -recurse "C:\temp\binaries\7-Zip"  -Filter *.msi

$binaryFullName = $binary.FullName

$p = Start-Process 'msiexec.exe' -ArgumentList '/i', """$binaryFullName""", "/quiet" -wait

Write-Output $p
<#
#### Install Microsoft 365 ####

Write-Output "#### Install Microsoft 365 ####"

#Turn off Windows Installer RDS Compatibility.

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\TSMSI" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\TSMSI" -Name "Enable" -PropertyType DWORD -Value 0 -Force

$officeDeploymentToolBinary = Get-ChildItem -recurse "C:\temp\binaries\Office Deployment Tool"  -Filter *officedeploymenttool_15028-20160.exe*
$officeDeploymentToolBinaryName = $officeDeploymentToolBinary.FullName

echo $officeDeploymentToolBinaryName

$officeDeploymentToolConfig = Get-ChildItem -recurse "C:\temp\binaries\Office Deployment Tool Config"  -Filter "configuration64bit(withAccess).xml"
$officeDeploymentToolConfigName = $officeDeploymentToolConfig.FullName

echo $officeDeploymentToolConfigName

mkdir "C:\temp\binaries\Office Deployment Tool\setup"

#### Unpack setup.exe ####
$p = Start-Process """$officeDeploymentToolBinaryName""" -ArgumentList """/extract:C:\temp\binaries\Office Deployment Tool\setup""", '/passive', '/quiet' -wait
#### Perform The Install ####
$p = Start-Process """C:\temp\binaries\Office Deployment Tool\setup\setup.exe""" -ArgumentList '/configure', """$officeDeploymentToolConfigName""" -wait

Write-Output $p

# Enable Windows Installer RDS Compatibility now installation of Microsoft 365 is complete.

Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv" -Force -Recurse 

Start-Sleep -s 10

#### Install C++ Runtime ####
Write-Output "#### Install C++ Runtime ####"

$cRuntimeBinary = Get-ChildItem -recurse "C:\temp\binaries\Visual C"  -Filter *.exe
$cRuntimeBinaryFullName = $cRuntimeBinary.FullName

echo $cRuntimeBinaryFullName

$p = Start-Process """$cRuntimeBinaryFullName""" -ArgumentList '/q', '/norestart' -wait

Start-Sleep -s 10

#### Install WebRTC Redirector ####
Write-Output "#### Install WebRTC Redirector ####"

$binary = Get-ChildItem -recurse "C:\temp\binaries\WebRTC Redirector"  -Filter *MsRdcWebRTCSvc_HostSetup_1.4.2111.18001_x64.msi*

$binaryFullName = $binary.FullName

$p = Start-Process 'msiexec.exe' -ArgumentList '/i', """$binaryFullName""", "/l*v c:\temp\WebRTC_Redirector.log", "/quiet" -wait

Write-Output $p

Start-Sleep -s 10

#### Install Teams ####
Write-Output "#### Install Teams ####"

New-Item 'HKLM:\Software\Microsoft\Teams' -Force 
New-ItemProperty -Path HKLM:\Software\Microsoft\Teams -Name IsWVDEnvironment -PropertyType Dword -Value '1'-Force

$binary = Get-ChildItem -recurse "C:\temp\binaries\Teams"  -Filter *Teams_windows_x64.msi.exe*

$binaryFullName = $binary.FullName

$p = Start-Process 'msiexec.exe' -ArgumentList '/i', """$binaryFullName""", "/l*v c:\temp\Teams.log", "ALLUSERS=1" -wait

Write-Output $p

Start-Sleep -s 10

#### Install OneDrive ####

Write-Output "#### Install OneDrive ####"

$oneDrivelBinary = Get-ChildItem -recurse "C:\temp\binaries\OneDrive"  -Filter *exe
$oneDriveBinaryName = $oneDrivelBinary.FullName

echo $oneDriveBinaryName

$p = Start-Process """$oneDriveBinaryName""" -ArgumentList '/allusers', ' /silent' -wait

Write-Output $p 

Start-Sleep -s 10


#### Install Slack ####
Write-Output "#### Install Slack ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\Slack"  -Filter *slack-standalone-4.25.2.0.msi*
$binaryFullName = $binary.FullName
echo $binaryFullName

$p = Start-Process 'msiexec.exe' -ArgumentList '/passive', '/i', """$binaryFullName""", 'ALLUSER=1' -wait
Write-Output $p

Start-Sleep -s 10


#### Install Stata ####
Write-Output "#### Install Stata ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\StataCorp Stata 17SE x64 Network Licence"  -Filter Install*cmd
$binaryFullName = $binary.FullName
echo $binaryFullName

$p = Start-Process $binaryFullName -wait
Write-Output $p

Start-Sleep -s 10



#### Install NVIVIO ####
Write-Output "#### Install NVIVIO ####"
Write-Output "#### Install Prereq - SQL Server Express"
$binary = Get-ChildItem -recurse "C:\temp\binaries\QSR_International_NVIVIO_2020"  -Filter SqlLocalDB_x64*
$binaryFullName = $binary.FullName
echo $binaryFullName
$p = Start-Process 'msiexec.exe' -ArgumentList '/passive', '/i', """$binaryFullName""", 'IACCEPTSQLLOCALDBLICENSETERMS=YES', '/qb' -wait
Write-Output $p

Start-Sleep -s 10

Write-Output "#### Install Main Binary - NVivo.msi ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\QSR_International_NVIVIO_2020"  -Filter NVivo.msi
$binaryFullName = $binary.FullName
echo $binaryFullName
$p = Start-Process 'msiexec.exe' -ArgumentList '/passive', '/i', """$binaryFullName""", '/qb' -wait
Write-Output $p

Start-Sleep -s 10




#### Install SPSS ####
Write-Output "#### Install SPSS ####"

#Suspected chained MSI installation. Creates a problem with the Embedded MSI technology and the Windows Installer Coordinator.  
#The Coordinator is responsible for keeping multiple MSI installations from running concurrently.
#Turn off Windows Installer RDS Compatibility.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\TSMSI" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\TSMSI" -Name "Enable" -PropertyType DWORD -Value 0 -Force

$binary = Get-ChildItem -recurse "C:\temp\binaries\IBM SPSS Statistics 27.0 x64"  -Filter *.msi
$binaryFullName = $binary.FullName
echo $binaryFullName
Write-Output "#### Starting Install of SPSS ####"
$p = Start-Process 'msiexec.exe' -ArgumentList '/passive', '/i', """$binaryFullName""", "/l*v c:\temp\SPSS_install.log", 'LSHOST=APPPOR05.PHE.GOV.UK', 'LICENCETYPE=Network' -wait
Write-Output $p
Write-Output "#### Install of SPSS complete ####"

Start-Sleep -s 10

# Enable Windows Installer RDS Compatibility now installation of SPSS is complete.
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv" -Force -Recurse 


#### Install R For Windows ####
Write-Output "#### Install R For Windows ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\R For Windows"  -Filter R-4.2.0-win.exe
$RbinaryFullName = $binary.FullName
Write-Output $binaryFullName

Write-Output "#### Install Main Binary - NVivo.msi ####"

$p = Start-Process """$RbinaryFullName""" -ArgumentList '/VERYSILENT', '/NORESTART' -wait
Write-Output $p

Start-Sleep -s 10



#### Install SQL Management Studio ####
Write-Output "#### Install SQL Management Studio ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\SQLManagementStudio"  -Filter *.exe
$binaryFullName = $binary.FullName
echo $binaryFullName
$p = Start-Process $binaryFullName -ArgumentList '/install', '/quiet', '/norestart' -wait
Write-Output $p

Start-Sleep -s 10

#### Install Miniconda ####
Write-Output "#### Install Miniconda ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\Miniconda"  -Filter *.exe
$binaryFullName = $binary.FullName
Write-Output $binaryFullName
$p = Start-Process $binaryFullName -ArgumentList '/InstallationTypiie=AllUsers', '/RegisterPython=1', '/S', '/D=%programfiles%\Miniconda' -wait
Write-Output $p

Start-Sleep -s 10


#### Apply Start Menu Templates. Set the default pinned applications i.e the layout for new users

Import-StartLayout -LayoutPath "C:\temp\binaries\Start Menu Templates\officeWorkerLayout.xml" -MountPath "C:\" 

Start-Sleep -s 10




#### Install Egress Client ####

Write-Output "#### Install Egress Client ####"

# Required for multisession install. Ensures that the auth token stored in the user profile is transferred between sessions/VMs
# Provided by the Egress vendor via a support request as part of AVD planning.

New-Item -Path HKLM:\SOFTWARE\WOW6432Node\Egress\Switch -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Egress\Switch\" -Name "DeviceID" -PropertyType String -Value 'profile' -Force

$egressClientBinary = Get-ChildItem -recurse "C:\temp\binaries\Egress Client"  -Filter Install.bat
$egressClientBinaryName = $egressClientBinary.FullName

echo $egressClientBinaryName

$p = Start-Process """$egressClientBinaryName""" -wait

Write-Output $p

#region Param
$KeyName = "IdentityProviderHost"
#Command to run
$Command = "wsfed://login.microsoftonline.com:443/ee4e1499-4a35-4b2e-ad47-5f3cf9de8666/wsfed?sso-acs=https%3A%2F%2Fswitch.phe.gov.uk%2Fui%2F&sso-refresh=1"
#endregion Param

#region RegistryEntry
if (-not ((Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Egress\Switch).$KeyName))
{
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Egress\Switch' -Name $KeyName -Value $Command
}
else
{
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Egress\Switch' -Name $KeyName -Value $Command
}

Start-Sleep -s 10

#### Install Adobe ####
Write-Output "#### Install Adobe ####"
$binary = Get-ChildItem -recurse "C:\temp\binaries\Adobe Reader"  -Filter AcroRead.msi
$binaryPatches = Get-ChildItem -recurse "C:\temp\binaries\Adobe Reader"  -Filter AcroRdrDCUpd2200120117.msp
$binaryTransform = Get-ChildItem -recurse "C:\temp\binaries\Adobe Reader"  -Filter AcroRead.mst


$binaryFullName = $binary.FullName
$binaryPatchesFullName = $binaryPatches.FullName
$binaryTransformFullName = $binaryTransform.FullName

Write-Output $binaryFullName
Write-Output $binaryTransformFullName

$p = Start-Process 'msiexec.exe' -ArgumentList '/i', """$binaryFullName""", 'TRANSFORMS="C:\temp\binaries\Adobe Reader\AcroRead.mst"', "/quiet" -wait
Write-Output $p

foreach ($msp in $binaryPatchesFullName) {


$p = Start-Process 'msiexec.exe' -ArgumentList '/update', """$msp""", "/qn", "/norestart" -wait
Write-Output $msp

}
Write-Output $p

Start-Sleep -s 10

#########################FOHI-UPDATE############################################################



##.Net Framework
Write-Output "#Enabling .Net Framework"
Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3"
Start-Sleep -s 10


##Microsoft .NET Framework 3.5 SP1
Write-Output "##Microsoft .NET Framework 3.5 SP1"
cd 'C:\temp\binaries\Microsoft .NET Framework 3.5 SP1'
.\Install.bat -wait
Start-Sleep -s 50

<#
##Microsoft .NET Framework 4.8 x64 (version or later already installed)
Write-Output "##Microsoft .NET Framework 4.8 x64"
cd 'C:\temp\binaries\Microsoft .NET Framework 4.8 x64'
.\ndp48-x86-x64-allos-enu.exe
Start-Sleep -s 50



##DotNet SDK
Write-Output "##Microsoft_.Net_Core_SDK"
cd 'C:\temp\binaries\Microsoft_.Net_Core_SDK'
.\Install.CMD
Start-Sleep -s 50


##Access Database Engine 2007
Write-Output "##Access Database Engine 2007"
cd 'C:\temp\binaries\Microsoft_Office_Access_Database_Engine_2007_P1'
msiexec /i "AceRedist.msi" /T "Microsoft_Office_Access_Database_Engine_2007_P1.Mst" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50


##HSCIC Identity Agent
Write-Output "##HSCIC Identity Agent"
cd 'C:\temp\binaries\NHS HSCIC Identity Agent'
msiexec /i "NHS-Digital-Identity-Agent-2.3.2.0.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN 
Start-Sleep -s 50

##SQL Server Report Builder
Write-Output "##SQL Server Report Builder"
cd 'C:\temp\binaries\Microsoft Report Builder\Microsoft_Report_Builder_15.0.19611.0_P1'
msiexec /i "ReportBuilder.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50

## Firefox
Write-Output "##Firefox"
cd "C:\temp\binaries\Mozilla Firefox"
& '.\Firefox Setup 91.10.0esr.exe' -ms -wait
Start-Sleep -s 50

##Classic Client Patch for NHS
Write-Output "##Classic Client Patch for NHS"
cd 'C:\temp\binaries\Gemalto Classic Client'
msiexec /i "Gemalto Classic Client 6.1 Patch 3 x64 User Setup.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN

Start-Sleep -s 50

##NDR Tunnel
Write-Output "##NDR Tunnel"
##cd "C:\temp\binaries\NDR_Tunnel_1.0_P5\NDR Tunnel 1.0 P5"
cd "C:\temp\binaries\NDR_Tunnel_1.0_P5\Package Source\PROJECT_ASSISTANT\SINGLE_MSI_IMAGE\DiskImages\DISK1"
msiexec /i "NDR Tunnel 1.0 P5.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 10

##Tortoise
Write-Output "##Tortoise"
cd 'C:\temp\binaries\Tortoise SVN'
msiexec /i "TortoiseSVN-1.14.0.28885-x64-svn-1.14.0.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 10

##Python
Write-Output "##Python"
cd 'C:\temp\binaries\Python'
.\Install.CMD
Start-Sleep -s 50

##PostgresSQL JDBC Driver
Write-Output "##PostgresSQL JDBC Driver"
cd 'C:\temp\binaries\PostgresSQL_JDBC_Driver'
msiexec /i "PostgresSQL_JDBC_Driver_42.2.2_P1.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN 
Start-Sleep -s 50

##EndNote
Write-Output "##EndNote"
cd 'C:\temp\binaries\Clarivate_Analytics_Endnote'
.\Install.cmd
Start-Sleep -s 50


##Dbeaver
Write-Output "##Dbeaver"
cd 'C:\temp\binaries\DBeaver'
.\dbeaver-ce-22.1.0-x86_64-setup.exe /Allusers /S
Start-Sleep -s 50

##Filezilla
Write-Output "##Filezilla"
cd 'C:\temp\binaries\Filezilla'
.\FileZilla_3.60.1_win64-setup.exe /S
Start-Sleep -s 10

##Git
Write-Output "##Git"
cd 'C:\temp\binaries\Git'
.\Git-2.37.0-64-bit.exe /VERYSILENT /NOCLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /NORESTART /SP- /SUPPRESSMSGBOXES
Start-Sleep -s 10


##Notepad++
Write-Output "##Notepad++"
cd 'C:\temp\binaries\NotePad++'
.\npp.8.4.2.Installer.x64.exe /S
Start-Sleep -s 50

##Tableau
Write-Output "##Tableau Desktop"
cd 'C:\temp\binaries\Tableau Desktop 2021'
.\TableauDesktop-64bit-2021-4-8.exe /quiet /norestart ACCEPTEULA=1 REMOVEINSTALLEDAPP=1
Start-Sleep -s 50

#PyCharm
Write-Output "#PyCharm"
cd 'C:\temp\binaries\JetBrains PyCharm'
msiexec /i "PyCharm2019.3.3.0.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50

##SQLyog
Write-Output "##SQLyog"
cd 'C:\temp\binaries\Webyog_SQLyog'
.\Install.bat
Start-Sleep -s 50

####PuTTY
Write-Output "##PuTTY"
cd 'C:\temp\binaries\Putty'
.\putty-64bit-0.77-installer.msi REBOOT=ReallySuppress /qn
Start-Sleep -s 50

####Postgress SQL ODBC Drivers
Write-Output "##Postgress SQL ODBC Drivers"
cd 'C:\temp\binaries\Postgress SQL ODBC Drivers_13_00_0000-x64'
msiexec /i "psqlodbc_x64.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50

####Oracle Java SE 15 Development Kit
Write-Output "##Oracle Java SE 15 Development Kit"
cd 'C:\temp\binaries\Oracle Java SE 15 Development Kit'
.\jdk-15_windows-x64_bin.exe /s
Start-Sleep -s 50

####WinPython
Write-Output "##WinPython"
cd 'C:\temp\binaries\WinPython'
msiexec /i "WinPython_3.6.3.0-x64_V01.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN 
Start-Sleep -s 50

####WinSCP
Write-Output "##WinSCP"
cd 'C:\temp\binaries\WinSCP'
.\WinSCP-5.21.1-Setup.exe /VERYSILENT /NOCLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /NORESTART /SP- /SUPPRESSMSGBOXES
Start-Sleep -s 50

<#
####BadgerNet
Write-Output "##BadgerNet"
cd 'C:\temp\binaries\BadgerNet'
msiexec /i "BadgerNet Client v3.0.3.msi" TRANSFORMS="BadgerNet Client v3.0.3.mst" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50




####Anaconda
Write-Output "##Anaconda"
cd 'C:\temp\binaries\Anaconda'
.\Anaconda3-2020.07-Windows-x86_64.exe /InstallationType=AllUsers /S /D=C:\ProgramData\Anaconda3
Start-Sleep -s 50


####ArcGis
Write-Output "#### ArcGis ####"

$binary = Get-ChildItem "C:\temp\binaries\ArcGis\Package"  -Filter phegis_install_10_5_1.bat

$binaryFullName = $binary.FullName
echo $binaryFullName

$p = Start-Process """$binaryFullName""" -wait


####Ruby
Write-Output "##Ruby"
cd 'C:\temp\binaries\Ruby'
msiexec /i "Ruby_2.5.0-1_P1.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50


####Oracle_SQLDeveloper
Write-Output "##Oracle_SQLDeveloper"
cd 'C:\temp\binaries\Oracle_SQLDeveloper'
.\Install.cmd
Start-Sleep -s 50

####PowerBI Desktop
Write-Output "##PowerBI Desktop"
cd 'C:\temp\binaries\PowerBI Desktop'
.\PBIDesktopSetup.exe -silent -norestart ACCEPT_EULA=1
Start-Sleep -s 50

####Chrome
Write-Output "##Chrome"
cd 'C:\temp\binaries\Chrome'
msiexec /i "GoogleChromeStandaloneEnterprise64.msi" /qn
Start-Sleep -s 50


####Oracle Instant Client and ODBC Drivers
Write-Output "##Oracle Instant Client and ODBC Drivers"
cd 'C:\temp\binaries\Oracle Instant Client and ODBC Drivers'
.\Install.CMD
Start-Sleep -s 50

####Rtools
Write-Output "##Rtools"
cd 'C:\temp\binaries\RTools\RTools 4.0 x86_64'
msiexec /i "Rtools.msi" ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50


####Oracle Java 8u271
Write-Output "##Oracle Java 8u271"
cd 'C:\temp\binaries\Oracle Java 8u271 x86'
.\Install.cmd
Start-Sleep -s 50

####Microsoft SQL Server Native Client 2017
Write-Output "##Microsoft SQL Server Native Client 2017"
cd 'C:\temp\binaries\Microsoft SQL Server Native Client 2017'
msiexec /i "sqlncli.msi" ALLUSERS=1 REBOOT=ReallySupress IACCEPTSQLNCLILICENSETERMS=YES /qn
Start-Sleep -s 50


####Microsoft SQL Server ODBC Driver 17
Write-Output "##Microsoft SQL Server ODBC Driver 17"
cd 'C:\temp\binaries\Microsoft SQL Server ODBC Driver 17'
msiexec /i "msodbcsql.msi" IACCEPTMSODBCSQLLICENSETERMS=YES ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50


####Microsoft SQL Server Command Line Utilities 14.0
Write-Output "##Microsoft SQL Server Command Line Utilities 14.0"
cd 'C:\temp\binaries\Microsoft SQL Server Command Line Utilities 14.0'
msiexec /i "MsSqlCmdLnUtils.msi" IACCEPTMSSQLCMDLNUTILSLICENSETERMS=YES ALLUSERS=1 REBOOT=ReallySuppress /QN
Start-Sleep -s 50






Write-Output "##COMPLETE" 

#########################FOHI-UPDATE############################################################

#########################FOHI-UPDATE############################################################

#### Add Defender Scripts To Image ####
<#
Write-Output "#### Add Defender Scripts To Image ####"

New-Item -ItemType Directory -Force -Path C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup

$WindowsDefenderScriptsDir = Get-ChildItem "C:\temp\binaries\" -Filter WindowsDefender*

$WindowsDefenderScriptsPath = $WindowsDefenderScriptsDir.FullName + "\*" 

Copy-Item -Path $WindowsDefenderScriptsPath -Destination "C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup"  -Exclude *.zip

#### The following reg entries add the Defender for Endpoint scripts to the start up by local policy
#### Note that this executes the Single entry per device variant (useful for multi session, but can be used elsewhere). If this is not required
#### then WindowsDefenderATPOnboardingScript.bat shoud be called directly. 
#### See https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-endpoints-vdi?view=o365-worldwide#onboard-non-persistent-virtual-desktop-infrastructure-vdi-devices

#########################FOHI-UPDATE############################################################

Write-Output "#### Add Defender Scripts To Start Up under Local Policy ####"

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup" -Force
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -Force
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\1" -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -Name "GPO-ID" -PropertyType STRING -Value 'LocalGPO' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -Name "SOM-ID" -PropertyType STRING -Value 'Local' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -Name "FileSysPath" -PropertyType STRING -Value 'C:\Windows\System32\GroupPolicy\Machine' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -Name "DisplayName" -PropertyType STRING -Value 'Local Group Policy' -Force 
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -Name "GPOName" -PropertyType STRING -Value 'Local Group Policy' -Force 
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0" -Name "PSScriptOrder" -PropertyType DWORD -Value 1 -Force 

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -Name "Script" -PropertyType STRING -Value 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Onboard-NonPersistentMachine.ps1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -Name "Parameters" -PropertyType STRING -Value '' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -Name "IsPowershell" -PropertyType DWORD -Value '1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -Name "ExecTime" -PropertyType QWORD -Value 0 -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\1" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\1" -Name "Script" -PropertyType STRING -Value 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AVEngine_Update.ps1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\1" -Name "Parameters" -PropertyType STRING -Value '' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\1" -Name "IsPowershell" -PropertyType DWORD -Value '1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\1" -Name "ExecTime" -PropertyType QWORD -Value 0 -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup" -Force
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" -Force
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\1" -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" -Name "GPO-ID" -PropertyType STRING -Value 'LocalGPO' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" -Name "SOM-ID" -PropertyType STRING -Value 'Local' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" -Name "FileSysPath" -PropertyType STRING -Value 'C:\Windows\System32\GroupPolicy\Machine' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" -Name "DisplayName" -PropertyType STRING -Value 'Local Group Policy' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" -Name "GPOName" -PropertyType STRING -Value 'Local Group Policy' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0" -Name "PSScriptOrder" -PropertyType DWORD -Value '1' -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" -Name "Script" -PropertyType STRING -Value 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Onboard-NonPersistentMachine.ps1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" -Name "Parameters" -PropertyType STRING -Value '' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" -Name "IsPowershell" -PropertyType DWORD -Value '1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\0" -Name "ExecTime" -PropertyType QWORD -Value 0 -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\1" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\1" -Name "Script" -PropertyType STRING -Value 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\AVEngine_Update.ps1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\1" -Name "Parameters" -PropertyType STRING -Value '' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\1" -Name "IsPowershell" -PropertyType DWORD -Value '1' -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\0\1" -Name "ExecTime" -PropertyType QWORD -Value 0 -Force


#### The following is not strictly required, but makes the above config visible in the UI. The process uses the information
#### from the registry. 

$psScriptsFile = "C:\Windows\System32\GroupPolicy\Machine\Scripts\psscripts.ini"
New-Item $psScriptsFile -type file -Force -ErrorAction Ignore
"[Startup]" | Out-File $psScriptsFile -Append
"0CmdLine=C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\Onboard-NonPersistentMachine.ps1" | Out-File $psScriptsFile -Append 

Start-Sleep -s 10

<#
#region TeamViewer
########## TeamViewer Install ###############
Write-Output "##### Install TeamViewer ####"

#region CreateFolder
New-Item -ItemType Directory -Path 'C:\Scripts' -Force
$Folder = Get-Item 'C:\Scripts' -Force
$Folder.Attributes = 'Hidden'
#endregion CreateFolder

#region extract
Get-ChildItem -recurse "C:\temp\binaries" -Filter TeamViewer.zip |

Foreach-Object {
    echo $_.FullName 
    echo $_.Directory 
    Expand-Archive $_.FullName 'C:\Scripts' -Force
}
#endregion extract
$TeamViewerBat = Get-ChildItem -Recurse "C:\Scripts" -Filter *.bat
$TeamViewerMSI = Get-ChildItem -Recurse "C:\Scripts" -Filter *.msi
$TeamViewerBatName = $TeamViewerBat.FullName
$TeamViewerMSIName = $TeamViewerMSI.FullName

Write-Output $TeamViewerBatName

# $p = Start-Process """$TeamViewerBatName""" -wait

$p = Start-Process 'msiexec.exe' -ArgumentList '/i', """$TeamviewerMSIName""", '/qn DESKTOPSHORTCUTS=0 CUSTOMCONFIGID=6b65jzf APITOKEN=14590208-wIdpxsxFUNXRKoa8trAU ASSIGNMENTOPTIONS="--reassign --alias %ComputerName% --grant-easy-access --group AVD"' -Wait

Write-Output $p

Start-Sleep -s 10


<#
#region Param
    $KeyName = "TeamViewer"
    #Command to run
    $Command = "C:\Scripts\TeamViewer_AVD_Host.bat"
#endregion Param

#region RegistryEntry
if (-not ((Get-Item -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce).$KeyName ))
{
New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name $KeyName -Value $Command -PropertyType ExpandString
}
else
{
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name $KeyName -Value $Command -PropertyType ExpandString
}
#endregion RegistryEntry
#>
#endregion TeamViewer
#>

#### App Masking Demo  ####
#### A demo of FSLogix App Masking was requested for the Golden Image. This demo simply masks Adobe Acrobat from user WVD.Test1@ukhsa.gov.uk  ####
#### It is designed ot provide a start point only

<#Removed for TEST
Write-Output "#### Copy App Masking ####"
Copy-Item -Path "C:\temp\binaries\App Masking\*" -Destination "C:\Program Files\FSLogix\Apps\Rules" 
#>




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

<#
#Stopping Microsoft Monitoring Agent Service
$numberOfCerts = 0
Write-Output "Stopping the 'Microsoft Monitoring Agent' service if it exists ..."
Stop-Service -name Healthservice -Force -Confirm:$false -ErrorAction SilentlyContinue
Write-Output "The 'Microsoft Monitoring Agent' service has been succesfully stopped."
cd Cert:\LocalMachine\"Microsoft Monitoring Agent"
$numberOfCerts = (ls | measure).Count
#Delete any certs in Monitoring agent store
Write-Output "Certificates in Microsoft Monitoring Agent Store: $numberOfCerts" 
 
for ($n = 0 ; $n -lt $numberOfCerts ; $n++){ 
  Invoke-Expression "certutil -delstore ""Microsoft Monitoring Agent"" 0"
}
#>

#### Prevents AIB build process sticking on certain base images

Write-Output "#### AIB Related Entries ####"
New-Item -Path "HKLM:\Software\Microsoft\DesiredStateConfiguration"
New-ItemProperty -Path "HKLM:\Software\Microsoft\DesiredStateConfiguration" -Name "AgentId" -PropertyType STRING -Force

#MOVED this section
#### Tidy up the binaries and other installation artifacts ####

<#
Write-Output "#### Tidy Up Installation Directory ####"
Remove-Item -Path "C:\\temp" -recurse -Force
#>

#### Removing local drives as the last step

Write-Output "#### Removing local drives as the last step ####"
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDrives" -PropertyType Dword -Value '67108863' -Force
