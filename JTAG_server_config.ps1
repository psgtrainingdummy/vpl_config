# Script globals
$ssh_path_local = "$env:USERPROFILE\.ssh"

# Create log file to hold log errors
#	Each log error will produce a respective success message if error is not encountered
$log_fh = "${PSScriptRoot}\logfile.txt"
$null > $log_fh
$pass_path = "${PSScriptRoot}\pass.ps1"
$null > "$pass_path"
$host.ui.RawUI.WindowTitle = "JTAG Config"

# Presence check GitHub deploy key for vpl_config (id_vpl_config)
$id_vpl_config = "${ssh_path_local}\id_vpl_config"
if ( ( Test-Path $id_vpl_config ) -and ( Test-Path "${id_vpl_config}.pub" ) ) {
	$success_str = "Success: Found vpl_config repo deploy keys."
    Add-Content $log_fh $success_str
} else {
	$err_str = "Error: Could not find vpl_config repo deploy keys at ${id_vpl_config}. Exiting."
	Add-Content $log_fh $err_str
	Get-Content $log_fh
	exit
}

# Clear/create config_jtagservers file
$config_export_fh = "${ssh_path_local}\config_jtagservers"
if ( Test-Path $config_export_fh ) {
	Add-Content $log_fh "Config export file found. Clearing contents."
	Clear-Content $config_export_fh
} else {
	New-Item $config_export_fh
}
 
# Clear previous local SSH keys for JTAG servers
Get-ChildItem ${ssh_path_local} -Filter "*id*jtagserver*" -Recurse | Remove-Item

# Clear previous local SSH keys for JTAG servers
Get-ChildItem ${ssh_path_local} -Filter "*known_hosts*" -Recurse | Remove-Item
 
# Clone vpl_config 
#	Repo exclusively containins vpl_config.csv
#	Admin populates rows to define JTAG server hosts
#	Required col headers {Host Name,Device,Dev Kit,IP,Password}
$vpl_config_pull_dir = "${PSScriptRoot}\GitHubPulls\vpl_config"
if ( Test-Path $vpl_config_pull_dir ) {
	Add-Content $log_fh "Clearing exisiting GitHub vpl_config pull"
	Remove-Item -Recurse -Force $vpl_config_pull_dir
	New-Item $vpl_config_pull_dir -itemType Directory
} else {
	Add-Content $log_fh "No exisiting GitHub vpl_config pull."
	New-Item $vpl_config_pull_dir -itemType Directory
}

git clone git@github-vpl_config:psgtrainingdummy/vpl_config.git $vpl_config_pull_dir >> $log_fh 2>&1

if ( $LASTEXITCODE -eq 0 ) {
	Add-Content $log_fh "Successs: Git clone for vpl_config completed."
} else {
	Add-Content $log_fh "Error: Git clone for vpl_config failed. Exiting."
	Get-Content $log_fh
	exit
}

# Import vpl_config.csv to object
$vpl_conf_csv_path = "${vpl_config_pull_dir}\vpl_config.csv"
$vpl_conf_ok = 0
if ( $vpl_conf_csv_path ) {
	Add-Content $log_fh "Successs: vpl_config.csv found in vpl_config clone."
	$vpl_config = Import-CSV -Path $vpl_conf_csv_path
	$col_headers = ${vpl_config}[0].psobject.Properties.name
	if ( ( $col_headers -contains "Host Name" )`
		-and( $col_headers -contains "Device" )`
		-and( $col_headers -contains "Dev Kit" )`
		-and( $col_headers -contains "IP" )`
		-and( $col_headers -contains "Password" ) ){
		Add-Content $log_fh "Successs: vpl_config.csv has required headers."
		$vpl_conf_ok = 1
	} else {
		Add-Content $log_fh "Error: vpl_config.csv does not has required headers {Host Name,Device,Dev Kit,IP,Password}."
		Get-Content $log_fh
		exit
	}
} else {
	Add-Content $log_fh "Error: No vpl_config.csv found in vpl_config clone."
	Get-Content $log_fh
	exit
}

# Presence check GitHub deploy key for vpl_update (id_vpl_update)
$id_vpl_update = "${ssh_path_local}\id_vpl_update"
if ( ( Test-Path $id_vpl_update ) -and ( Test-Path "${id_vpl_update}.pub" ) ) {
	$success_str = "Success: Found vpl_update repo deploy keys."
    Add-Content $log_fh $success_str
} else {
	$err_str = "Error: Could not find vpl_update repo deploy keys at ${id_vpl_update}. Exiting."
	Add-Content $log_fh $err_str
	Get-Content $log_fh
	exit
}

# Clone vpl_update
$vpl_update_pull_dir = "${PSScriptRoot}\GitHubPulls\vpl_update"
if ( Test-Path $vpl_update_pull_dir ) {
	Add-Content $log_fh "Clearing exisiting GitHub vpl_update clone"
	Remove-Item -Recurse -Force $vpl_update_pull_dir
	New-Item $vpl_update_pull_dir -itemType Directory
} else {
	Add-Content $log_fh "No exisiting GitHub vpl_update clone."
	New-Item $vpl_update_pull_dir -itemType Directory
}

git clone git@github-vpl_update:psgtrainingdummy/vpl_update.git $vpl_update_pull_dir >> $log_fh 2>&1

if ( $LASTEXITCODE -eq 0 ) {
	Add-Content $log_fh "Successs: Git clone for vpl_update completed."
} else {
	Add-Content $log_fh "Error: Git clone for vpl_update failed. Exiting."
	Get-Content $log_fh
	exit
}

# Clear ssh folder
$vpl_update_ssh_dir = "${vpl_update_pull_dir}\.ssh"
$config_export = "${vpl_update_pull_dir}\.ssh\config"
if ( Test-Path $vpl_update_ssh_dir ) {
	Add-Content $log_fh "Clearing exisiting GitHub vpl_update clone"
	Remove-Item -Recurse -Force $vpl_update_ssh_dir
	New-Item $vpl_update_ssh_dir -itemType Directory
} else {
	Add-Content $log_fh "No exisiting GitHub vpl_update clone."
	New-Item $vpl_update_pull_dir -itemType Directory
}

# Initialize vpl_update config file (will be populated with functional jtagservers)
New-Item $config_export
Add-Content $log_fh "Initialized vpl_update config file"

# Initialize vpl_status.csv for admin vpl_status repo
	#	Copy of vpl_config (minus password and user name columns)
	#	Add status columns for all tests performed
$vpl_status = $vpl_config
$vpl_status = $vpl_status | Select-Object * -ExcludeProperty  Password
$vpl_status = $vpl_status | Select-Object * -ExcludeProperty  "User Name"
$vpl_status = $vpl_status | Select-Object *, @{n="SSH Up";e={NULL}}
$vpl_status = $vpl_status | Select-Object *, @{n="JTAGcnfg on JTAGserv";e={NULL}}
$vpl_status = $vpl_status | Select-Object *, @{n="Port 1309 Forward";e={NULL}}
$vpl_status = $vpl_status | Select-Object *, @{n="JTAGcnfg on Master";e={NULL}}
Add-Content $log_fh "Initialized vpl_status.csv."

# Initialize fpga_list.csv in vpl_update repo
	#	Copy of vpl_config (minus ip, username and password columns)
	#	Will be trimmed if hosts fail tests
$fpga_list = $vpl_config
$fpga_list = $fpga_list | Select-Object * -ExcludeProperty  Password
$fpga_list = $fpga_list | Select-Object * -ExcludeProperty  "User Name"
$fpga_list = $fpga_list | Select-Object * -ExcludeProperty  IP
Add-Content $log_fh "Initialized fpga_list.csv."

$i = 0
# Foreach JTAGserver host
foreach (${jtag_server_host_name} in ${vpl_config}."Host Name"){
	
	# Define data for the current server being configured
	$jtag_server_ip =  ${vpl_config}.IP[$i]
	$jtag_server_device =  ${vpl_config}.Device[$i]
	$jtag_server_user_name =  ${vpl_config}."User Name"[$i]
	$all_tests_passed = 0
	$ssh_test_passed = 0
	$jtag_config_test_1_passed = 0
	$ssh_pf_test_passed = 0
	$jtag_config_test_2_passed = 0
	
	#Create SSH keys
	$identity_file_path = "${ssh_path_local}/id_rsa_jtagserver_${jtag_server_host_name}"
	ssh-keygen -q -t rsa -N '""' -f $identity_file_path
	$identity_file_path = ${identity_file_path}.Replace("\", "/")

	# Make SSH password hack script
	Clear-Content $pass_path
	Add-Content $pass_path '$wshell = New-Object -ComObject wscript.shell;'
	Add-Content $pass_path '$wshell.AppActivate("JTAG Config")'
	Add-Content $pass_path 'Sleep 2'
	Add-Content $pass_path '$wshell.SendKeys("yes")'
	Add-Content $pass_path '$wshell.SendKeys("~")'
	Add-Content $pass_path 'Sleep 2'
	$this_pass =  ${vpl_config}.Password[${i}]
	Add-Content $pass_path "`$wshell.SendKeys(""${this_pass}"")"
	Add-Content $pass_path '$wshell.SendKeys("~")'
	Add-Content $log_fh "Created password hack script"

	# Append config entries to local .ssh
	# Create config file entries for diagnostics
	$jtag_server_entry_diag = "jtagserver_${jtag_server_host_name}_diag"
	Add-Content "${ssh_path_local}\config_jtagservers" "Host ${jtag_server_entry_diag}"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tHostName ${jtag_server_ip}"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tUser ${jtag_server_user_name}"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tIdentityFile ${identity_file_path}`n"
	Start-Process -FilePath $env:GIT_USR_BIN\dos2unix.exe -ArgumentList "${ssh_path_local}\config" -Wait
	
	# Create config file entries for port forwarding
	$jtag_server_entry_pf = "jtagserver_${jtag_server_host_name}"
	Add-Content "${ssh_path_local}\config_jtagservers" "Host ${jtag_server_entry_pf}"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tStrictHostKeyChecking no"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tHostName ${jtag_server_ip}"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tUser ${jtag_server_user_name}"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tIdentityFile ${identity_file_path}"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tLocalForward 1309 127.0.0.1:1309"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tRemoteCommand cat"
	Add-Content "${ssh_path_local}\config_jtagservers" "`tLogLevel DEBUG`n"
	Start-Process -FilePath $env:GIT_USR_BIN\dos2unix.exe -ArgumentList "${ssh_path_local}\config" -Wait
	
	Add-Content $log_fh "Created local SSH config entries."

	# Attempt to deploy public key to JTAGserver host
	$authorizedKey = Get-Content -Path "${identity_file_path}.pub"
	$remotePowershell = "powershell Clear-Content '$env:ProgramData\ssh\administrators_authorized_keys'; Add-Content -Force -Path '$env:ProgramData\ssh\administrators_authorized_keys' -Value '$authorizedKey';icacls.exe ""$env:ProgramData\ssh\administrators_authorized_keys"" /inheritance:r /grant ""Administrators:F"" /grant ""SYSTEM:F""; New-ItemProperty -Path ""HKLM:\SOFTWARE\OpenSSH"" -Name DefaultShell -Value ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"" -PropertyType String -Force"
	start powershell.exe $pass_path -WorkingDirectory ${PSScriptRoot}; ssh ${jtag_server_user_name}@${jtag_server_ip} $remotePowershell
	Add-Content $log_fh "Cleared authorized key file, set default shell as powershell, and deployed SSH keys to JTAG server ${jtag_server_host_name}."

	# Perform .ssh test
	# Test SSH using config for diagnostics
	$sshLogTxt = "${PSScriptRoot}\test_log.txt"
	$null > $sshLogTxt
	$stdErrLog = "${PSScriptRoot}\test_log_err.txt"
	$null > $stdErrLog
	$stdOutLog = "${PSScriptRoot}\test_log_out.txt"
	$null > $stdOutLog 
	$ssh_test_proc = Start-Process -FilePath "ssh.exe" -ArgumentList "${jtag_server_entry_diag} echo ok" -RedirectStandardOutput "$stdOutLog" -RedirectStandardError "$stdErrLog" -PassThru
	Start-Sleep 1
	Get-Content $stdErrLog, $stdOutLog | Out-File $sshLogTxt -Append
	$sshLog = Get-Content $sshLogTxt
	$ssh_test_successful = $ssh_test_proc.HasExited
	if ( ( $sshLog -like 'ok*' ) -and ( $ssh_test_successful -eq 'True' ) ) {
		Add-Content $log_fh "Success: SSH test for JTAG server ${jtag_server_host_name} successful."
		$ssh_test_passed = 1
	} else {
		Add-Content $log_fh "Error: SSH test for JTAG server ${jtag_server_host_name} unsuccessful."
		$ssh_test_passed = 0
		if ( $ssh_test_proc.HasExited -ne 'True') {
			Stop-Process $ssh_test_proc.Id
		}
	}

	# Perform JTAG config test
	# Test JTAG config (local to JTAG server)
	$jtagLogTxt = "${PSScriptRoot}\test_log.txt"
	$null > $jtagLogTxt
	$stdErrLog = "${PSScriptRoot}\test_log_err.txt"
	$null > $stdErrLog
	$stdOutLog = "${PSScriptRoot}\test_log_out.txt"
	$null > $stdOutLog 
	$jtag_test_1_proc = Start-Process -FilePath "ssh.exe" -ArgumentList "${jtag_server_entry_diag} jtagconfig" -RedirectStandardOutput "$stdOutLog" -RedirectStandardError "$stdErrLog" -PassThru
	Start-Sleep 4
	Get-Content $stdErrLog, $stdOutLog | Out-File $jtagLogTxt -Append
	$jtagLog = Get-Content $jtagLogTxt
	$jtag_test_successful = $jtag_test_1_proc.HasExited
	if ( ( $jtagLog -like '*)*USB*Blaster*' ) -and ( $jtag_test_successful -eq 'True' ) ) {
		Add-Content $log_fh "Success: JTAGconfig on JTAGserver test for JTAG server ${jtag_server_host_name} successful."
		$jtag_config_test_1_passed = 1
	} else {
		Add-Content $log_fh "Error: JTAGconfig on JTAGserver test for JTAG server ${jtag_server_host_name} unsuccessful."
		$jtag_config_test_1_passed = 0
		if ( $jtag_test_1_proc.HasExited -ne 'True') {
			Stop-Process $jtag_test_1_proc.Id
		}
	}

	# Perform port forwarding test
	$sshLogTxt = "${PSScriptRoot}\test_log.txt"
	$null > $sshLogTxt
	$stdErrLog = "${PSScriptRoot}\test_log_err.txt"
	$null > $stdErrLog
	$stdOutLog = "${PSScriptRoot}\test_log_out.txt"
	$null > $stdOutLog 
	$ssh_test_proc = Start-Process -FilePath "ssh.exe" -ArgumentList "${jtag_server_entry_pf}" -RedirectStandardOutput "$stdOutLog" -RedirectStandardError "$stdErrLog" -PassThru
	Start-Sleep 2
	Get-Content $stdErrLog, $stdOutLog | Out-File $sshLogTxt -Append
	$sshLog = Get-Content $sshLogTxt
	$ssh_test_successful = (-Not $ssh_test_proc.HasExited)
	if ( ( $sshLog -like '*Local forwarding listening on ::1 port 1309.*' ) -and ( $sshLog -like '*debug1: Sending command: cat' ) -and ( $ssh_test_successful -eq 'True' ) ) {
		Add-Content $log_fh "Success: SSH port forward test for JTAG server ${jtag_server_host_name} successful."
		$ssh_pf_test_passed = 1
	} else {
		Add-Content $log_fh "Error: SSH port forward test for JTAG server ${jtag_server_host_name} unsuccessful."
		$ssh_pf_test_passed = 0
		if ( $ssh_test_proc.HasExited -ne 'True') {
			Stop-Process $ssh_test_proc.Id
		}
	}
	
	# Perform local JTAG config test
		Stop-Process $ssh_test_proc.Id
	#
	$row = $i
	
	if ( $ssh_test_passed ) {
		${vpl_status}[$row]."SSH Up" = "Success"
	} else {
		${vpl_status}[$row]."SSH Up" = "Fail"
	}
	if ( $jtag_config_test_1_passed ) {
		${vpl_status}[$row]."JTAGcnfg on JTAGserv" = "Success"
	} else {
		${vpl_status}[$row]."JTAGcnfg on JTAGserv" = "Fail"
	}
	if ( $ssh_pf_test_passed ) {
		${vpl_status}[$row]."Port 1309 Forward" = "Success"
	} else {
		${vpl_status}[$row]."Port 1309 Forward" = "Fail"
	}
	if ( $jtag_config_test_2_passed ) {
		${vpl_status}[$row]."JTAGcnfg on Master" = "Success"
	} else {
		${vpl_status}[$row]."JTAGcnfg on Master" = "Fail"
	}

	echo ${vpl_status}

	# Trim fpga_list.csv

		# Log err 20.0: [this JTAGserver host] could not trim fpga_list.csv due to test failure

	# If successful
	#  Copy SSH keys to vpl_update
	#  Append config entry to vpl_update config file

		# Log err 21.0: [this JTAGserver host] could not copy ssh keys to vpl_update
		# Log err 21.1: [this JTAGserver host] could not append to vpl_update SSH config
		
	if ( $all_tests_passed ) {
		# Create config file to export to VM
		Add-Content "${ssh_path_local}\config_jtag" "Host ${jtag_server_entry_pf}"
		Add-Content "${ssh_path_local}\config_export" "`tStrictHostKeyChecking no"
		Add-Content "${ssh_path_local}\config_export" "`tHostName ${jtag_server_ip}"
		Add-Content "${ssh_path_local}\config_export" "`tUser ${jtag_server_user_name}"
		Add-Content "${ssh_path_local}\config_export" "`tIdentityFile ${identity_file_path}"
		Add-Content "${ssh_path_local}\config_export" "`tLocalForward 1309 127.0.0.1:1309"
		Add-Content "${ssh_path_local}\config_export" "`tRemoteCommand cat"
		Add-Content "${ssh_path_local}\config_export" "`tLogLevel DEBUG`n"
		Start-Process -FilePath $env:GIT_USR_BIN\dos2unix.exe -ArgumentList  "${ssh_path_local}\config_export" -Wait
	}
	++$i
}

# Add and commit vpl_status

	# Log err 22.0: Could not push updates to vpl_status

# Add and commit vpl_update files

	# Log err 23.0: Could not push updates to vpl_update
	