# vpl_config
- Admin configuration repository for Intel PSG Training VPL infrastructure.

- This repository should exclusively contain definitions for FPGA-connected "JTAG servers" within the VPL network. 

- New machines may be added by carefully appending rows to the "vpl_config.csv" file in this repo. Note that the minimum required columns are {Host Name,Device,Dev Kit,IP,Password}. Omitting these columns will result in a configuration failure.

- Keep this repo private! The only users/machines with access should be to repo owner (the VPL admin) and the master server in the VPL infrastructure. All other access should be prohibited.

- This repo is cloned by the Master server automatically each day and the following steps are performed via the jtag server configuration script:
  - Import vpl_config.csv
  - Foreach row in vpl_config.csv (foreach JTAG server machine)
    - Generate SSH public/private keys
    - Using provided password, export keys to JTAG server
    - Test key-authenticated SSH
    - Test JTAGconfig response
    - Test port-forwarding of port 1309
    - Append machine statuses (results of all tests) to the vpl_status.csv and push to VPL_admin_status repository
    - Append the SSH keys and config entries to the vpl_update/.ssh folder and push to the repo. These items will be pulled by trainee VM instances at startup.

# Common Reasons Config Fails
- Missing path append for Quartus Programmer bin
  - RDP to the problematic JTAG server
  - Append the path to the Quartus Programmer/Quartus bin64 folder to the Windows Path environment variable
- JTAG server has an existing remote connection that can't be reached
  - Results in a long JTAGconfig result
  - May be fixed by opening Quartus programmer and removing all existing
    - RDP to the problematic JTAG server
    - Open Quartus Programmer
    - Click "Hardware Setup"
    - Click "JTAG Settings"
    - Remove all servers
- SSHD config issue
  - Remote connect anticipates the standard unmodified sshd_config file
  - This file can be restored easily in Windows
    - RDP to the problematic JTAG server
    - Open powershell as an administrator
    - Run the following command
      - `cd C:\ProgramData\ssh\; Remove-Item .\sshd_config; Restart-Service sshd` 
