# AddTempAdminRights
This tool provides users to elevate themselves as admins for 5 minutes through Intune's Company Portal for Windows Devices. You can specify the time in lenght yourself in the script, if you find 5 minutes being too short. 

# Features
- Uses Intune Win32 app package detection method to flag the status of admin rights been added. Detection file is also removed in 5 minutes together with previleges.
- Logs activity in Event Viewer Application - node. Two log event will hapen - rights added and rights removed.

  <img width="484" height="174" alt="image" src="https://github.com/user-attachments/assets/5cebf801-2f2b-42d1-af35-fff28414bc11" />

- Scheduled Task is hidden inside the node hierarcy that advanced user will not find the task to make his/her rights permanent




# Instructions
Detection file is  
```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AddTempAdminRights.flag
```
Command line for installation is  
```
%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "AddTempAdminRights_v1.1.ps1"
```

# Additional considerations
Add Account Protection Policy or Remediation Script in Intune to remove any local admin rights. Because with this tool, user will be capable to add side-by-side permanent local admin account.

# Known issues
- User will not be additionally prompted when rights are added. Only Company Portal installation status will appear. Make sure you write good instruction to application notes how it supposed to be used.
- Some times Company Portal still shows "installed" status after rights are removed. This is due to Intune mdm policies not being updated yet. Users should still be capable of re-installing the app from CP 

<img width="1061" height="754" alt="image" src="https://github.com/user-attachments/assets/7fc5bca5-c579-4531-9f1a-144c2f75c486" />
