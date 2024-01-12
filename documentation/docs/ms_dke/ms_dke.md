

# MS Install

## Restrict access to content by using sensitivity labels to apply encryption

Main documentation https://learn.microsoft.com/en-gb/purview/encryption-sensitivity-labels

1. Activating the protection service from Azure Information Protection

https://learn.microsoft.com/en-us/azure/information-protection/activate-service

Run PowerShell as Admin

```powershell
Install-Module -Name AIPService
``` 
In case of troubles with the execution policy, try

```powershell
powershell -ExecutionPolicy ByPass
```

Get the status of the AIP service

```powershell
Import-Module AIPService
Get-AIPService
```

You may have to connect to it first
```powershell
Connect-AipService
```

If it is disabled, enable it
```powershell
Enable-AipService
```

More options for phased deployments here: https://learn.microsoft.com/en-us/azure/information-protection/activate-service#configuring-onboarding-controls-for-a-phased-deployment

2. Microsoft Entra configuration for encrypted content

Check if there is [anything to configure](https://learn.microsoft.com/en-gb/purview/encryption-azure-ad-configuration)

3. Create a sensitivity label for encryption

Navigate to [Purview](https://compliance.microsoft.com/homepage)

Then `Solutions > Information protection > Labels`

Follow [these instructions](https://learn.microsoft.com/en-gb/purview/create-sensitivity-labels#create-and-configure-sensitivity-labels) to create the label.

 - Sensitivity labels must be activated for MS 365 groups which are also called unified groups

The first objective is to set the `EnableMIPLabels` parameter to `True` at the Entra ID Directory level (which is set to `False` by default), using  `Group.Unified` template 

> The [EnableMIPLabels] flag indicates whether sensitivity labels published in Microsoft Purview compliance portal can be applied to Microsoft 365 groups. For more information, see Assign Sensitivity Labels for Microsoft 365 groups.

To verify the current value of the `EnableMIPLabels` parameter, run the following command:

```powershell
$Setting = Get-AzureADDirectorySetting | ? { $_.DisplayName -eq "Group.Unified"}
&Setting.Values
```

   [See this doc](https://learn.microsoft.com/en-gb/purview/sensitivity-labels-teams-groups-sites#using-sensitivity-labels-for-microsoft-teams-microsoft-365-groups-and-sharepoint-sites)
   - [Enable sensitivity label support in PowerShell](https://learn.microsoft.com/en-us/entra/identity/users/groups-assign-sensitivity-labels#enable-sensitivity-label-support-in-powershell)
   - which will probably require [configuring groups](https://learn.microsoft.com/en-us/entra/identity/users/groups-settings-cmdlets) first