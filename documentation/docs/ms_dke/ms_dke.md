To use Microsoft Double Key Encryption (DKE)you must have a Microsoft 365 E5 license (EEA or standard)
and must have access to the Microsoft Purview compliance portal.

## Configuring Microsoft Double Key Encryption in your tenant

Please follow the [main documentation](https://learn.microsoft.com/en-us/purview/double-key-encryption-setup)
provided by Microsoft. The following adds a few details and tips to the process.

The documentation on configuring sensitivity labels is [available here](https://learn.microsoft.com/en-gb/purview/encryption-sensitivity-labels)


1. Activating the protection service from Azure Information Protection

    The protection service [must be activated](https://learn.microsoft.com/en-us/azure/information-protection/activate-service) in order to use DKE.
    
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


3. Activate sensitivity labels for MS 365 groups

   Sensitivity labels must be activated for MS 365 groups which are also called unified groups

    The objective is to set the `EnableMIPLabels` parameter to `True` at the Entra ID Directory level (which is set to `False` by default), using  `Group.Unified` template

    > The [EnableMIPLabels] flag indicates whether sensitivity labels published in Microsoft Purview compliance portal can be applied to Microsoft 365 groups. For more information, see Assign Sensitivity Labels for Microsoft 365 groups.

    To verify the current value of the `EnableMIPLabels` parameter, run the following command:

    ```powershell
    $Setting = Get-AzureADDirectorySetting | ? { $_.DisplayName -eq "Group.Unified"}
    &Setting.Values
    ```
    
    [See this doc](https://learn.microsoft.com/en-gb/purview/sensitivity-labels-teams-groups-sites#using-sensitivity-labels-for-microsoft-teams-microsoft-365-groups-and-sharepoint-sites) and [Enable sensitivity label support in PowerShell](https://learn.microsoft.com/en-us/entra/identity/users/groups-assign-sensitivity-labels#enable-sensitivity-label-support-in-powershell) which will probably require [configuring groups](https://learn.microsoft.com/en-us/entra/identity/users/groups-settings-cmdlets) first


4. De-activate co-authoring in Mircosoft Purview

   Do NOT click the box on [this page](https://compliance.microsoft.com/compliancesettings/co-authoring_for_files_with_sensitivity_labels),
   doing so will prevent the use of DKE in Sensitivity Labels.

   If you need to deactivate co-authoring, you can do so by running the following commands:

    ```powershell
    Install-Module -Name PSWSMan # if not already installed
    Install-WSMan
    Install-Module -Name ExchangeOnlineManagement
    Import-Module ExchangeOnlineManagement
    Connect-IPPSSession -UserPrincipalName you_admin_user@your_domain.com
    Set-PolicyConfig -EnableLabelCoauth:$false
    ```


5. Create a sensitivity label for encryption

   Navigate to [Purview](https://compliance.microsoft.com/homepage) then `Solutions > Information protection > Labels`

   Follow [these instructions](https://learn.microsoft.com/en-gb/purview/create-sensitivity-labels#create-and-configure-sensitivity-labels) to create the label.
   Select `Double Key Encryption` on the encryption configuration screen and make sure 
   you do not activate co-authoring.
   ![Sensitivity Label](./sensitivity_label.png)

   Activating the label (scope) for meetings does not seem to work.
   ![label scope](./label_scope.png)



