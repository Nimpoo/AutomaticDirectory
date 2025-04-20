Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
Add-WindowsFeature -Name DNS -IncludeManagementTools -IncludeAllSubFeature
Add-WindowsFeature -Name RSAT-AD-Tools -IncludeManagementTools -IncludeAllSubFeature
