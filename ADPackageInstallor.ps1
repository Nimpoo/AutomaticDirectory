# Installation de "Active Directory Domain Services"
$ADDS = Get-WindowsFeature -Name AD-Domain-Services
try {
    if ($ADDS.Installed) {
        Write-Output "Active Directory Domain Service est DEJA installe."
    } else {
        Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
        Write-Output "Active Directory Domain Service est desormais installe."
    }
} catch {
    Write-Output "Erreur lors de l'installation de AD DS : [$_]"
}

# Installation de "Domain Name Service"
$DNS = Get-WindowsFeature -Name DNS
try {
    if ($DNS.Installed) {
        Write-Output "DNS est DEJA installe."
    } else {
        Add-WindowsFeature -Name DNS -IncludeManagementTools -IncludeAllSubFeature
        Write-Output "DNS est desormais installe."
    }
} catch {
    Write-Output "Erreur lors de l'installation de DNS : [$_]"
}

# Installation de "RSAT-AD-Tools"
$RSAT = Get-WindowsFeature -Name RSAT-AD-Tools
try {
    if ($RSAT.Installed) {
        Write-Output "RSAT-AD-Tools est DEJA installe."
    } else {
        Add-WindowsFeature -Name RSAT-AD-Tools -IncludeManagementTools -IncludeAllSubFeature
        Write-Output "RSAT-AD-Tools est desormais installe."
    }
} catch {
    Write-Output "Erreur lors de l'installation de RSAT-AD-Tools : [$_]"
}
