# Installation de "Active Directory Domain Services"
$ADDS = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop
try {
    if ($ADDS.Installed) {
        Write-Host -ForegroundColor Blue "Active Directory Domain Service est DEJA installe."
    } else {
        Write-Host -ForegroundColor Yellow "Installation d'Active Directory Domain Services EN COURS..."
        Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature -ErrorAction Stop
        Write-Host -ForegroundColor Green "Active Directory Domain Service est desormais installe."
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'installation de AD DS : [$_]"
}

# Installation de "Domain Name Service"
$DNS = Get-WindowsFeature -Name DNS -ErrorAction Stop
try {
    if ($DNS.Installed) {
        Write-Host -ForegroundColor Blue "DNS est DEJA installe."
    } else {
        Write-Host -ForegroundColor Yellow "Installation de DNS EN COURS..."
        Add-WindowsFeature -Name DNS -IncludeManagementTools -IncludeAllSubFeature -ErrorAction Stop
        Write-Host -ForegroundColor Green "DNS est desormais installe."
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'installation de DNS : [$_]"
}

# Installation de "RSAT-AD-Tools"
$RSAT = Get-WindowsFeature -Name RSAT-AD-Tools -ErrorAction Stop
try {
    if ($RSAT.Installed) {
        Write-Host -ForegroundColor Blue "RSAT-AD-Tools est DEJA installe."
    } else {
        Write-Host -ForegroundColor Yellow "Installation de RSAT-AD-Tools EN COURS..."
        Add-WindowsFeature -Name RSAT-AD-Tools -IncludeManagementTools -IncludeAllSubFeature -ErrorAction Stop
        Write-Host -ForegroundColor Green "RSAT-AD-Tools est desormais installe."
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'installation de RSAT-AD-Tools : [$_]"
}
