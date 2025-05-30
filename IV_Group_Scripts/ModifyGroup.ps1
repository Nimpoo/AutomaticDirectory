# Chargement de l'assembly "Microsoft.VisualBasic" pour le InputDialog
try {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors du chargement de l'assembly 'Microsoft.VisualBasic' : [$_]"
    exit
}


# Check if AD DS is already installed
Write-Host -ForegroundColor Yellow "Vérification de la présence d'AD DS EN COURS..."

$IsInstalled = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop

try {
    if (-not $IsInstalled.Installed) {
        Write-Host -ForegroundColor Yellow "AD DS n'est pas installé. Veuillez installer AD DS avant de promouvoir ce serveur en tant que contrôleur de domaine (ADPackageInstallor.ps1)."
        exit
    }
    Write-Host -ForegroundColor Green "AD DS est bien installé sur le serveur."
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification d'AD DS ou du statut du contrôleur de domaine : [$_]"
    exit
}

# Check if the server is a domain controller
try {
    Write-Host -ForegroundColor Yellow "Vérification si le serveur est un contrôleur de domaine EN COURS..."

    # Use WMI to check if the server is a domain controller
    $IsDomainController = Get-WmiObject -Class Win32_ComputerSystem -Property DomainRole -ErrorAction Stop

    if ($IsDomainController.DomainRole -ne 4 -and $IsDomainController.DomainRole -ne 5) {
        Write-Host -ForegroundColor Yellow "Ce serveur n'est pas un contrôleur de domaine."
        exit
    }

    Write-Host -ForegroundColor Green "Ce serveur est un contrôleur de domaine."
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification du statut du contrôleur de domaine : [$_]"
    exit
}

# Importer le module Active Directory
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'importation du module Active Directory : [$_]"
    exit
}

# Nom du groupe
try {
    $GroupName = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du groupe que vous voulez modifier (le 'SamAccountName' plus precisement, par defaut les 'Name' et 'SamAccountName' sont similaire pour les groupes).", "Modify Group", "Informatique")
    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le nom du groupe ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check si le groupe existe
try {
    $ExistingGroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -Properties * -ErrorAction Stop
    if (-not $ExistingGroup) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le groupe '$GroupName' n'existe pas."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$($ExistingGroup.Name)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$($ExistingGroup.SamAccountName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Path : [$($ExistingGroup.DistinguishedName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GroupScope : [$($ExistingGroup.GroupScope)]`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Description :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "$($ExistingGroup.Description)`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "PropertyNames :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "$($ExistingGroup.PropertyNames)`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de l'existence du groupe : [$_]"
    exit
}

# Nom de l'attribut du groupe a modifier
try {
    $GroupAttribute = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom de l'attribut que vous voulez modifier au groupe '$GroupName'.", "Modify Group", "Description")
    if ([string]::IsNullOrWhiteSpace($GroupAttribute)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le nom de l'attribut ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }

    # Vérification de la validité de l'attribut
    if (-not ($ExistingGroup.PSObject.Properties.Name -contains $GroupAttribute)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'attribut spécifié '$GroupAttribute' n'est pas valide pour le groupe '$GroupName'."
        exit
    }

    Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "L'attribut a modifier pour le groupe '$GroupName' :"
    Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "$GroupAttribute : [$($ExistingGroup.$GroupAttribute)]`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Demander la nouvelle valeur de l'attribut
try {
    $NewValue = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez la nouvelle valeur pour l'attribut '$GroupAttribute' (laisser vide pour supprimer la valeur actuelle).", "Modify Group", $ExistingGroup.$GroupAttribute)
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Modifier l'attribut du groupe
try {
    if ([string]::IsNullOrWhiteSpace($NewValue)) {
        # Supprimer la valeur de l'attribut
        Set-ADGroup -Identity $ExistingGroup.SamAccountName -Clear $GroupAttribute -ErrorAction Stop
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "La valeur de l'attribut '$GroupAttribute' a été supprimée avec succès pour le groupe '$($ExistingGroup.Name)'."
    } else {
        # Mettre à jour la valeur de l'attribut
        Set-ADGroup -Identity $ExistingGroup.SamAccountName -Replace @{$GroupAttribute = $NewValue} -ErrorAction Stop
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "L'attribut '$GroupAttribute' a été modifié avec succès pour le groupe '$($ExistingGroup.Name)'."
    }

    if ($GroupAttribute -eq "SamAccountName") {
        $UpdatedGroup = Get-ADGroup -Identity $NewValue -Properties $GroupAttribute -ErrorAction Stop
    } else {
        $UpdatedGroup = Get-ADGroup -Identity $GroupName -Properties $GroupAttribute -ErrorAction Stop
    }

    $UpdatedValue = $UpdatedGroup.$GroupAttribute

    Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "$GroupAttribute : [$UpdatedValue]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la modification de l'attribut : [$_]"
    exit
}
