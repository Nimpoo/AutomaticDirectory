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

# L'utilisateur dont un attribut va etre change
try {
    $User = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le 'SamAccountName' de l'utilisateur dont vous voulez modifier un attribut. ('SamAccountName' = premiere lettre du 'GivenName' suivi du 'Surname' (prenom puis nom de famille) en minuscule. Exemple : 'Zoro Roronoa' -> 'SamAccountName' = 'zroronoa')", "Edit User Attribute", "zroronoa")
    if ([string]::IsNullOrWhiteSpace($User)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le 'SamAccountName' ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check de l'existance du user
try {
    $ExistingUser = Get-ADUser -Identity $User -Properties * -ErrorAction Stop
    if (-not $ExistingUser) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'utilisateur '$User' n'existe pas."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "DistinguishedName : [$($ExistingUser.DistinguishedName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GivenName : [$($ExistingUser.GivenName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Surname : [$($ExistingUser.Surname)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$($ExistingUser.Name)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$($ExistingUser.SamAccountName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "UserPrincipalName : [$($ExistingUser.UserPrincipalName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "ObjectClass : [$($ExistingUser.ObjectClass)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "ObjectGUID : [$($ExistingUser.ObjectGUID)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Enabled : [$($ExistingUser.Enabled)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SID : [$($ExistingUser.SID)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "AddedProperties : [$($ExistingUser.AddedProperties)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "RemovedProperties : [$($ExistingUser.RemovedProperties)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "ModifiedProperties : [$($ExistingUser.ModifiedProperties)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "PropertyCount : [$($ExistingUser.PropertyCount)]`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "PropertyNames : [$($ExistingUser.PropertyNames)]`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la verification de l'existance de l'utilisateur : [$_]"
    exit
}

# Demander l'attribut à modifier
try {
    $Attribute = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom de l'attribut que vous souhaitez modifier pour l'utilisateur '$($ExistingUser.Name)' (par exemple, 'Department', 'Title', 'EmailAddress', etc.)", "Edit User Attribute", "Department")
    if ([string]::IsNullOrWhiteSpace($Attribute)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'attribut ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }

    # Vérification de la validité de l'attribut
    $UserAttributes = Get-ADUser -Identity $User -Properties * -ErrorAction Stop
    if (-not ($UserAttributes.PSObject.Properties.Name -contains $Attribute)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'attribut spécifié '$Attribute' n'est pas valide pour l'utilisateur '$($ExistingUser.Name)'."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Afficher la valeur actuelle de l'attribut
try {
    $CurrentValue = $ExistingUser.$Attribute
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "$Attribute : [$CurrentValue]`n"
} catch {
    Write-Host -ForegroundColor Yellow "L'attribut '$Attribute' n'existe pas ou n'a pas de valeur actuelle."
}

# Demander la nouvelle valeur de l'attribut
try {
    $NewValue = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez la nouvelle valeur pour l'attribut '$Attribute' que vous voulez modifier pour l'utilisateur '$($ExistingUser.Name)' (Laissez vide pour supprimer la valeur).", "Modifier l'attribut de l'utilisateur", "")
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Modifier l'attribut de l'utilisateur
try {
    if ([string]::IsNullOrWhiteSpace($NewValue)) {
        # Supprimer la valeur de l'attribut
        Set-ADUser -Identity $User -Clear $Attribute -ErrorAction Stop
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "La valeur de l'attribut '$Attribute' a été supprimée avec succès pour l'utilisateur '$($ExistingUser.Name)'."

        # Afficher la nouvelle valeur de l'attribut
        $UpdatedUser = Get-ADUser -Identity $User -Properties $Attribute -ErrorAction Stop
        $UpdatedValue = $UpdatedUser.$Attribute
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "$Attribute : [$UpdatedValue]"
    } else {
        Set-ADUser -Identity $User -Replace @{$Attribute = $NewValue} -ErrorAction Stop
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "La valeur de l'attribut '$Attribute' a été modifié avec succès par '$NewValue' pour l'utilisateur '$($ExistingUser.Name)'."

        # Afficher la nouvelle valeur de l'attribut
        $UpdatedUser = Get-ADUser -Identity $User -Properties $Attribute -ErrorAction Stop
        $UpdatedValue = $UpdatedUser.$Attribute
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "$Attribute : [$UpdatedValue]"
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la modification de l'attribut : [$_]"
    exit
}
