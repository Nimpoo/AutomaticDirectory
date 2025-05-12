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

# L'utilisateur a filtrer
try {
    $User = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le 'SamAccountName' d'un utilisateur pour filtrer les resultats. Laissez vide pour ne rien filtrer ('SamAccountName' = premiere lettre du 'GivenName' suivi du 'Surname' (prenom puis nom de famille) en minuscule. Exemple : 'Zoro Roronoa' -> 'SamAccountName' = 'zroronoa')", "Read Data Base Information", "")
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check de l'existance du user a filtrer
try {
    if ([string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrEmpty($User)) {
        Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "Tout les utilisateur du domaine seront pris."
    } else {
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
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "UserPrincipalName : [$($ExistingUser.UserPrincipalName)]`n"

        Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "PropertyNames : [$($ExistingUser.PropertyNames)]`n"
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la verification de l'existance de l'utilisateur : [$_]"
    exit
}

# L'attribut a filtrer
try {
    $Attribute = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom de l'attribut que vous souhaitez utiliser pour filtrer les résultats (laisser vide pour les attributs principaux, ''*' pour tout les attributs).", "Read Data Base Information", "")
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Récupérer les utilisateurs
try {
    if ([string]::IsNullOrWhiteSpace($User)) {
        # Récupérer tous les utilisateurs
        $Users = Get-ADUser -Filter * -Properties * -ErrorAction Stop
    } else {
        # Récupérer un utilisateur spécifique
        $Users = Get-ADUser -Identity $User -Properties * -ErrorAction Stop
        if (-not $Users) {
            Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'utilisateur '$User' n'existe pas."
            exit
        }
    }

    # Afficher les informations des utilisateurs
    if ([string]::IsNullOrWhiteSpace($Attribute)) {
        # Afficher les informations principaux de chaque utilisateur
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "Informations des utilisateurs :"
        $Users | Format-Table -AutoSize -Property SamAccountName, GivenName, Surname, Name, UserPrincipalName

    } elseif ($Attribute -eq "*") {
        # Afficher toutes les propriétés de chaque utilisateur
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "Toutes les propriétés des utilisateurs :"
        foreach ($user in $Users) {
            Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Informations de l'utilisateur '$($user.Name)' ($($user.SamAccountName)) :"
            $user | Format-List *
        }

    } else {
        # Afficher uniquement l'attribut spécifié pour chaque utilisateur
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "Valeurs de l'attribut '$Attribute' pour les utilisateurs :"
        foreach ($user in $Users) {
            if ($user.PSObject.Properties.Name -contains $Attribute) {
                $AttributeValue = $user.$Attribute
                Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "$($user.Name) ($($user.SamAccountName)) : $AttributeValue"
            } else {
                Write-Host -ForegroundColor Yellow "L'attribut '$Attribute' n'existe pas pour l'utilisateur '$($user.SamAccountName)'."
            }
        }
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la récupération des informations des utilisateurs : [$_]"
    exit
}
