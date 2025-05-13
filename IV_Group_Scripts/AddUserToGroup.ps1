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

# L'utilisateur qui sera ajoute au groupe
try {
    $User = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le 'SamAccountName' de l'utilisateur a ajouter dans un groupe. ('SamAccountName' = premiere lettre du 'GivenName' suivi du 'Surname' (prenom puis nom de famille) en minuscule. Exemple : 'Zoro Roronoa' -> 'SamAccountName' = 'zroronoa')", "Add User To Group", "zroronoa")
    if ([string]::IsNullOrWhiteSpace($User)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le 'SamAccountName' ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check de l'existance du user a ajouter
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
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "UserPrincipalName : [$($ExistingUser.UserPrincipalName)]`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "PropertyNames : [$($ExistingUser.PropertyNames)]`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la verification de l'existance de l'utilisateur : [$_]"
    exit
}

# Nom du groupe ou ajouter un user
try {
    $GroupName = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du groupe que $($ExistingUser.Name) va integrer (le 'SamAccountName' plus precisement, par defaut les 'Name' et 'SamAccountName' sont similaire pour les groupes).", "Add User To Group", "Informatique")
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
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkBlue "-------------------------------------------------------------------`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$($ExistingGroup.Name)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$($ExistingGroup.SamAccountName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Path : [$($ExistingGroup.DistinguishedName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GroupScope : [$($ExistingGroup.GroupScope)]`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Description :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "$($ExistingGroup.Description)`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "PropertyNames :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "$($ExistingGroup.PropertyNames)`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkBlue "-------------------------------------------------------------------`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de l'existence du groupe : [$_]"
    exit
}

# Check si l'utilisateur est deja present dans le groupe
try {
    $GroupMembers = Get-ADGroupMember -Identity $ExistingGroup.SamAccountName -ErrorAction Stop
    $UserPresent = $GroupMembers | Where-Object { $_.SamAccountName -eq $ExistingUser.SamAccountName }

    if ($UserPresent) {
        Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) est déjà présent dans le groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName))."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de la présence de l'utilisateur dans le groupe : [$_]"
    exit
}

# Demander confirmation à l'utilisateur
try {
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkRed "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) s'apprete a rejoindre le groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName)).`n" 
    $confirmation = [Microsoft.VisualBasic.Interaction]::MsgBox("Voulez-vous faire entrer l'uilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) au groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName)) ?", 4 + 32, "Confirmation")
    if ($confirmation -ne 6) {  # 6 correspond à "Yes" dans MsgBox
        Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "Opération annulée par l'utilisateur."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Ajout de l'utilisateur saisi au groupe demandé
try {
    Add-ADGroupMember `
        -Identity $ExistingGroup.SamAccountName `
        -Members $ExistingUser.SamAccountName `
        -ErrorAction Stop

    Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) a été ajouté avec succès au groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName))."
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'ajout de l'utilisateur au groupe : [$_]"
    exit
}
