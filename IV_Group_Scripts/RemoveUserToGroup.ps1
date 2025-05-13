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

# L'utilisateur qui sera retire au groupe
try {
    $User = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le 'SamAccountName' de l'utilisateur a retirer d'un groupe. ('SamAccountName' = premiere lettre du 'GivenName' suivi du 'Surname' (prenom puis nom de famille) en minuscule. Exemple : 'Zoro Roronoa' -> 'SamAccountName' = 'zroronoa')", "Remove User To Group", "zroronoa")
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

# Check si l'utilisateur est dans au moins un groupe
try {
    $UserGroups = Get-ADUser -Identity $ExistingUser.SamAccountName -Properties MemberOf -ErrorAction Stop
    if (-not $UserGroups.MemberOf) {
        Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) n'est membre d'aucun groupe."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "Groupe.s dont l'utilisateur $($ExistingUser.Name) est membre :"
    $UserGroups.MemberOf | ForEach-Object {
        $Group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
        if ($Group) {
            Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "- $($Group.Name)"
        }
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification des groupes de l'utilisateur : [$_]"
    exit
}

# Nom du groupe ou retirer le user
try {
    $GroupName = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du groupe que $($ExistingUser.Name) va quitter (le 'SamAccountName' plus precisement, par defaut les 'Name' et 'SamAccountName' sont similaire pour les groupes).", "Remove User To Group", "Informatique")
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
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkBlue "`n-------------------------------------------------------------------`n"

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

# Check si l'utilisateur est présent dans le groupe
try {
    $GroupMembers = Get-ADGroupMember -Identity $ExistingGroup.SamAccountName -ErrorAction Stop
    $UserPresent = $GroupMembers | Where-Object { $_.SamAccountName -eq $ExistingUser.SamAccountName }

    if (-not $UserPresent) {
        Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) n'est pas membre du groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName))."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de la présence de l'utilisateur dans le groupe : [$_]"
    exit
}

# Demander confirmation à l'utilisateur
try {
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkRed "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) s'apprete a quitter le groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName)).`n" 
    $confirmation = [Microsoft.VisualBasic.Interaction]::MsgBox("Voulez-vous faireretirer l'uilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) du groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName)) ?", 4 + 32, "Confirmation")
    if ($confirmation -ne 6) {  # 6 correspond à "Yes" dans MsgBox
        Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "Opération annulée par l'utilisateur."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Retirer l'utilisateur du groupe demandé
try {
    Remove-ADGroupMember `
        -Identity $ExistingGroup.SamAccountName `
        -Members $ExistingUser.SamAccountName `
        -Confirm:$false `
        -ErrorAction Stop

    Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) a été retiré avec succès du groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName))."

    # Mise à jour des groupes de l'utilisateur
    $UpdatedUserGroups = Get-ADUser -Identity $ExistingUser.SamAccountName -Properties MemberOf -ErrorAction Stop
    if (-not $UpdatedUserGroups.MemberOf) {
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "L'utilisateur '$($ExistingUser.Name)' ($($ExistingUser.SamAccountName)) n'est membre d'aucun groupe."        
    } else {
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "Mise a jour des/du groupe.s de l'utilisateur $($ExistingUser.Name) :"

        $UpdatedUserGroups.MemberOf | ForEach-Object {
            $Group = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
            if ($Group) {
                Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "- $($Group.Name)"
            }
        }
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'ajout de l'utilisateur au groupe : [$_]"
    exit
}
