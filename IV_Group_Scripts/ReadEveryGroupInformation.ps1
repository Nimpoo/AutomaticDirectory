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

# Nom de l'attribut à consulter chez tout les groupes
try {
    $GroupAttribute = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom de l'attribut à consulter chez tout les groupes (laissez vide pour tout afficher).", "Read Every Group Information", "")
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Lire et afficher les informations de tous les groupes
try {
    $AllGroups = Get-ADGroup -Filter * -Properties * -ErrorAction Stop

    foreach ($Group in $AllGroups) {
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkBlue "`n-------------------------------------------------------------------`n"
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Nom du groupe : $($Group.Name)"
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : $($Group.SamAccountName)"

        if ([string]::IsNullOrWhiteSpace($GroupAttribute)) {
            # Afficher tous les attributs
            Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Tous les attributs du groupe '$($Group.Name)' :"
            $Group | Format-List | Out-String | ForEach-Object {
                Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen $_
            }
        } else {
            # Vérifier si l'attribut existe
            if ($Group.PSObject.Properties.Name -contains $GroupAttribute) {
                # Afficher l'attribut spécifique
                if ($GroupAttribute -eq "member" -or $GroupAttribute -eq "Members") {
                    # Afficher les membres du groupe
                    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Membres du groupe '$($Group.Name)' :"
                    $GroupMembers = Get-ADGroupMember -Identity $Group.SamAccountName -ErrorAction Stop
                    foreach ($Member in $GroupMembers) {
                        Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "- $($Member.Name) ($($Member.SamAccountName)) | $($Member.DistinguishedName)"
                    }
                } else {
                    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "Attribut '$GroupAttribute' du groupe '$($Group.Name)' :"
                    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "$($Group.$GroupAttribute)"
                }
            } else {
                Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'attribut '$GroupAttribute' n'existe pas pour le groupe '$($Group.Name)'."
            }
        }
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la lecture des informations des groupes : [$_]"
    exit
}
