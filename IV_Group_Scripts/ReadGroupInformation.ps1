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
    $GroupName = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du groupe a consulter.", "Read Group Information", "Informatique")
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

# Nom de l'attribut du groupe à consulter
try {
    $GroupAttribute = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom de l'attribut du groupe '$($ExistingGroup.Name)' ($($ExistingGroup.SamAccountName)) à consulter (laissez vide pour tout afficher).", "Lire les informations du groupe", "")
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Afficher l'attribut (ou tous si le champs est laisse vide) + check si l'attribut existe (s'il est precise)
try {
    if ([string]::IsNullOrWhiteSpace($GroupAttribute)) {
        # Afficher tous les attributs
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "Tous les attributs du groupe '$($ExistingGroup.Name)' :"
        $ExistingGroup | Format-List | Out-String | ForEach-Object {
            Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen $_
        }
    } else {
        # Vérifier si l'attribut existe
        if ($ExistingGroup.PSObject.Properties.Name -contains $GroupAttribute) {

            # Afficher l'attribut spécifique
            if ($GroupAttribute -eq "member" -or $GroupAttribute -eq "Members") {

                # Afficher les membres du groupe
                Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "Membres du groupe '$($ExistingGroup.Name)' :"
                $GroupMembers = Get-ADGroupMember -Identity $ExistingGroup.SamAccountName -ErrorAction Stop
                foreach ($Member in $GroupMembers) {
                    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "- $($Member.Name) ($($Member.SamAccountName)) | $($Member.DistinguishedName)"
                }
            } else {
                Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "Attribut '$GroupAttribute' du groupe '$($ExistingGroup.Name)' :"
                Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "$($ExistingGroup.$GroupAttribute)"
            }

        } else {
            Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'attribut '$GroupAttribute' n'existe pas pour le groupe '$($ExistingGroup.Name)'."
        }
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la lecture des informations du groupe : [$_]"
    exit
}
