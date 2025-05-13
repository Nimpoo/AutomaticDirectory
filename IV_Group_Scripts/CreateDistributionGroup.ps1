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

# Nom du groupe de distribution a creer
try {
    $GroupName = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du groupe de distribution que vous voulez creer.", "Create Distribution Group", "Distrib")
    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le nom du groupe ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$GroupName]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$GroupName]"
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check si le groupe de distribution existe deja
try {
    $ExistingGroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction Stop
    if ($ExistingGroup) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Un groupe avec le nom '$GroupName' existe déjà."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de l'existence du groupe : [$_]"
    exit
}

# Nom du Organisation Unit (OU)
try {
    $OU = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom de l'unité d'organisation (OU) où le groupe sera créé (par exemple, 'Domain Controllers').", "Create Distribution Group", "Domain Controllers")
    if ([string]::IsNullOrWhiteSpace($OU)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le nom de l'unité d'organisation ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }

    # Vérification de l'existence de l'OU
    $ExistingOU = Get-ADOrganizationalUnit -Filter "Name -eq '$OU'" -ErrorAction Stop
    if (-not $ExistingOU) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'unité d'organisation '$OU' n'existe pas."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Path : [$($ExistingOU.DistinguishedName)]"
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Portée du groupe de distribution (Group Scope)
try {
    $GroupScope = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez la portée du groupe (par exemple, 'Global', 'DomainLocal' ou 'Universal').", "Create Distribution Groupe", "Global")
    if ([string]::IsNullOrWhiteSpace($GroupScope)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "La portée du groupe ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }

    # Vérification de la validité de la portée du groupe
    $validScopes = @("Global", "DomainLocal", "Universal")
    if ($validScopes -notcontains $GroupScope) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "La portée du groupe doit être 'Global', 'DomainLocal', ou 'Universal'."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GroupScope : [$GroupScope]`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Description du futur groupe de distribution
try {
    $DescriptionGroup = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez une description au groupe de distribution '$GroupName' que vous voulez creer (laissez vide si vous ne voulez pas de description).", "Create Distribution Group", "En gros ici on envoie des mails je crois.")

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Description :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "$DescriptionGroup`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Creation du groupe de distribution
try {
    $OUDistinguishedName = $ExistingOU.DistinguishedName
    New-ADGroup `
        -Name $GroupName `
        -SamAccountName $GroupName `
        -GroupCategory Distribution `
        -Path $OUDistinguishedName `
        -GroupScope $GroupScope `
        -Description $DescriptionGroup `
        -ErrorAction Stop

    Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "Le groupe de distribution '$GroupName' a été créé avec succès dans l'unité d'organisation '$OU'."
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la création du groupe : [$_]"
    exit
}
