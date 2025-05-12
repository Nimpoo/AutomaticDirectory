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

# Check if the server is already a domain controller
try {
    Write-Host -ForegroundColor Yellow "Vérification si le serveur est déjà un contrôleur de domaine..."

    # Use WMI to check if the server is a domain controller
    $IsDomainController = Get-WmiObject -Class Win32_ComputerSystem -Property DomainRole -ErrorAction Stop

    if ($IsDomainController.DomainRole -eq 4 -or $IsDomainController.DomainRole -eq 5) {
        Write-Host -ForegroundColor Yellow "Ce serveur est déjà un contrôleur de domaine."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification du statut du contrôleur de domaine : [$_]"
    exit
}

    Write-Host -ForegroundColor Green "Ce serveur n'est pas encore un contrôleur de domaine."

# Charger l'assembly Microsoft.VisualBasic pour pouvoir ouvrir des pop-ups
try {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors du chargement de l'assembly 'Microsoft.VisualBasic' : [$_]"
    exit
}

# Importer le module Active Directory
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'importation du module Active Directory : [$_]"
    exit
}

# Pop-up ouverte pour taper le nom du Controlleur de Domain
try {
    $DomainAddress = [Microsoft.VisualBasic.Interaction]::InputBox("What existing Domain Controller you want this server joins ? (exemple: nimpo.local)", "Joining an existing Domain Controller", "domolia.local")
    if ([string]::IsNullOrWhiteSpace($DomainAddress)) {
        Write-Host -ForegroundColor Red "Le nom de domaine ne peut pas etre vide (ou qu'avec des whitespaces)."
        exit
    }
    if ($DomainAddress -match '\d') {
        Write-Host -ForegroundColor Red "Le nom de domaine ne doit pas contenir de chiffres."
        exit
    }

    Write-Host -ForegroundColor Cyan "Le nom de votre nom de domaine : [$DomainAddress]"
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Pop-up ouverte pour saisir les informations d'identification de l'administrateur afin de rejoindre le DC existant
try {
    $AdminCredential = Get-Credential -Message "Veuillez entrer les informations d'identification de l'administrateur (exemple: Administrator@domolia.local)" -UserName "Administrator@domolia.local" -ErrorAction Stop

    if (-not $AdminCredential) {
        Write-Host -ForegroundColor Red "Les informations d'identification ne peuvent pas être vides."
        exit
    }

    $AdminPasswordPlainText = ConvertTo-SecureString $AdminCredential.Password -AsPlaintext -Force -ErrorAction Stop

    Write-Host -ForegroundColor Cyan "Nom d'utilisateur : [$AdminUser]"
    Write-Host -ForegroundColor Cyan "Les informations d'identification ont été saisies en toute sécurité."

} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de la saisie des informations d'identification : [$_]"
    exit
}

# Vérification de la connectivité DNS
try {
    Write-Host -ForegroundColor Yellow "Verification de la connectivite DNS avec $DomainAddress EN COURS..."
    $dnsServers = Resolve-DnsName -Name $DomainAddress -ErrorAction Stop
    Write-Host -ForegroundColor Cyan "Les serveurs DNS pour le domaine $DomainAddress ont été résolus avec succès."
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la résolution DNS pour le domaine $DomainAddress : [$_]"
    exit
}

# Promotion d'un serveur en tant que Controleur de Domaine a un domaine deja existant
try {
    Write-Host -ForegroundColor Yellow "Promotion du serveur en tant que Controleur de Domaine a un domaine deja existant EN COURS..."

    Install-ADDSDomainController `
        -DomainName $DomainAddress `
        -Credential $AdminCredential `
        -SafeModeAdministratorPassword $AdminPasswordPlainText `
        -InstallDns:$true `
        -Force `
        -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de la promotion du serveur en tant que Controleur de Domaine a un domaine deja existant : [$_]"
    exit
}

Write-Host -ForegroundColor Green "PROMOTION A UN DOMAINE DEJA EXISTANT TERMINEE ! Veuillez redemarrer le serveur pour appliquer les modifications et finaliser la configuration du contrôleur de domaine (s'il ne se redemarre pas automatiquement)."
