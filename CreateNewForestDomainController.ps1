######################################################################################################
# Function to validate password against common policy rules
function Test-PasswordPolicy {
    param (
        [SecureString]$Password
    )

    # Convert SecureString to plain text for validation
    $plainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

    # Define password policy rules
    $minLength = 8
    $hasUpperCase = $plainTextPassword -match '[A-Z]'
    $hasLowerCase = $plainTextPassword -match '[a-z]'
    $hasDigit = $plainTextPassword -match '\d'
    $hasSpecialChar = $plainTextPassword -match '[^a-zA-Z0-9]'

    # Check password against policy rules
    if ($plainTextPassword.Length -lt $minLength) {
        Write-Host -ForegroundColor Red "Le mot de passe doit contenir au moins $minLength caractères."
        return $false
    }
    if (-not $hasUpperCase) {
        Write-Host -ForegroundColor Red "Le mot de passe doit contenir au moins une lettre majuscule."
        return $false
    }
    if (-not $hasLowerCase) {
        Write-Host -ForegroundColor Red "Le mot de passe doit contenir au moins une lettre minuscule."
        return $false
    }
    if (-not $hasDigit) {
        Write-Host -ForegroundColor Red "Le mot de passe doit contenir au moins un chiffre."
        return $false
    }
    if (-not $hasSpecialChar) {
        Write-Host -ForegroundColor Red "Le mot de passe doit contenir au moins un caractère spécial."
        return $false
    }

    return $true
}
######################################################################################################

# Check if AD DS is already installed
$IsInstalled = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop

try {
    if (-not $IsInstalled.Installed) {
        Write-Host -ForegroundColor Yellow "AD DS n'est pas installe. Veuillez installer AD DS avant de promouvoir ce serveur en tant que controlleur de domaine (ADPackageInstallor.ps1)."
        exit
    }
    Write-Host -ForegroundColor Green "AD DS est bien installe dans le serveur."
} catch {
    Write-Host -ForegroundColor Red "Erreur lors du check de AD DS : [$_]"
}

# Charger l'assembly Microsoft.VisualBasic pour pouvoir ouvrir des pop-ups
try {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors du chargement de l'assembly 'Microsoft.VisualBasic' : [$_]"
}

# Pop-up ouverte pour taper le nom du Controlleur de Domain
try {
    $DomainAddress = [Microsoft.VisualBasic.Interaction]::InputBox("Choose a Domain Name (exemple: nimpo.local)", "Domain Controller Promotion", "domolia.local")
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
}

# Pop-up ouverte pour taper le Netbios name
try {
    $NetbiosName = [Microsoft.VisualBasic.Interaction]::InputBox("Choose a Netbios Name (exemple: NIMPO)", "Domain Controller Promotion", "DOMOLIA")
    if ([string]::IsNullOrWhiteSpace($NetbiosName)) {
        Write-Host -ForegroundColor Red "Le Netbios name ne peut pas etre vide (ou qu'avec des whitespaces)."
        exit
    }
    if ($NetbiosName -cne $NetbiosName.ToUpper()) {
        Write-Host -ForegroundColor Red "Le Netbios name doit être entièrement en majuscules."
        exit
    }
        if ($NetbiosName -match '\d') {
        Write-Host -ForegroundColor Red "Le Netbios name ne doit pas contenir de chiffres."
        exit
    }

    Write-Host -ForegroundColor Cyan "Le Netbios name : [$NetbiosName]"
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
}

# Pop-up ouverte pour taper le SafeModePassword
try {
    $DSRMPW = Read-Host -AsSecureString -Prompt "Enter the DSRM password (Directory Services Restore Mode)"
    if ($DSRMPW -eq $null -or $DSRMPW.Length -eq 0) {
        Write-Host -ForegroundColor Red "Le password ne peut pas etre vide."
        exit
    }
    if (-not (Test-PasswordPolicy -Password $DSRMPW)) {
        exit
    }

    $DSRMPWPlainText = ConvertTo-SecureString $DSRMPW -AsPlaintext -Force -ErrorAction Stop

    Write-Host -ForegroundColor Cyan "Le password respecte les politiques de mot de passe."

} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
}

try {
    Write-Host -ForegroundColor Yellow "Promotion du serveur en tant que controlleur de domaine EN COURS..."

    Install-ADDSForest `
        -CreateDnsDelegation:$CreateDnsDelegation `
        -DomainName $DomainAddress `
        -DomainNetbiosName $NetbiosName `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -DomainMode "WinThreshold" `
        -InstallDns:$true `
        -ForestMode "WinThreshold" `
        -NoRebootOnCompletion:$false `
        -SafeModeAdministratorPassword $DSRMPWPlainText `
        -Force:$true
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de la promotion du serveur en tant que controlleur de domaine : [$_]"
}

Write-Host -ForegroundColor Green "PROMOTION TERMINE ! Veuillez redemarrer le serveur pour appliquer les modifications et finaliser la configuration du contrôleur de domaine."

