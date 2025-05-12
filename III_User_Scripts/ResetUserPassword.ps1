######################################################################################################
# Function to validate password against common policy rules
function Test-PasswordCompliance {
    param (
        [SecureString]$Password
    )

    # Récupération des paramètres de la stratégie de mot de passe du domaine
    try {
        $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    } catch {
        Write-Host -ForegroundColor Red "Erreur lors de la récupération de la stratégie de mot de passe dans la fonction 'Test-PasswordCompliance' : [$_]"
        exit
    }

    $passwordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    )

    # Vérification de la longueur minimale
    if ($passwordText.Length -lt $PasswordPolicy.MinPasswordLength) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le mot de passe ne respecte pas la longueur minimale requise."
        return $false
    }

    # Vérification de la complexité
    $hasUpper = $passwordText -match '[A-Z]'
    $hasLower = $passwordText -match '[a-z]'
    $hasDigit = $passwordText -match '[0-9]'
    $hasSpecial = $passwordText -match '[^A-Za-z0-9]'

    if (-not ($hasUpper -and $hasLower -and ($hasDigit -or $hasSpecial))) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le mot de passe ne respecte pas les exigences de complexité."
        return $false
    }
    return $true
}
######################################################################################################

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

# L'utilisateur dont le password va etre reset
try {
    $User = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le 'SamAccountName' de l'utilisateur dont vous voulez reset le password. ('SamAccountName' = premiere lettre du 'GivenName' suivi du 'Surname' (prenom puis nom de famille) en minuscule. Exemple : 'Zoro Roronoa' -> 'SamAccountName' = 'zroronoa')", "Reste User Password", "zroronoa")
    if ([string]::IsNullOrWhiteSpace($User)) {
        Write-Host -ForegroundColor Red "Le 'SamAccountName' ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check de l'existance du user
try {
    $ExistingUser = Get-ADUser -Identity $User -ErrorAction Stop
    if (-not $ExistingUser) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'utilisateur '$User' n'existe pas."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GivenName : [$($ExistingUser.GivenName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Surname : [$($ExistingUser.Surname)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$($ExistingUser.Name)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$($ExistingUser.SamAccountName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "UserPrincipalName : [$($ExistingUser.UserPrincipalName)]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la verification de l'existance de l'utilisateur : [$_]"
    exit
}

# Taper le nouveau password
try {
    $NewPassword = Read-Host -AsSecureString -Prompt "Entrez le nouveau password desire pour l'utilisateur '$($ExistingUser.Name)' ." -ErrorAction Stop
    if ($NewPassword -eq $null -or $NewPassword.Length -eq 0) {
        Write-Host -ForegroundColor Red "Le password ne peut pas etre vide."
        exit
    }
    try {
        if (-not (Test-PasswordCompliance -Password $NewPassword)) {
            exit
        }
    } catch {
        Write-Host -ForegroundColor Red "Erreur lors de l'execution de la fonction 'Test-PasswordCompliance' : [$_]"
        exit
    }

    $NewPasswordPlaintext = ConvertTo-SecureString $NewPassword -AsPlaintext -Force -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Reset du password
try {
    Set-ADAccountPassword `
        -Identity $ExistingUser `
        -Reset `
        -NewPassword $NewPasswordPlaintext `
        -ErrorAction Stop

    Set-ADUser `
        -Identity $ExistingUser.SamAccountName `
        -ChangePasswordAtLogon $true `
        -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Erreur lors du reset du password : [$_]"
    exit
}

Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "Le password de l'utilisateur $($ExistingUser.Name + ' ' + $ExistingUser.GivenName + '(' + $ExistingUser.SamAccountName + ')') a ete reset avec succes ! Il devra changer son password a sa prochaine reconnection."
