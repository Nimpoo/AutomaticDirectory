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

# Take the firstname
try {
    $FirstName = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le prenom du futur utilisateur", "User Creation", "Zoro")
    if ([string]::IsNullOrWhiteSpace($FirstName)) {
        Write-Host -ForegroundColor Red "Le prenom ne peut pas etre vide (ou qu'avec des whitespaces)."
        exit
    }

    # Vérification que le prenom ne contient que des lettres
    if (-not ($FirstName -match '^[a-zA-Z]+$')) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le prenom ne doit contenir que des lettres."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GivenName : [$FirstName]"
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Take the lastname
try {
    $LastName = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du futur utilisateur", "User Creation", "Roronoa")
    if ([string]::IsNullOrWhiteSpace($LastName)) {
        Write-Host -ForegroundColor Red "Le nom ne peut pas etre vide (ou qu'avec des whitespaces)."
        exit
    }

    # Vérification que le nom ne contient que des lettres
    if (-not ($LastName -match '^[a-zA-Z]+$')) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le nom ne doit contenir que des lettres."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SurName : [$LastName]"
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$LastName $FirstName]"

# The Email
try {
    $DomainName = (Get-ADDomain -ErrorAction Stop).DNSRoot
    $localPart = "$FirstName.$LastName".ToLower()
    if ($localPart.Length -gt 20) {
        $localPart = $localPart.Substring(0, 20)
    }
    $Email = "$localPart@$DomainName"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "EmailAddress : [$Email]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la création du mail de l'utilisateur : [$_]"
    exit
}

# SamAccountName
try {
    $SamAccountName = (($FirstName.Substring(0, 1)) + $LastName).ToLower()
    if ($SamAccountName.Length -gt 20) {
        $SamAccountName = $SamAccountName.Substring(0, 20)
    }
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$SamAccountName]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la creation du SamAccountName : [$_]"
    exit
}

# Vérification de l'existence de l'utilisateur
try {
    $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction Stop
    if ($ExistingUser) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Un utilisateur avec le même SamAccountName existe déjà."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de l'existence de l'utilisateur : [$_]"
    exit
}

# UserPrincipalName
try {
    $UserPrincipalName = $Email
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "UserPrincipalName : [$UserPrincipalName]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la creation du UserPrincipalName : [$_]"
    exit
}

# The Password
try {
    $Password = Read-Host -AsSecureString -Prompt "Entrez un password pour l'utilisateur $FirstName $LastName." -ErrorAction Stop
    if ($Password -eq $null -or $Password.Length -eq 0) {
        Write-Host -ForegroundColor Red "Le password ne peut pas etre vide."
        exit
    }
    try {
        if (-not (Test-PasswordCompliance -Password $Password)) {
            exit
        }
    } catch {
        Write-Host -ForegroundColor Red "Erreur lors de l'execution de la fonction 'Test-PasswordCompliance' : [$_]"
        exit
    }

    $PasswordPlaintext = ConvertTo-SecureString $Password -AsPlaintext -Force -ErrorAction Stop
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCy "AccountPassword :[******]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la creation d'un mot de passe : [$_]"
    exit
}

# Demande de l'unité d'organisation (OU)
try {
    $OrganizationalUnit = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez l'unité d'organisation (OU) à rejoindre", "User Creation", "Domain Controllers")
    if ([string]::IsNullOrWhiteSpace($OrganizationalUnit)) {
        Write-Host -ForegroundColor Red "L'unité d'organisation ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Organisation Unit : [$OrganizationalUnit]"
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Vérification de l'existence de l'unité d'organisation (OU)
try {
    $OU = Get-ADOrganizationalUnit -Filter "Name -eq '$OrganizationalUnit'" -ErrorAction Stop
    if (-not $OU) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "L'unité d'organisation spécifiée n'existe pas."
        exit
    }

    $OUDistinguishedName = $OU.DistinguishedName
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Path : [$OUDistinguishedName]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de l'unité d'organisation : [$_]"
    exit
}

Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Enabled : [$true]"
Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "PasswordNeverExpired : [$false]"
Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "ChangePasswordAtLogon : [$true]"

# Demande du groupe souhaité
try {
    $DesiredGroup = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le groupe souhaité", "User Creation", "Domain Users")
    if ([string]::IsNullOrWhiteSpace($DesiredGroup)) {
        Write-Host -ForegroundColor Red "Le groupe ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Fatal error. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Vérification de l'existence du groupe
try {
    $Group = Get-ADGroup -Filter "Name -eq '$DesiredGroup'" -ErrorAction Stop
    if (-not $Group) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le groupe spécifié n'existe pas."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "Group to join : [$DesiredGroup]"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification du groupe : [$_]"
    exit
}

# Création de l'utilisateur dans Active Directory
try {
    Write-Host -ForegroundColor Yellow "Creation de l'utilisateur '$FirstName $LastName' EN COURS..."

    New-ADUser -Name "$FirstName $LastName" `
               -GivenName $FirstName `
               -Surname $LastName `
               -SamAccountName $SamAccountName `
               -UserPrincipalName $UserPrincipalName `
               -Path $OU.DistinguishedName `
               -AccountPassword $Password `
               -Enabled $true `
               -PasswordNeverExpires $false `
               -ChangePasswordAtLogon $true `
               -EmailAddress $Email `
               -ErrorAction Stop

    Write-Host -ForegroundColor Green "Utilisateur créé avec succès."
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la création de l'utilisateur : [$_]"
    exit
}

# Ajout de l'utilisateur au groupe spécifié
try {
    Write-Host -ForegroundColor Yellow "Ajout de l'utilisateur '$FirstName $LastName' dans le groupe '$DesiredGroup' EN COURS..."

    # Vérification si l'utilisateur est déjà membre du groupe
    $IsMember = Get-ADGroupMember -Identity $DesiredGroup | Where-Object { $_.SamAccountName -eq $SamAccountName }

    if ($IsMember) {
        Write-Host -ForegroundColor Cyan "L'utilisateur '$FirstName $LastName' est déjà membre du groupe '$DesiredGroup'."
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "L'utilisateur '$FirstName $LastName' a été créé dans le domaine '$DomainName' et etait deja dans le groupe '$DesiredGroup' avec SUCCÈS !"
    } else {
        Add-ADGroupMember -Identity $DesiredGroup -Members $SamAccountName -ErrorAction Stop
        Write-Host -ForegroundColor Green "Utilisateur ajouté au groupe avec succès."
        Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "L'utilisateur '$FirstName $LastName' a été créé dans le domaine '$DomainName' et a été ajouté au groupe '$DesiredGroup' avec SUCCÈS !"
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'ajout de l'utilisateur au groupe : [$_]"
    exit
}
