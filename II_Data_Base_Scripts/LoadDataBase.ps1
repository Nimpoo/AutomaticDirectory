# Chargement de l'assembly "Microsoft.VisualBasic" pour le InputDialog
try {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors du chargement de l'assembly 'Microsoft.VisualBasic' : [$_]"
}

# Chargement de l'assembly "System.Windows.Forms" pour le SaveFileDialog
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors du chargement de l'assembly 'System.Windows.Forms' : [$_]"
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

# Setup du OpenFileDialog pour charger le fichier CSV
try {
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog -ErrorAction Stop
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $openFileDialog.Filter = "CSV Files (*.csv)|*.csv"
    $openFileDialog.Title = "Load CSV File (with the extension '_Users.csv' or '_Groups.csv')"
    $result = $openFileDialog.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $Path = $openFileDialog.FileName
    } else {
        Write-Host -ForegroundColor Red "Aucun chemin de fichier spécifié. Arrêt du script."
        exit
    }

    Write-Host -ForegroundColor Cyan "Chemin du fichier CSV a charger : [$Path]"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de la création du OpenFileDialog : [$_]"
    exit
}

$AcceptedDelimiters = @(',', ';', ':', '|', '.', '-')
# Pop up pour obtenir le délimiteur
try {
    $Delimiter = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le délimiteur qu'il y a dans '$Path' pour que le fichier CSV soit correctement lu (par exemple, ',' pour une virgule)", "Delimiter Input of the CSV file to load", ",")

    if ([string]::IsNullOrWhiteSpace($Delimiter)) {
        Write-Host -ForegroundColor Red "Aucun délimiteur spécifié. Arrêt du script."
        exit
    } elseif ($AcceptedDelimiters -notcontains $Delimiter) {
        Write-Host -ForegroundColor Red "Veuillez choisir un délimiteur parmi ceux acceptés ET corresspondant au fichier CSV que vous selectionnez : [, ; : | . -]"
        exit
    }

    Write-Host -ForegroundColor Cyan "Délimiteur pour le fichier CSV a charger : [$Delimiter]"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de l'obtention du délimiteur : [$_]"
    exit
}

# Vérification du délimiteur
try {
    $firstLine = Get-Content -Path $Path -First 1 -ErrorAction Stop
    $detectedDelimiter = $firstLine | Select-String -Pattern "[,;:|.\-]" -ErrorAction Stop | ForEach-Object { $_.Matches.Value } -ErrorAction Stop

    if ($detectedDelimiter -ne $Delimiter) {
        Write-Host -ForegroundColor Red "Le délimiteur spécifié ne correspond pas au délimiteur détecté dans le fichier CSV et ne peut donc pas etre lu correctement. Délimiteur détecté : [$detectedDelimiter]"
        exit
    }

    Write-Host -ForegroundColor Green "Le délimiteur spécifié correspond au délimiteur détecté dans le fichier CSV."
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de la vérification du délimiteur : [$_]"
    exit
}

# Lire le fichier CSV
try {
    Write-Host -ForegroundColor Yellow "Chargement du fichier '$Path' EN COURS..."
    $csvData = Import-Csv -Path $Path -Delimiter $Delimiter -ErrorAction Stop

    Write-Host -ForegroundColor Green -BackgroundColor DarkCyan "Le fichier CSV '$Path' est chargé avec succès."
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors du chargement du fichier CSV : [$_]"
    exit
}

# Vérifier l'extension du fichier pour déterminer s'il s'agit d'un fichier d'utilisateurs ou de groupes
if ($Path -match "_Users\.csv$") {
    $objectType = "User"
    $ouPath = "CN=Users,DC=domolia,DC=local"
} elseif ($Path -match "_Groups\.csv$") {
    $objectType = "Group"
    $ouPath = "CN=Users,DC=domolia,DC=local"
} else {
    Write-Host -ForegroundColor Red "Le type d'objet ne peut pas être déterminé à partir de l'extension du fichier. Arrêt du script."
    exit
}

# Importer le module Active Directory
Import-Module ActiveDirectory

# Importer les utilisateurs et les groupes dans Active Directory
try {
    foreach ($item in $csvData) {
        if ($objectType -eq "User") {

            # Verification de l'existance de l'utilisateur dans l'Active Directory
            $var = $item.SamAccountName
            $existingUser = Get-ADUser -Filter { SamAccountName -eq $var } -ErrorAction SilentlyContinue
            if ($existingUser) {
                Write-Host -ForegroundColor Yellow "L'utilisateur avec SamAccountName '$($item.SamAccountName)' existe déjà."
                continue
            }

            # Créer un utilisateur
            New-ADUser `
                -Name $item.Name `
                -SamAccountName $item.SamAccountName `
                -GivenName $item.GivenName `
                -Surname $item.Surname `
                -EmailAddress $item.EmailAddress `
                -UserPrincipalName $item.UserPrincipalName `
                -Path $ouPath `
                -AccountPassword (ConvertTo-SecureString "TotallyN0tSecure" -AsPlainText -Force) `
                -PasswordNeverExpires $true `
                -ChangePasswordAtLogon $false `
                -Enabled $true `
                -ErrorAction Stop

            Write-Host -ForegroundColor Green -BackgroundColor DarkGray "Utilisateur créé : $($item.Name)"
        } elseif ($objectType -eq "Group") {


            # Verification de l'existance du groupe dans l'Active Directory
            $var = $item.SamAccountName
            $existingUser = Get-ADGroup -Filter { SamAccountName -eq $var } -ErrorAction SilentlyContinue
            if ($existingUser) {
                Write-Host -ForegroundColor Yellow "L'utilisateur avec SamAccountName '$($item.SamAccountName)' existe déjà."
                continue
            }

            # Créer un groupe
            New-ADGroup `
                -Name $item.Name `
                -SamAccountName $item.SamAccountName `
                -GroupScope $item.GroupScope `
                -Path $ouPath `
                -ErrorAction Stop

            Write-Host -ForegroundColor Green -BackgroundColor DarkGray "Groupe créé : $($item.Name)"
        } else {
            Write-Host -ForegroundColor Yellow "Type d'objet non reconnu : $($item.ObjectType)"
        }
    }
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de l'importation des utilisateurs et des groupes : [$_]"
    exit
}

Write-Host -ForegroundColor Green -BackgroundColor DarkCyan "Importation des utilisateurs et/ou des groupes terminée avec succès !"
