# Importer le module Active Directory
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de l'importation du module Active Directory : [$_]"
    exit
}

# Chargement de l'assembly "Microsoft.VisualBasic" pour le InputDialog
try {
    Add-Type -AssemblyName Microsoft.VisualBasic
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors du chargement de l'assembly 'Microsoft.VisualBasic' : [$_]"
    exit
}

# Chargement de l'assembly "System.Windows.Forms" pour le SaveFileDialog
try {
    Add-Type -AssemblyName System.Windows.Forms
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors du chargement de l'assembly 'System.Windows.Forms' : [$_]"
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

# Setup du SaveFileDialog pour les users (pop up pour enregistrer un fichier)
try {
    $saveFileDialogUsers = New-Object System.Windows.Forms.SaveFileDialog -ErrorAction Stop
    $saveFileDialogUsers.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $saveFileDialogUsers.Filter = "CSV Files (*.csv)|*.csv"
    $saveFileDialogUsers.Title = "Save CSV File"
    $saveFileDialogUsers.FileName = "AD_Domolia_Users.csv"
    $resultUsers = $saveFileDialogUsers.ShowDialog()

    if ($resultUsers -eq [System.Windows.Forms.DialogResult]::OK) {
        $PathUsers = $saveFileDialogUsers.FileName
    } else {
        Write-Host -ForegroundColor Red "Aucun chemin de fichier spécifié. Arret du script."
        exit
    }

    Write-Host -ForegroundColor Cyan "Emplacement de la sauvegarde : [$Path]"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de la creation du SaveFileDialog : [$_]"
    exit
}

# Setup du SaveFileDialog pour les groups (pop up pour enregistrer un fichier)
try {
    $saveFileDialogGroups = New-Object System.Windows.Forms.SaveFileDialog -ErrorAction Stop
    $saveFileDialogGroups.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $saveFileDialogGroups.Filter = "CSV Files (*.csv)|*.csv"
    $saveFileDialogGroups.Title = "Save CSV File for Groups"
    $saveFileDialogGroups.FileName = "AD_Domolia_Groups.csv"
    $resultGroups = $saveFileDialogGroups.ShowDialog()

    if ($resultGroups -eq [System.Windows.Forms.DialogResult]::OK) {
        $PathGroups = $saveFileDialogGroups.FileName
    } else {
        Write-Host -ForegroundColor Red "Aucun chemin de fichier spécifié pour les groupes. Arrêt du script."
        exit
    }

    Write-Host -ForegroundColor Cyan "Emplacement de la sauvegarde pour les groupes : [$PathGroups]"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de la création du SaveFileDialog pour les groupes : [$_]"
    exit
}

$AcceptedDelimiters = @(',', ';', ':', '|', '.', '-')
# Pop up pour obtenir le delimiteur
try {
    $Delimiter = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le délimiteur pour le fichier CSV (par exemple, ',' pour une virgule)", "Delimiter Input", ",")

    if ([string]::IsNullOrWhiteSpace($Delimiter)) {
        Write-Host -ForegroundColor Red "Aucun délimiteur spécifié. Arret du script."
        exit
    } elseif ($AcceptedDelimiters -notcontains $Delimiter) {
        Write-Host -ForegroundColor Red "Veuillez choisir un delimiteur parmis ceux acceptes : [, ; : | . -]"
        exit
    }

    Write-Host -ForegroundColor Cyan "Delimiteur pour le fichier de sauvegarde .CSV : [$Delimiter]"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de l'obtention du delimiteur : [$_]"
    exit
}

# Pop up pour obtenir les attributs des utilisateurs à enregistrer
try {
    $UserAttributesInput = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez les attributs des utilisateurs à inclure dans le fichier CSV, séparés par des virgules (par exemple, 'Name,SamAccountName,EmailAddress')", "User Attributes Input", "Name,SamAccountName,EmailAddress")
    if ([string]::IsNullOrWhiteSpace($UserAttributesInput)) {
        Write-Host -ForegroundColor Red "Aucun attribut des utilisateurs spécifié. Arrêt du script."
        exit
    }
    $UserAttributes = $UserAttributesInput -split ','
    Write-Host -ForegroundColor Cyan "Attributs des utilisateurs à inclure dans le fichier CSV : [$UserAttributesInput]"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de l'obtention des attributs des utilisateurs : [$_]"
    exit
}

# Pop up pour obtenir les attributs des groupes à enregistrer
try {
    $GroupAttributesInput = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez les attributs des groupes à inclure dans le fichier CSV, séparés par des virgules (par exemple, 'Name,SamAccountName,GroupScope')", "Group Attributes Input", "Name,SamAccountName,GroupScope")
    if ([string]::IsNullOrWhiteSpace($GroupAttributesInput)) {
        Write-Host -ForegroundColor Red "Aucun attribut des groupes spécifié. Arrêt du script."
        exit
    }
    $GroupAttributes = $GroupAttributesInput -split ','
    Write-Host -ForegroundColor Cyan "Attributs des groupes à inclure dans le fichier CSV : [$GroupAttributesInput]"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de l'obtention des attributs des groupes : [$_]"
    exit
}

# Obtenir les utilisateurs et les exporter vers un fichier CSV
try {
    Write-Host -ForegroundColor Yellow "Exportation des utilisateur avec les attributs '$UserAttributesInput' EN COURS..."

    # Get all users
    $users = Get-ADUser -Filter * -Property $UserAttributes -ErrorAction Stop | Select-Object $UserAttributes

    # Export users to CSV
    $users | Export-Csv -Path $PathUsers -Delimiter $Delimiter -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    Write-Host -ForegroundColor Green "Les utilisateurs ont été exportés avec succès vers $PathUsers"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de l'exportation des utilisateurs vers le fichier CSV : [$_]"
    exit
}

# Obtenir les groupes et les exporter vers un fichier CSV
try {
    Write-Host -ForegroundColor Yellow "Exportation des groupes avec les attributs '$GroupAttributesInput' EN COURS..."

    # Get all groups
    $groups = Get-ADGroup -Filter * -Property $GroupAttributes -ErrorAction Stop | Select-Object $GroupAttributes

    # Export groups to CSV
    $groups | Export-Csv -Path $PathGroups -Delimiter $Delimiter -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    Write-Host -ForegroundColor Green "Les groupes ont été exportés avec succès vers $PathGroups"
} catch {
    Write-Host -ForegroundColor Red "Fatal Error. Erreur lors de l'exportation des groupes vers le fichier CSV : [$_]"
    exit
}

Write-Host -ForegroundColor Green -BackgroundColor DarkCyan "Les utilisateurs ainsi que les groupes du AD ont ete enregistres avec succes !"
