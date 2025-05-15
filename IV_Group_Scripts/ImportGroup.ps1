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

# Nom du groupe origin
try {
    $GroupNameOrigin = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du groupe d'origine a importer.", "Import Group", "Informatique")
    if ([string]::IsNullOrWhiteSpace($GroupNameOrigin)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le nom du groupe ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check si le groupe existe
try {
    $ExistingGroupOrigin = Get-ADGroup -Filter "Name -eq '$GroupNameOrigin'" -Properties * -ErrorAction Stop
    if (-not $ExistingGroupOrigin) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le groupe '$GroupNameOrigin' n'existe pas."
        exit
    }
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$($ExistingGroupOrigin.Name)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$($ExistingGroupOrigin.SamAccountName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Path : [$($ExistingGroupOrigin.DistinguishedName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GroupScope : [$($ExistingGroupOrigin.GroupScope)]`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Description :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "$($ExistingGroupOrigin.Description)`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkYellow "Members :"
    $GroupMembersOrigin = Get-ADGroupMember -Identity $ExistingGroupOrigin.SamAccountName -ErrorAction Stop
    foreach ($Member in $GroupMembersOrigin) {
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkYellow "- $($Member.Name)"
    }
    Write-Host ""

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "PropertyNames :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "$($ExistingGroupOrigin.PropertyNames)`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkBlue "-------------------------------------------------------------------`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de l'existence du groupe : [$_]"
    exit
}

# Nom du groupe destination
try {
    $GroupNameDestination = [Microsoft.VisualBasic.Interaction]::InputBox("Entrez le nom du groupe de destination ou sera importe le groupe '$($ExistingGroupOrigin.Name)' ('$($ExistingGroupOrigin.SamAccountName)').", "Import Group", "Workshop")
    if ([string]::IsNullOrWhiteSpace($GroupNameDestination)) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le nom du groupe ne peut pas être vide (ou ne contenir que des espaces)."
        exit
    }
} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}

# Check si le groupe existe
try {
    $ExistingGroupDestination = Get-ADGroup -Filter "Name -eq '$GroupNameDestination'" -Properties * -ErrorAction Stop
    if (-not $ExistingGroupDestination) {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Le groupe '$GroupNameDestination' n'existe pas."
        exit
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Name : [$($ExistingGroupDestination.Name)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "SamAccountName : [$($ExistingGroupDestination.SamAccountName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "Path : [$($ExistingGroupDestination.DistinguishedName)]"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkCyan "GroupScope : [$($ExistingGroupDestination.GroupScope)]`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "Description :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGray "$($ExistingGroupDestination.Description)`n"

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkYellow "Members :"
    $GroupMembersDestination = Get-ADGroupMember -Identity $ExistingGroupDestination.SamAccountName -ErrorAction Stop
    foreach ($Member in $GroupMembersDestination) {
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkYellow "- $($Member.Name)"
    }
    Write-Host ""

    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "PropertyNames :"
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkMagenta "$($ExistingGroupDestination.PropertyNames)`n"
} catch {
    Write-Host -ForegroundColor Red "Erreur lors de la vérification de l'existence du groupe : [$_]"
    exit
}

# Importation du groupe d'origine a u groupe de destination
try {
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkRed "Le groupe '$($ExistingGroupOrigin.Name)' ($($ExistingGroupOrigin.SamAccountName)) s'apprete a etre importer dans le groupe '$($ExistingGroupDestination.Name)' ($($ExistingGroupDestination.SamAccountName)).`n"
    $confirmation = [Microsoft.VisualBasic.Interaction]::MsgBox("Voulez-vous importer le groupe '$($ExistingGroupOrigin.Name)' ($($ExistingGroupOrigin.SamAccountName)) au groupe '$($ExistingGroupDestination.Name)' ($($ExistingGroupDestination.SamAccountName)) ?", 4 + 32, "Confirmation")
    if ($confirmation -ne 6) {  # 6 correspond à "Yes" dans MsgBox
        Write-Host -ForegroundColor Yellow -BackgroundColor DarkYellow "Opération annulée par l'utilisateur."
        exit
    }

    $ErrorNumber = 0
    foreach ($Member in $GroupMembersOrigin) {
        try {
            # Vérifier si le membre est déjà dans le groupe de destination
            $IsMemberPresent = Get-ADGroupMember -Identity $ExistingGroupDestination.SamAccountName | Where-Object { $_.SamAccountName -eq $Member.SamAccountName }

            if ($IsMemberPresent) {
                Write-Host -ForegroundColor Yellow "L'utilisateur '$($Member.Name)' ($($Member.SamAccountName)) est déjà présent dans le groupe '$($ExistingGroupDestination.Name)' ($($ExistingGroupDestination.SamAccountName))."
                continue
            }

            Add-ADGroupMember `
            -Identity $ExistingGroupDestination.SamAccountName `
            -Members $Member.SamAccountName `
            -ErrorAction Stop

            Write-Host -ForegroundColor Green "L'utilisateur '$($Member.Name)' ($($Member.SamAccountName)) a été ajouté avec succès au groupe '$($ExistingGroupDestination.Name)' ($($ExistingGroupDestination.SamAccountName))."
        } catch {
            Write-Host -ForegroundColor Red "Erreur lors de l'ajout de l'utilisateur '$($Member.Name)' ($($Member.SamAccountName)) au groupe : [$_]"
            $ErrorNumber += 1
        }
    }

    Write-Host -ForegroundColor Green -BackgroundColor DarkGreen "L'ajout des membres du groupe '$($ExistingGroupOrigin.Name)' ($($ExistingGroupOrigin.SamAccountName)) au groupe '$($ExistingGroupDestination.Name)' ($($ExistingGroupDestination.SamAccountName)) est TERMINE avec [ $ErrorNumber ] erreur rencontre.`n"

    $GroupMembersDestinationUpdate = Get-ADGroupMember -Identity $ExistingGroupDestination.SamAccountName -ErrorAction Stop
    Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "Mise a jour des membres du groupe '$($ExistingGroupDestination.Name)' ($($ExistingGroupDestination.SamAccountName)) :"
    foreach ($Member in $GroupMembersDestinationUpdate) {
        Write-Host -ForegroundColor Cyan -BackgroundColor DarkGreen "- $($Member.Name)"
    }

} catch {
    Write-Host -ForegroundColor Red "Erreur fatale. Erreur lors de l'ouverture de la pop-up : [$_]"
    exit
}
