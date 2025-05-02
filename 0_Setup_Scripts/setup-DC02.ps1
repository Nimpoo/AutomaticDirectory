# Désactivation de DHCP
try {
    Set-NetIPInterface -InterfaceIndex 5 -Dhcp Disabled -ErrorAction Stop
    Write-Output "DHCP désactivé sur l'interface 5."
} catch {
    Write-Output "Erreur lors de la désactivation de DHCP : $_"
}

# Configuration du serveur DNS sur le Domain Controller (DC02)
try {
    Set-DnsClientServerAddress -InterfaceIndex 5 -ServerAddresses 192.168.1.20 -ErrorAction Stop
    Write-Output "Serveur DNS configuré sur 192.168.1.20 pour l'interface 5."
} catch {
    Write-Output "Erreur lors de la configuration du serveur DNS : [$_]"
}

# Suppression des adresses IP existantes (si elles existent)
try {
    $existingIPs = Get-NetIPAddress -InterfaceIndex 5 -ErrorAction SilentlyContinue
    if ($existingIPs) {
        $existingIPs | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        Write-Output "Adresse IP dans l'interface 5 supprimée."
    } else {
        Write-Output "Aucune adresse IP existante à supprimer."
    }
} catch {
    Write-Output "Erreur lors de la suppression des adresses IP de l'interface 5 : [$_]"
}

# Ajouter une nouvelle adresse IP
try {
    New-NetIPAddress -InterfaceIndex 5 -IPAddress 192.168.1.21 -PrefixLength 24 -ErrorAction Stop
    Write-Output "Nouvelle adresse IP 192.168.1.21 créée pour l'interface 5."
} catch {
    Write-Output "Erreur lors de l'attribution d'une nouvelle adresse IP à l'interface 5 : [$_]"
}

# Supprimer la route par défaut existante (si elle existe)
try {
    $defaultRoute = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue
    if ($defaultRoute) {
        $defaultRoute | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        Write-Output "Actuelle default gateway supprimée."
    } else {
        Write-Output "Aucune default gateway à supprimer."
    }
} catch {
    Write-Output "Erreur lors de la suppression de la default gateway : [$_]"
}

# Ajouter une nouvelle route par défaut
try {
    New-NetRoute -InterfaceIndex 5 -NextHop 192.168.1.1 -DestinationPrefix 0.0.0.0/0 -ErrorAction Stop
    Write-Output "Création d'une nouvelle default gateway à 192.168.1.1 sur l'interface 5."
} catch {
    Write-Output "Erreur lors de l'ajout d'une nouvelle default gateway : [$_]"
}
