# Desactivation de DHCP
try {
    Set-NetIPInterface -InterfaceIndex 15 -Dhcp Disabled -ErrorAction Stop
    Write-Output "DHCP desactive sur l'interface 15."
} catch {
    Write-Output "Erreur lors de la desactivation de DHCP : $_"
}

# Configuration du serveur DNS
try {
    Set-DnsClientServerAddress -InterfaceIndex 15 -ServerAddresses 127.0.0.1 -ErrorAction Stop
    Write-Output "Serveur DNS configuré sur 127.0.0.1 pour l'interface 15."
} catch {
    Write-Output "Erreur lors de la configuration du serveur DNS : [$_]"
}

# Suppression des adresses IP existantes (si elles existent)
try {
    $existingIPs = Get-NetIPAddress -InterfaceIndex 15 -ErrorAction SilentlyContinue
    if ($existingIPs) {
        $existingIPs | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        Write-Output "Adresse IP dans l'interface 15 supprimee."
    } else {
        Write-Output "Aucune adresse IP existant a supprimer."
    }
} catch {
    Write-Output "Erreur lors de la suppression des adresses IP de l'interface 15 [$_]"
}

# Ajouter une nouvelle adresse IP
try {
    New-NetIPAddress -InterfaceIndex 15 -IPAddress 192.168.1.20 -PrefixLength 24 -ErrorAction Stop
    Write-Output "Nouvelle adresse IP 192.168.1.20 creee pour l'interface 15."
} catch {
    Write-Output "Erreur lors de l'attribution d'une nouvelle adresse IP a l'interface 15 : [$_]"
}

# Supprimer la route par défaut existante (si elle existe)
try {
    $defaultRoute = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue
    if ($defaultRoute) {
        $defaultRoute | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        Write-Output "Actuelle default Gateway supprime."
    } else {
        Write-Output "Aucune default gateway a supprimer."
    }
} catch {
    Write-Output "Erreur lors de la suppression de la default gateway : [$_]"
}

# Ajouter une nouvelle route par defaut
try {
    New-NetRoute -InterfaceIndex 15 -NextHop 192.168.1.1 -DestinationPrefix 0.0.0.0/0 -ErrorAction Stop
    Write-Output "Creation d'une nouvelle default gateway a 192.168.1.1 a l'interface 15"
} catch {
    Write-Output "Erreur lors de l'ajout d'une nouvelle default gateway : [$_]"
}

