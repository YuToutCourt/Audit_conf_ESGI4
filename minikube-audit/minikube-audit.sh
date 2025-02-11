#!/bin/bash

# Fonction pour afficher l'ASCII art du titre
function display_ascii_art() {
    echo "  _   _           _        _____            _     "
    echo " | \ | | ___   __| |_ __  | ____|_ __   ___| |___ "
    echo " |  \| |/ _ \ / _\` | '__| |  _| | '_ \ / _ \ / __|"
    echo " | |\  | (_) | (_| | |    | |___| |_) |  __/ \__ \\"
    echo " |_| \_|\___/ \__,_|_|    |_____| .__/ \___|_|___/"
    echo "                               |_|               "
    echo ""
    echo "Bienvenue dans l'outil d'audit Kubernetes pour Minikube!"
}

# Fonction pour vérifier si kubectl est configuré
function check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        echo "Erreur : kubectl n'est pas installé ou configuré."
        exit 1
    fi
}

# Fonction pour lister les pods en cours d'exécution
function audit_pods() {
    echo "=== Pods en cours d'exécution ==="
    kubectl get pods --all-namespaces
}

# Fonction pour vérifier les secrets non chiffrés
function audit_secrets() {
    echo "=== Secrets non chiffrés ==="
    kubectl get secrets --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.type}{"\n"}{end}' | grep 'Opaque'
}

# Fonction pour vérifier les RBAC (rôles et permissions)
function audit_rbac() {
    echo "=== Rôles et rôles liés au cluster ==="
    kubectl get roles --all-namespaces
    kubectl get clusterroles
}

# Fonction pour vérifier les NetworkPolicies
function audit_network_policies() {
    echo "=== NetworkPolicies configurées ==="
    kubectl get networkpolicies --all-namespaces
}

# Fonction pour vérifier les images des pods
function audit_pod_images() {
    echo "=== Images des pods et leurs versions ==="
    kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}'
}

# Fonction pour exécuter toutes les vérifications
function full_audit() {
    audit_pods
    audit_secrets
    audit_rbac
    audit_network_policies
    audit_pod_images
}

# Menu interactif
function show_menu() {
    clear
    display_ascii_art
    echo "Menu d'audit Kubernetes :"
    echo "1. Auditer les pods en cours d'exécution"
    echo "2. Auditer les secrets non chiffrés"
    echo "3. Auditer les rôles et permissions (RBAC)"
    echo "4. Auditer les NetworkPolicies"
    echo "5. Auditer les images des pods"
    echo "6. Exécuter un audit complet"
    echo "0. Quitter"
    echo ""
    read -p "Veuillez sélectionner une option : " choice
    case $choice in
        1) audit_pods ;;
        2) audit_secrets ;;
        3) audit_rbac ;;
        4) audit_network_policies ;;
        5) audit_pod_images ;;
        6) full_audit ;;
        0) exit 0 ;;
        *) echo "Option invalide. Veuillez réessayer." ;;
    esac
    echo ""
    read -p "Appuyez sur Entrée pour revenir au menu..."
}

# Point d'entrée du script
check_kubectl
while true; do
    show_menu
done
