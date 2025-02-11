import os
import subprocess

Bienvenue dans Mini Audit - Outil d'audit Kubernetes pour Minikube!
""")

# Fonction pour vérifier si kubectl est configuré
def check_kubectl():
    try:
        subprocess.run(["kubectl", "version", "--client"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Erreur : kubectl n'est pas installé ou configuré.")
        exit(1)

# Fonction pour lister les pods en cours d'exécution
def audit_pods():
    print("=== Pods en cours d'exécution ===")
    result = subprocess.run(["kubectl", "get", "pods", "--all-namespaces"], capture_output=True, text=True)
    print(result.stdout)

# Fonction pour vérifier les secrets non chiffrés
def audit_secrets():
    print("=== Secrets non chiffrés ===")
    command = "kubectl get secrets --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.type}{\"\\n\"}{end}' | grep 'Opaque'"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(result.stdout)

# Fonction pour vérifier les RBAC (rôles et permissions)
def audit_rbac():
    print("=== Rôles et rôles liés au cluster ===")
    subprocess.run(["kubectl", "get", "roles", "--all-namespaces"])
    subprocess.run(["kubectl", "get", "clusterroles"])

# Fonction pour vérifier les NetworkPolicies
def audit_network_policies():
    print("=== NetworkPolicies configurées ===")
    subprocess.run(["kubectl", "get", "networkpolicies", "--all-namespaces"])

# Fonction pour vérifier les images des pods
def audit_pod_images():
    print("=== Images des pods et leurs versions ===")
    command = "kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[*].image}{\"\\n\"}{end}'"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(result.stdout)

# Fonction pour exécuter toutes les vérifications
def full_audit():
    audit_pods()
    audit_secrets()
    audit_rbac()
    audit_network_policies()
    audit_pod_images()

# Menu interactif
def show_menu():
    while True:
        os.system('clear') if os.name == 'posix' else os.system('cls')
        display_ascii_art()
        print("Menu d'audit Kubernetes :")
        print("1. Auditer les pods en cours d'exécution")
        print("2. Auditer les secrets non chiffrés")
        print("3. Auditer les rôles et permissions (RBAC)")
        print("4. Auditer les NetworkPolicies")
        print("5. Auditer les images des pods")
        print("6. Exécuter un audit complet")
        print("0. Quitter")
        print("")
        choice = input("Veuillez sélectionner une option : ")
        if choice == "1":
            audit_pods()
        elif choice == "2":
            audit_secrets()
        elif choice == "3":
            audit_rbac()
        elif choice == "4":
            audit_network_policies()
        elif choice == "5":
            audit_pod_images()
        elif choice == "6":
            full_audit()
        elif choice == "0":
            print("Au revoir !")
            break
        else:
            print("Option invalide. Veuillez réessayer.")
        input("\nAppuyez sur Entrée pour revenir au menu...")

# Point d'entrée du script
if __name__ == "__main__":
    check_kubectl()
    show_menu()
