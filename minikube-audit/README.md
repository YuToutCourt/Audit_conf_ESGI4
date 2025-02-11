Mini Audit - Outil d'Audit Kubernetes pour Minikube 

Mini Audit  est un outil simple et efficace conçu pour auditer les configurations et les pratiques de sécurité d'un cluster Kubernetes localisé sur Minikube. Cet outil permet d'examiner différents aspects critiques du cluster, tels que les pods en cours d'exécution, les secrets non chiffrés, les politiques RBAC (Role-Based Access Control), les NetworkPolicies et les images des conteneurs. 

Ce projet a été développé conjointement par Yannis  et Julien , dans le but de fournir un outil facile à utiliser pour les administrateurs de clusters Kubernetes souhaitant s'assurer que leur environnement est bien configuré et sécurisé. 
Fonctionnalités 

    Audit des Pods  : Liste tous les pods en cours d'exécution dans toutes les namespaces.
    Audit des Secrets  : Identifie les secrets non chiffrés (type Opaque) dans le cluster.
    Audit des RBAC  : Affiche les rôles et rôles liés au cluster pour vérifier les permissions attribuées.
    Audit des NetworkPolicies  : Vérifie si des règles de réseau sont configurées pour contrôler les communications entre les pods.
    Audit des Images des Pods  : Répertorie toutes les images utilisées dans les pods pour faciliter l'analyse des vulnérabilités potentielles.
    Audit Complet  : Exécute toutes les vérifications ci-dessus en une seule commande.
     

Prérequis 

Pour utiliser cet outil, assurez-vous que les éléments suivants sont installés et configurés sur votre machine : 

    Minikube  : Un environnement local pour exécuter Kubernetes.
        Installation : https://minikube.sigs.k8s.io/docs/start/ 
         
    kubectl  : L'outil en ligne de commande officiel pour interagir avec Kubernetes.
        Installation : https://kubernetes.io/docs/tasks/tools/install-kubectl/ 
         
    Python 3  : Le script principal est écrit en Python 3.
        Installation : https://www.python.org/downloads/ 
         

Assurez-vous que Minikube est démarré et que kubectl est configuré pour pointer vers le cluster Minikube : 
bash
 

     
    1
    2
    minikube start
    kubectl config use-context minikube
     
     
     

Utilisation 

Exécutez le script principal pour accéder au menu interactif : 
bash
 
 
1
python3 minikube-audit.py
 
 

Vous verrez alors un menu avec plusieurs options pour auditer différentes parties de votre cluster. Choisissez une option en entrant le numéro correspondant. 
Exemple de Menu : 
 
 
1
2
3
4
5
6
7
8
9
10
11
12
Mini Audit - Outil d'audit Kubernetes pour Minikube

Menu d'audit Kubernetes :
1. Auditer les pods en cours d'exécution
2. Auditer les secrets non chiffrés
3. Auditer les rôles et permissions (RBAC)
4. Auditer les NetworkPolicies
5. Auditer les images des pods
6. Exécuter un audit complet
0. Quitter

Veuillez sélectionner une option :
 
 
Contributions 

Ce projet a été créé par Yannis  et Julien . Si vous souhaitez contribuer ou signaler des problèmes, n'hésitez pas à ouvrir une issue ou une pull request sur le dépôt GitHub. 
License 

Ce projet est sous licence MIT. Consultez le fichier LICENSE  pour plus de détails. 
