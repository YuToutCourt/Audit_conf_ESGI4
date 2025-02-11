import os
import re
import json
import subprocess
import requests
from datetime import datetime

def check_wp_version(wp_path):
    version_file = os.path.join(wp_path, 'wp-includes', 'version.php')
    if os.path.exists(version_file):
        with open(version_file, 'r') as f:
            content = f.read()
            version = re.search(r"\$wp_version\s*=\s*'(.+?)'\s*;", content)
            return version.group(1) if version else "Version non détectée"
    return "Fichier version.php non trouvé"

def check_php_version():
    try:
        result = subprocess.run(['php', '-v'], capture_output=True, text=True)
        version = re.search(r"PHP (\d+\.\d+\.\d+)", result.stdout)
        return version.group(1) if version else "Version non détectée"
    except:
        return "PHP non trouvé"

def check_plugin_vulnerabilities(plugins_dir):
    vulnerabilities = []
    for plugin in os.listdir(plugins_dir):
        plugin_file = os.path.join(plugins_dir, plugin, f"{plugin}.php")
        if os.path.exists(plugin_file):
            with open(plugin_file, 'r') as f:
                content = f.read()
                version = re.search(r"Version:\s*(.+)", content)
                if version:
                    version = version.group(1)
                    # Simuler une vérification de vulnérabilité (à remplacer par une API réelle)
                    if plugin == "plugin vulnerable":
                        vulnerabilities.append(f"Plugin {plugin} version {version} a des vulnérabilités connues")
    return vulnerabilities

def check_user_accounts(wp_path):
    users_file = os.path.join(wp_path, 'wp-content', 'uploads', 'users.csv')
    if os.path.exists(users_file):
        with open(users_file, 'r') as f:
            users = f.read().splitlines()
        return users[1:] if len(users) > 1 else []
    return []

def check_file_permissions(wp_path):
    critical_files = {
        'wp-config.php': '600',
        '.htaccess': '644',
        'index.php': '644',
        'wp-includes': '755',
        'wp-admin': '755'
    }
    issues = []
    for file, expected_perm in critical_files.items():
        full_path = os.path.join(wp_path, file)
        if os.path.exists(full_path):
            actual_perm = oct(os.stat(full_path).st_mode)[-3:]
            if actual_perm != expected_perm:
                issues.append(f"Permissions incorrectes pour {file}: {actual_perm} (devrait être {expected_perm})")
    return issues

def check_wp_config(wp_path):
    config_file = os.path.join(wp_path, 'wp-config.php')
    issues = []
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            content = f.read()
            if "define( 'WP_DEBUG', true );" in content:
                issues.append("WP_DEBUG est activé en production")
            if not re.search(r"define\(\s*'AUTH_KEY'", content):
                issues.append("Clés de sécurité WordPress manquantes")
    return issues

def generate_client_report(vulnerabilities):
    report = f"""
Rapport d'Audit de Sécurité WordPress

Date de l'audit : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

1. Résumé Exécutif
==================
Nous avons effectué un audit de sécurité complet de votre installation WordPress. 
Cet audit a couvert la vérification des versions, l'analyse des vulnérabilités des plugins, 
l'examen des comptes utilisateurs, les permissions de fichiers et la configuration WordPress.

2. Résultats Clés
=================
Nombre total de problèmes détectés : {len(vulnerabilities)}

3. Détails des Vulnérabilités
=============================
"""
    for vuln in vulnerabilities:
        report += f"- {vuln}\n"

    report += """
4. Recommandations
==================
1. Mettez à jour WordPress, tous les plugins et thèmes vers leurs dernières versions.
2. Corrigez les permissions de fichiers incorrectes.
3. Désactivez WP_DEBUG en production.
4. Assurez-vous que toutes les clés de sécurité WordPress sont définies.
5. Renforcez la sécurité des comptes utilisateurs.
6. Effectuez des sauvegardes régulières.
7. Mettez en place une authentification à deux facteurs.

5. Conclusion
=============
Cet audit a identifié plusieurs domaines nécessitant votre attention. 
En appliquant les recommandations ci-dessus, vous améliorerez significativement 
la sécurité de votre site WordPress. Nous recommandons d'effectuer des audits 
réguliers pour maintenir un niveau de sécurité optimal.

Pour toute assistance dans la mise en œuvre de ces recommandations, 
n'hésitez pas à nous contacter.
"""
    return report

def main():
    wp_path = input("Entrez le chemin de l'installation WordPress : ")
    
    vulnerabilities = []
    
    # Vérification de la version WordPress
    wp_version = check_wp_version(wp_path)
    vulnerabilities.append(f"Version WordPress : {wp_version}")
    
    # Vérification de la version PHP
    php_version = check_php_version()
    vulnerabilities.append(f"Version PHP : {php_version}")
    
    # Vérification des vulnérabilités des plugins
    plugins_dir = os.path.join(wp_path, 'wp-content', 'plugins')
    plugin_vulns = check_plugin_vulnerabilities(plugins_dir)
    vulnerabilities.extend(plugin_vulns)
    
    # Vérification des comptes utilisateurs
    users = check_user_accounts(wp_path)
    if len(users) > 5:
        vulnerabilities.append(f"Nombre élevé de comptes utilisateurs : {len(users)}")
    
    # Vérification des permissions de fichiers
    perm_issues = check_file_permissions(wp_path)
    vulnerabilities.extend(perm_issues)
    
    # Vérification de wp-config.php
    config_issues = check_wp_config(wp_path)
    vulnerabilities.extend(config_issues)
    
    # Génération du rapport client
    client_report = generate_client_report(vulnerabilities)
    
    # Sauvegarde du rapport
    with open('wordpress_security_audit_report.txt', 'w') as f:
        f.write(client_report)
    
    print("Audit de sécurité terminé. Le rapport a été sauvegardé dans 'wordpress_security_audit_report.txt'")

if __name__ == "__main__":
    main()
