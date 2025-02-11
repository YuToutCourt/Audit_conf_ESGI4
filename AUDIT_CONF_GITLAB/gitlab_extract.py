import os
import re
import yaml
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

console = Console()

# Ce chemin peut etre changé 
REPERTOIRE = "/path/to/code/AUDIT_CONF_GITLAB"
REPERTOIRE_ANALYSE = f"{REPERTOIRE}/conf_file"
ANALYSE_RESULTAT = f"{REPERTOIRE}/resultats_analyse.txt"

SENSITIVE_KEYWORDS = ['password', 'secret', 'key', 'token']
UNSECURE_COMMANDS = ['curl --insecure', 'wget --no-check-certificate']
PROJECT_CONFIG_VULNERABILITIES = {
    "password": {
        "vuln": "Mot de passe en texte clair",
        "explanation": "L'utilisation de mots de passe en texte clair peut exposer des informations sensibles si ces mots de passe sont fuités.",
        "recommendation": "Utiliser des méthodes de stockage sécurisées comme le hachage ou le chiffrement pour protéger les mots de passe.\n"
    },
    "secret": {
        "vuln": "Secret en texte clair",
        "explanation": "L'utilisation de secrets en texte clair peut exposer des informations sensibles si ces secrets sont fuités.",
        "recommendation": "Utiliser des méthodes de stockage sécurisées comme le chiffrement pour protéger les secrets.\n"
    },
    "project_visibility": {
        "vuln": "Visibilité publique du projet",
        "explanation": "Un projet configuré en 'public' peut exposer des informations sensibles à tout le monde sur Internet.",
        "recommendation": "Restreindre la visibilité à 'private' ou 'internal' selon le niveau de confidentialité requis.\n"
    },
    "project_pages_access_level": {
        "vuln": "Accès public aux pages du projet",
        "explanation": "Permettre un accès public aux pages du projet expose potentiellement des informations sensibles qui devraient être restreintes.",
        "recommendation": "Restreindre l'accès aux pages sensibles à des utilisateurs authentifiés ou le limiter à un groupe restreint.\n"
    },
    "project_security_and_compliance_enabled": {
        "vuln": "Sécurité et conformité désactivées",
        "explanation": "Désactiver la sécurité et la conformité peut rendre le projet vulnérable à des attaques ou à des violations de normes de sécurité.",
        "recommendation": "Activer la sécurité et la conformité pour assurer que le projet respecte les politiques de sécurité et les normes de conformité.\n"
    },
    "project_approvals_before_merge": {
        "vuln": "Pas d'approbation avant la fusion",
        "explanation": "L'absence d'approbation avant fusion permet à des modifications non vérifiées d'être intégrées, ce qui peut compromettre la qualité et la sécurité.",
        "recommendation": "Exiger au moins une approbation avant la fusion pour garantir que les modifications sont revues par un autre développeur.\n"
    },
    "project_push_rules_unsigned_commits": {
        "vuln": "Les commits non signés sont autorisés",
        "explanation": "Permettre des commits non signés ouvre la porte à des modifications non vérifiables, ce qui peut mener à l'injection de code malveillant.",
        "recommendation": "Activer les règles pour interdire les commits non signés, garantissant ainsi l'intégrité du code.\n"
    },
    "project_push_rules_comitter_check": {
        "vuln": "Vérification du committeur désactivée",
        "explanation": "L'absence de vérification du committeur peut permettre à un utilisateur non autorisé de modifier le code sous l'identité d'un autre.",
        "recommendation": "Activer la vérification du committeur pour s'assurer que les commits sont effectués par des utilisateurs autorisés.\n"
    },
    "project_protected_branches": {
        "vuln": "Branches non protégées",
        "explanation": "Les branches non protégées peuvent être modifiées sans restriction, ce qui permet à des erreurs ou à des modifications non approuvées de s'introduire dans le code.",
        "recommendation": "Activer les branches protégées pour empêcher les modifications non autorisées sur les branches principales comme 'main' ou 'master'.\n"
    },
    "project_access_tokens": {
        "vuln": "Tokens d'accès non sécurisés",
        "explanation": "L'utilisation de tokens d'accès non sécurisés peut exposer des informations sensibles si ces tokens sont fuités.",
        "recommendation": "S'assurer que les tokens d'accès sont correctement sécurisés et utilisés uniquement lorsque nécessaire.\n"
    },
    "project_deploy_tokens": {
        "vuln": "Tokens de déploiement non sécurisés",
        "explanation": "Les tokens de déploiement non sécurisés peuvent permettre à un attaquant d'effectuer des déploiements non autorisés.",
        "recommendation": "Sécuriser les tokens de déploiement et limiter leur utilisation aux processus de déploiement vérifiés.\n"
    },
    "project_deploy_keys": {
        "vuln": "Clés de déploiement non sécurisées",
        "explanation": "Les clés de déploiement non sécurisées exposent le projet à des risques d'accès non autorisé lors des déploiements.",
        "recommendation": "S'assurer que les clés de déploiement sont sécurisées et utilisées uniquement dans les environnements de production.\n"
    },
    "project_file_pipeline": {
        "vuln": "Pipeline de fichiers non activé",
        "explanation": "Ne pas activer les pipelines de fichiers peut empêcher une automatisation correcte des tests et des déploiements, ce qui peut rendre le processus vulnérable.",
        "recommendation": "Activer le pipeline de fichiers pour assurer que les tests et les déploiements sont automatisés et vérifiés.\n"
    },
    "project_merged_pipeline": {
        "vuln": "Pipeline de fusion non activé",
        "explanation": "Ne pas activer les pipelines de fusion peut mener à des erreurs ou à des incohérences dans les branches fusionnées, en particulier lors des mises à jour de code.",
        "recommendation": "Activer le pipeline de fusion pour garantir que toutes les modifications sont testées avant d'être fusionnées dans la branche principale.\n"
    },
    "project_file_codeowners": {
        "vuln": "Codeowners non configuré",
        "explanation": "Ne pas configurer les codeowners peut mener à une gestion désorganisée des autorisations sur le code, rendant les révisions de code plus difficiles.",
        "recommendation": "Configurer le fichier CODEOWNERS pour attribuer clairement les responsabilités de révision de code.\n"
    },
    "project_shared_runners_enabled": {
        "vuln": "Runners partagés activés",
        "explanation": "Les runners partagés peuvent poser un risque de sécurité car ils sont utilisés par plusieurs projets et peuvent partager des ressources sensibles.",
        "recommendation": "Désactiver les runners partagés et utiliser des runners spécifiques au projet pour limiter l'accès à des ressources sensibles.\n"
    },
    "project_runners_shared": {
        "vuln": "Runners partagés autorisés",
        "explanation": "L'utilisation de runners partagés autorisés peut entraîner des risques de sécurité si un autre projet malveillant utilise les mêmes ressources.",
        "recommendation": "Désactiver l'utilisation des runners partagés pour renforcer la sécurité.\n"
    },
    "project_runners_notshared": {
        "vuln": "Runners non partagés activés",
        "explanation": "Permettre des runners non partagés peut augmenter la complexité et le coût de l'infrastructure, mais peut améliorer la sécurité.",
        "recommendation": "Activer des runners non partagés si la sécurité et l'isolation des processus sont prioritaires.\n"
    }
}

CONFIGURATION_ERRORS = {
    "incorrect_permissions": {
        "vuln": "Permissions incorrectes",
        "explanation": "Des permissions incorrectes sur des fichiers ou répertoires peuvent permettre un accès non autorisé.",
        "recommendation": "Vérifiez les permissions et assurez-vous qu'elles sont restreintes au minimum nécessaire.\n"
    },
    "unused_groups": {
        "vuln": "Groupes inutilisés",
        "explanation": "Des groupes inutilisés ou mal configurés peuvent présenter des risques de sécurité.",
        "recommendation": "Désactivez ou supprimez les groupes inutilisés dans la configuration.\n"
    }
}

def analyser_yaml(fichier):
    try:
        with open(fichier, 'r', encoding='utf-8') as file:
            content = yaml.safe_load(file)
            failles = []

            if 'projects' in content:
                for project in content['projects']:
                    if isinstance(project, dict):
                        for project_name, config in project.items():
                            for key, vuln_info in PROJECT_CONFIG_VULNERABILITIES.items():
                                if key in config and not config[key]:
                                    failles.append(f"[red]{vuln_info['vuln']}[/red] : {vuln_info['explanation']}")
                                    failles.append(f"[yellow]Recommandation[/yellow]: {vuln_info['recommendation']}")

            return failles
    except Exception as e:
        console.print(f"[red]Erreur lors de l'analyse de {fichier}: {e}[/red]")
        return []

def verifier_secrets(fichier):
    with open(fichier, 'r', encoding='utf-8') as file:
        contenu = file.read()
        for keyword in SENSITIVE_KEYWORDS:
            if re.search(r'\b' + re.escape(keyword) + r'\b', contenu, re.IGNORECASE):
                return True
    return False

def verifier_commandes_non_securisees(fichier):
    with open(fichier, 'r', encoding='utf-8') as file:
        contenu = file.read()
        for command in UNSECURE_COMMANDS:
            if command in contenu:
                return True
    return False

def analyser_repertoire(repertoire):
    nb_fichiers = 0
    nb_fichiers_python = 0
    nb_todos = 0
    nb_secrets = 0
    nb_commandes_non_securisees = 0
    nb_configuration_errors = 0
    fichiers_config = {}
    recommandations = {}

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Nom du fichier", style="dim", width=40)
    table.add_column("Taille (octets)", justify="right")
    table.add_column("Recommandations", justify="left")

    for root, dirs, files in os.walk(repertoire):
        for file in files:
            file_path = os.path.join(root, file)
            nb_fichiers += 1

            if file.endswith(".py"):
                nb_fichiers_python += 1

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                    nb_todos += len(re.findall(r"\bTODO\b", file_content))

                    if file in ['Baseline.yml', 'pipeline_config.yml', 'project_config.yml']:
                        failles_yaml = analyser_yaml(file_path)
                        if failles_yaml:
                            console.print("\n[bold red]Vulnérabilités détectées et recommandations:[/bold red]")
                            for faille in failles_yaml:
                                console.print(faille)

                    if file.endswith(('.yaml', '.json', '.toml', '.gitlab-ci.yml')):
                        if verifier_secrets(file_path):
                            nb_secrets += 1
                            recommandations[file_path] = "[red]Retirer ou chiffrer les secrets. Utiliser un gestionnaire de secrets (par exemple, HashiCorp Vault) pour éviter l'exposition des informations sensibles.[/red]"

                        if verifier_commandes_non_securisees(file_path):
                            nb_commandes_non_securisees += 1
                            recommandations[file_path] = "[red]Utiliser des commandes sécurisées sans '--insecure'. Ne jamais désactiver la vérification de certificat SSL/TLS. Les commandes comme 'curl...[/red]"

                        table.add_row(file, str(os.path.getsize(file_path)), recommandations.get(file, "Consulter fichier résultats."))

            except Exception as e:
                console.print(f"[red]Erreur lors de l'analyse de {file_path}: {e}[/red]")

    console.print(f"\n\n[bold]Résumé de l'analyse[/bold]")
    console.print(f"Nombre total de fichiers analysés : {nb_fichiers}")
    console.print(f"Nombre de fichiers Python (.py) : {nb_fichiers_python}")
    console.print(f"Nombre de mentions 'TODO' dans le code : {nb_todos}")
    console.print(f"Nombre de fichiers contenant des secrets en texte clair : {nb_secrets}")
    console.print(f"Nombre de fichiers contenant des commandes non sécurisées : {nb_commandes_non_securisees}")
    console.print(f"Nombre d'erreurs de configuration : {nb_configuration_errors}")

    console.print("\n[bold]Fichiers de configuration détectés[/bold]")
    console.print(table)

    with open(ANALYSE_RESULTAT, 'w', encoding='utf-8') as f:
        f.write(f"Nombre total de fichiers analysés : {nb_fichiers}\n")
        f.write(f"Nombre de fichiers Python (.py) : {nb_fichiers_python}\n")
        f.write(f"Nombre de mentions 'TODO' dans le code : {nb_todos}\n")
        f.write(f"Nombre de fichiers contenant des secrets en texte clair : {nb_secrets}\n")
        f.write(f"Nombre de fichiers contenant des commandes non sécurisées : {nb_commandes_non_securisees}\n")
        f.write(f"Nombre d'erreurs de configuration : {nb_configuration_errors}\n")
        f.write(f"Recommandations pour les failles détectées :\n")
        for file, recommandation in recommandations.items():
            f.write(f"{file}: {recommandation}\n")

    console.print(f"[green]Analyse terminée et résultats sauvegardés dans '{ANALYSE_RESULTAT}'[/green]")

repertoire_analyse = Prompt.ask("Sélectionnez un répertoire à analyser", default=REPERTOIRE_ANALYSE)
analyser_repertoire(repertoire_analyse)
