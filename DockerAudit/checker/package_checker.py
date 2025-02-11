import subprocess
from rich.console import Console
from rich.text import Text

# Créer une instance de Console pour afficher des messages stylisés
console = Console()

def check_auditd_installed():
    try:
        # Exécute la commande pour vérifier si auditd est installé
        result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
        
        # Vérifie si auditd est dans la sortie
        if 'auditd' in result.stdout:
            # Affiche un message stylisé en vert si auditd est installé
            console.print("[bold green]auditd est installé.[/bold green]")
        else:
            # Affiche un message d'erreur stylisé en rouge avec plus de détails
            console.print("[bold red]Erreur : auditd n'est pas installé sur cette machine.[/bold red]")
            console.print("\n[bold yellow]Il est recommandé de l'avoir sur votre machine.\nVoici les étapes pour l'installer et le configurer :[/bold yellow]")
            
            # Instructions détaillées
            console.print("\n[bold cyan]- Étape 1 : Afficher les règles existantes[/bold cyan]")
            console.print("  [italic]auditctl -l | grep /usr/bin/runc[/italic]  # Affichera les règles stockées pour /usr/bin/runc")
            
            console.print("\n[bold cyan]- Étape 2 : Ajouter une règle d'audit pour Docker[/bold cyan]")
            console.print("  [italic]-w /usr/bin/runc -k docker[/italic]  # Surveille l'exécution de Docker avec runc")
            
            console.print("\n[bold cyan]- Étape 3 : Redémarrer le service auditd[/bold cyan]")
            console.print("  [italic]systemctl restart auditd[/italic]  # Redémarre le service auditd pour appliquer les modifications\n")
    
    except Exception as e:
        # En cas d'erreur dans l'exécution, affiche le message en rouge
        console.print(f"[bold red]Erreur lors de la vérification : {e}[/bold red]")
