import subprocess
import shutil
import os
import requests
from bs4 import BeautifulSoup

def get_local_docker_version():
    try:
        result = subprocess.run("docker --version", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            version_info = result.stdout.decode().strip()
            return version_info.split()[2].strip(',')
        else:
            return None
    except Exception as e:
        print(f"An error occurred while getting local Docker version: {e}")
        return None

def get_latest_docker_version():
    try:
        url = "https://docs.docker.com/engine/release-notes/"
        response = requests.get(url)
        response.raise_for_status()  # Vérifie si la requête est réussie
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Recherche de la version en fonction de la structure actuelle de la page
        # Ici, on suppose que la première entrée de version est dans un <h2> avec un format comme "Version X.Y.Z"
        version_heading = soup.find("h3")
        if version_heading:
            version = version_heading.get_text(strip=True).split(" ")[-1]
            return version
        else:
            print("Impossible de trouver la version sur la page.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération de la version : {e}")
        return None

