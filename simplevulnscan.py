#!/usr/bin/env python3
"""
Scanner de Vulnérabilités - Outil d'audit de sécurité
====================================================
Ce script audite les versions des logiciels installés et identifie
les vulnérabilités connues (CVE) en utilisant des bases de données en ligne.

Sources de données:
- OSV (Open Source Vulnerabilities) - Google (rapide & profond)
- PyPI Safety DB - Python Package Index (profond uniquement)

Auteur: Équipe Cybersécurité
Version: 2.1.0

Usage:
    simplevulnscan                 Affiche le manuel d'utilisation
    simplevulnscan -f, --fast      Scan rapide (OSV uniquement)
    simplevulnscan -d, --deep      Scan en profondeur (toutes les sources)
"""

import subprocess
import json
import csv
import sys
import platform
import re
import os
import time
import argparse
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import urllib.request
import urllib.error
import urllib.parse


# ============================================================================
# CONFIGURATION ET CONSTANTES
# ============================================================================

# Modes de scan
SCAN_MODE_FAST = "fast"
SCAN_MODE_DEEP = "deep"

# URLs des API de vulnérabilités
OSV_API_URL = "https://api.osv.dev/v1/query"
PYPI_SAFETY_DB_URL = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"

# Cache des réponses API pour éviter les requêtes répétées
API_CACHE = {}

# Mapping des niveaux de sévérité CVSS
SEVERITY_LEVELS = {
    "CRITICAL": {"min": 9.0, "max": 10.0, "color": "🔴"},
    "HIGH": {"min": 7.0, "max": 8.9, "color": "🟠"},
    "MEDIUM": {"min": 4.0, "max": 6.9, "color": "🟡"},
    "LOW": {"min": 0.1, "max": 3.9, "color": "🟢"},
    "NONE": {"min": 0.0, "max": 0.0, "color": "⚪"}
}


# ============================================================================
# FONCTIONS D'ACCÈS AUX API
# ============================================================================

def make_http_request(url: str, method: str = "GET", data: Optional[Dict] = None, timeout: int = 10) -> Optional[Dict]:
    """
    Effectue une requête HTTP avec gestion d'erreurs et retry.
    
    Args:
        url: URL de l'API à interroger
        method: Méthode HTTP (GET ou POST)
        data: Données à envoyer (pour POST)
        timeout: Délai d'attente en secondes
        
    Returns:
        Dictionnaire JSON de la réponse ou None en cas d'erreur
    """
    try:
        if method == "POST" and data:
            json_data = json.dumps(data).encode('utf-8')
            req = urllib.request.Request(
                url,
                data=json_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'VulnerabilityScanner/2.0'
                }
            )
        else:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'VulnerabilityScanner/2.0'}
            )
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode('utf-8'))
    
    except urllib.error.HTTPError as e:
        if e.code == 429:  # Rate limit
            print(f"   ⚠️  Rate limit atteint, attente 2s...")
            time.sleep(2)
            return None
        print(f"   ⚠️  Erreur HTTP {e.code}: {e.reason}")
        return None
    
    except urllib.error.URLError as e:
        print(f"   ⚠️  Erreur réseau: {e.reason}")
        return None
    
    except json.JSONDecodeError:
        print(f"   ⚠️  Réponse JSON invalide")
        return None
    
    except Exception as e:
        print(f"   ⚠️  Erreur inattendue: {e}")
        return None


def query_osv_api(package_name: str, package_version: str, ecosystem: str = "PyPI") -> List[Dict]:
    """
    Interroge l'API OSV (Open Source Vulnerabilities) de Google.
    
    Args:
        package_name: Nom du paquet à vérifier
        package_version: Version du paquet
        ecosystem: Écosystème (PyPI, npm, Go, etc.)
        
    Returns:
        Liste des vulnérabilités trouvées
    """
    cache_key = f"osv_{ecosystem}_{package_name}_{package_version}"
    if cache_key in API_CACHE:
        return API_CACHE[cache_key]
    
    vulnerabilities = []
    
    query_data = {
        "version": package_version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    
    response = make_http_request(OSV_API_URL, method="POST", data=query_data)
    
    if response and "vulns" in response:
        for vuln in response["vulns"]:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "No description available")
            
            # Extraire le score CVSS
            cvss_score = 5.0  # Score par défaut si non trouvé
            severity = "MEDIUM"
            
            if "severity" in vuln:
                for sev in vuln["severity"]:
                    if sev.get("type") == "CVSS_V3":
                        try:
                            cvss_score = float(sev.get("score", 5.0))
                        except (ValueError, TypeError):
                            cvss_score = 5.0
                        severity = calculate_severity_from_cvss(cvss_score)
                        break
            
            # Extraire la version corrigée
            fixed_version = "Unknown"
            
            if "affected" in vuln:
                for affected in vuln["affected"]:
                    if "ranges" in affected:
                        for range_info in affected["ranges"]:
                            if "events" in range_info:
                                for event in range_info["events"]:
                                    if "fixed" in event:
                                        fixed_version = event["fixed"]
                                        break
                            if fixed_version != "Unknown":
                                break
                    if fixed_version != "Unknown":
                        break
            
            vulnerabilities.append({
                "source": "OSV",
                "cve_id": vuln_id,
                "description": summary[:200],
                "cvss_score": cvss_score,
                "severity": severity,
                "affected_range": "See references",
                "fixed_version": fixed_version,
                "references": [ref.get("url", "") for ref in vuln.get("references", [])[:3]]
            })
    
    API_CACHE[cache_key] = vulnerabilities
    return vulnerabilities


def query_pypi_safety_db(package_name: str, package_version: str) -> List[Dict]:
    """
    Interroge la base de données Safety DB pour les paquets Python.
    
    Args:
        package_name: Nom du paquet Python
        package_version: Version du paquet
        
    Returns:
        Liste des vulnérabilités trouvées
    """
    cache_key = "safety_db_full"
    
    # Télécharger la base de données complète (une seule fois)
    if cache_key not in API_CACHE:
        print("   📥 Téléchargement de la base Safety DB...")
        response = make_http_request(PYPI_SAFETY_DB_URL, timeout=30)
        if response:
            API_CACHE[cache_key] = response
        else:
            API_CACHE[cache_key] = {}
            return []
    
    safety_db = API_CACHE[cache_key]
    vulnerabilities = []
    
    # Rechercher le paquet dans la base
    package_name_lower = package_name.lower()
    if package_name_lower in safety_db:
        for vuln in safety_db[package_name_lower]:
            # Vérifier si la version est affectée
            affected_versions = vuln.get("specs", [])
            is_affected = False
            
            for spec in affected_versions:
                if check_version_spec(package_version, spec):
                    is_affected = True
                    break
            
            if is_affected:
                cve_id = vuln.get("cve") or vuln.get("id", "PYSEC-UNKNOWN")
                try:
                    cvss_score = float(vuln.get("cvss", 5.0))
                except (ValueError, TypeError):
                    cvss_score = 5.0
                
                fixed_in = vuln.get("fixed_in", [])
                fixed_version = fixed_in[0] if fixed_in else "Unknown"
                
                vulnerabilities.append({
                    "source": "Safety DB",
                    "cve_id": str(cve_id),
                    "description": vuln.get("advisory", "No description")[:200],
                    "cvss_score": cvss_score,
                    "severity": calculate_severity_from_cvss(cvss_score),
                    "affected_range": ", ".join(affected_versions),
                    "fixed_version": fixed_version,
                    "references": []
                })
    
    return vulnerabilities


def aggregate_vulnerabilities_from_apis(package: Dict[str, str], scan_mode: str = SCAN_MODE_DEEP) -> List[Dict]:
    """
    Agrège les vulnérabilités de toutes les sources API disponibles.
    
    Args:
        package: Dictionnaire contenant le nom, version et type du paquet
        scan_mode: Mode de scan ('fast' = OSV uniquement, 'deep' = toutes sources)
        
    Returns:
        Liste consolidée des vulnérabilités uniques
    """
    package_name = package["name"]
    package_version = package["version"]
    package_type = package["type"]
    
    all_vulnerabilities = []
    seen_cve_ids = set()
    
    # Mode FAST : OSV uniquement (la plus connue et complète)
    # Mode DEEP : OSV + Safety DB
    
    # 1. Interroger OSV (toujours utilisé, c'est la source principale)
    if package_type == "python":
        try:
            osv_vulns = query_osv_api(package_name, package_version, "PyPI")
            for vuln in osv_vulns:
                if vuln["cve_id"] not in seen_cve_ids:
                    vuln["package"] = package_name
                    vuln["installed_version"] = package_version
                    vuln["package_type"] = package_type
                    all_vulnerabilities.append(vuln)
                    seen_cve_ids.add(vuln["cve_id"])
        except Exception as e:
            print(f"   ⚠️  Erreur OSV pour {package_name}: {e}")
    
    # 2. Interroger Safety DB (uniquement en mode DEEP)
    if scan_mode == SCAN_MODE_DEEP and package_type == "python":
        try:
            safety_vulns = query_pypi_safety_db(package_name, package_version)
            for vuln in safety_vulns:
                if vuln["cve_id"] not in seen_cve_ids:
                    vuln["package"] = package_name
                    vuln["installed_version"] = package_version
                    vuln["package_type"] = package_type
                    all_vulnerabilities.append(vuln)
                    seen_cve_ids.add(vuln["cve_id"])
        except Exception as e:
            print(f"   ⚠️  Erreur Safety DB pour {package_name}: {e}")
    
    return all_vulnerabilities


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def calculate_severity_from_cvss(cvss_score: float) -> str:
    """
    Calcule le niveau de sévérité à partir du score CVSS.
    
    Args:
        cvss_score: Score CVSS (0.0 à 10.0)
        
    Returns:
        Niveau de sévérité (CRITICAL, HIGH, MEDIUM, LOW, NONE)
    """
    for severity, bounds in SEVERITY_LEVELS.items():
        if bounds["min"] <= cvss_score <= bounds["max"]:
            return severity
    return "UNKNOWN"


def check_version_spec(version_str: str, spec: str) -> bool:
    """
    Vérifie si une version correspond à une spécification (format pip).
    
    Args:
        version_str: Version à vérifier
        spec: Spécification de version
        
    Returns:
        True si la version correspond à la spec
    """
    try:
        # Import ici pour éviter les erreurs si packaging n'est pas installé
        from packaging import version
        
        ver = version.parse(version_str)
        
        # Séparer les multiples conditions
        conditions = spec.split(',')
        
        for condition in conditions:
            condition = condition.strip()
            
            # Parser l'opérateur et la version cible
            match = re.match(r'^([<>=!]+)(.+)$', condition)
            if not match:
                continue
            
            operator, target = match.groups()
            target_ver = version.parse(target)
            
            # Évaluer la condition
            if operator == '<':
                if not (ver < target_ver):
                    return False
            elif operator == '<=':
                if not (ver <= target_ver):
                    return False
            elif operator == '>':
                if not (ver > target_ver):
                    return False
            elif operator == '>=':
                if not (ver >= target_ver):
                    return False
            elif operator == '==':
                if not (ver == target_ver):
                    return False
            elif operator == '!=':
                if not (ver != target_ver):
                    return False
        
        return True
    
    except ImportError:
        print("   ⚠️  Module 'packaging' non installé, comparaison de versions limitée")
        return True  # Par défaut, considérer comme affecté
    except Exception:
        return False


# ============================================================================
# FONCTIONS D'ÉNUMÉRATION DES PAQUETS
# ============================================================================

def get_system_info() -> Dict[str, str]:
    """
    Récupère les informations sur le système d'exploitation.
    
    Returns:
        Dict contenant les informations système
    """
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version()
    }


def get_python_packages() -> List[Dict[str, str]]:
    """
    Énumère tous les paquets Python installés via pip.
    
    Returns:
        Liste de dictionnaires contenant le nom et la version de chaque paquet
    """
    packages = []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            pip_list = json.loads(result.stdout)
            for package in pip_list:
                packages.append({
                    "name": package["name"].lower(),
                    "version": package["version"],
                    "type": "python"
                })
    except subprocess.TimeoutExpired:
        print("⚠️  Timeout lors de l'énumération des paquets Python")
    except json.JSONDecodeError:
        print("⚠️  Erreur de parsing JSON de pip list")
    except Exception as e:
        print(f"⚠️  Erreur lors de l'énumération des paquets Python: {e}")
    
    return packages


def enumerate_all_packages() -> List[Dict[str, str]]:
    """
    Énumère tous les paquets installés sur le système.
    
    Returns:
        Liste consolidée de tous les paquets avec leurs versions
    """
    all_packages = []
    
    print("📦 Énumération des paquets Python...")
    all_packages.extend(get_python_packages())
    
    print(f"✅ {len(all_packages)} paquets détectés\n")
    return all_packages


# ============================================================================
# FONCTIONS DE SCAN DE VULNÉRABILITÉS
# ============================================================================

def scan_all_packages(packages: List[Dict[str, str]], scan_mode: str = SCAN_MODE_DEEP) -> List[Dict]:
    """
    Scanne tous les paquets pour détecter les vulnérabilités via les API.
    
    Args:
        packages: Liste des paquets à scanner
        scan_mode: Mode de scan ('fast' ou 'deep')
        
    Returns:
        Liste de toutes les vulnérabilités détectées
    """
    mode_label = "RAPIDE (OSV)" if scan_mode == SCAN_MODE_FAST else "PROFONDEUR (OSV + Safety DB)"
    print(f"🔍 Scan des vulnérabilités en cours - Mode: {mode_label}")
    print("   Cela peut prendre quelques minutes...\n")
    
    all_vulnerabilities = []
    total_packages = len(packages)
    
    for idx, package in enumerate(packages, 1):
        if idx % 10 == 0 or idx == 1:
            print(f"   Progression: {idx}/{total_packages} paquets analysés...")
        
        vulns = aggregate_vulnerabilities_from_apis(package, scan_mode)
        all_vulnerabilities.extend(vulns)
        
        # Délai plus court en mode rapide
        delay = 0.05 if scan_mode == SCAN_MODE_FAST else 0.1
        time.sleep(delay)
    
    print(f"\n✅ Scan terminé: {len(all_vulnerabilities)} vulnérabilités détectées\n")
    return all_vulnerabilities


# ============================================================================
# FONCTIONS DE CLASSIFICATION
# ============================================================================

def classify_vulnerabilities_by_severity(vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Classe les vulnérabilités par niveau de sévérité.
    
    Args:
        vulnerabilities: Liste des vulnérabilités détectées
        
    Returns:
        Dictionnaire avec les vulnérabilités groupées par sévérité
    """
    classified = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "UNKNOWN": []
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "UNKNOWN")
        if severity in classified:
            classified[severity].append(vuln)
        else:
            classified["UNKNOWN"].append(vuln)
    
    return classified


def calculate_risk_statistics(vulnerabilities: List[Dict]) -> Dict:
    """
    Calcule des statistiques sur les risques détectés.
    
    Args:
        vulnerabilities: Liste des vulnérabilités
        
    Returns:
        Dictionnaire contenant les statistiques de risque
    """
    classified = classify_vulnerabilities_by_severity(vulnerabilities)
    
    total_score = sum(v.get("cvss_score", 0) for v in vulnerabilities)
    avg_score = total_score / len(vulnerabilities) if vulnerabilities else 0
    
    sources = set(v.get("source", "Unknown") for v in vulnerabilities)
    
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "critical_count": len(classified["CRITICAL"]),
        "high_count": len(classified["HIGH"]),
        "medium_count": len(classified["MEDIUM"]),
        "low_count": len(classified["LOW"]),
        "unknown_count": len(classified["UNKNOWN"]),
        "average_cvss_score": round(avg_score, 2),
        "total_cvss_score": round(total_score, 2),
        "data_sources": list(sources)
    }


# ============================================================================
# FONCTIONS DE REMÉDIATION
# ============================================================================

def generate_remediation_commands(vulnerability: Dict) -> List[str]:
    """
    Génère des commandes de remédiation pour une vulnérabilité.
    
    Args:
        vulnerability: Dictionnaire décrivant la vulnérabilité
        
    Returns:
        Liste de commandes à exécuter
    """
    commands = []
    package_name = vulnerability["package"]
    fixed_version = vulnerability.get("fixed_version", "latest")
    package_type = vulnerability.get("package_type", "python")
    
    if package_type == "python":
        if fixed_version == "Unknown" or "See references" in fixed_version:
            commands.append(f"# Vérifier les références pour {package_name}")
            commands.append(f"pip install --upgrade {package_name}")
        else:
            commands.append(f"pip install '{package_name}>={fixed_version}'")
    
    return commands


def generate_remediation_report(vulnerabilities: List[Dict]) -> str:
    """
    Génère un rapport de remédiation avec les actions recommandées.
    
    Args:
        vulnerabilities: Liste des vulnérabilités détectées
        
    Returns:
        Rapport de remédiation formaté en texte
    """
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("RAPPORT DE REMÉDIATION")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    classified = classify_vulnerabilities_by_severity(vulnerabilities)
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        vulns = classified[severity]
        if not vulns:
            continue
        
        color = SEVERITY_LEVELS.get(severity, {"color": "⚪"})["color"]
        report_lines.append(f"\n{color} {severity} ({len(vulns)} vulnérabilités)")
        report_lines.append("-" * 80)
        
        for vuln in vulns:
            report_lines.append(f"\nPaquet: {vuln['package']} v{vuln['installed_version']}")
            report_lines.append(f"CVE: {vuln['cve_id']} (CVSS: {vuln['cvss_score']}) [Source: {vuln['source']}]")
            report_lines.append(f"Description: {vuln['description']}")
            report_lines.append(f"Version corrigée: {vuln['fixed_version']}")
            
            if vuln.get("references"):
                report_lines.append("Références:")
                for ref in vuln["references"][:2]:
                    report_lines.append(f"  - {ref}")
            
            report_lines.append("\nCommandes de remédiation:")
            commands = generate_remediation_commands(vuln)
            for cmd in commands:
                report_lines.append(f"  {cmd}")
            report_lines.append("")
    
    return "\n".join(report_lines)


# ============================================================================
# FONCTIONS DE REPORTING
# ============================================================================

def create_report_directory() -> str:
    """
    Crée la structure de dossiers pour les rapports.
    
    Returns:
        Chemin du dossier créé pour ce scan
    """
    base_dir = "rapports"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
        print(f"✅ Dossier principal créé: {base_dir}/")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(base_dir, f"scan_{timestamp}")
    os.makedirs(scan_dir)
    print(f"✅ Dossier de scan créé: {scan_dir}/\n")
    
    return scan_dir


def generate_text_report(vulnerabilities: List[Dict], stats: Dict, system_info: Dict) -> str:
    """
    Génère un rapport complet en format texte.
    
    Args:
        vulnerabilities: Liste des vulnérabilités détectées
        stats: Statistiques de risque
        system_info: Informations sur le système
        
    Returns:
        Rapport formaté en texte brut
    """
    lines = []
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # En-tête
    lines.append("=" * 80)
    lines.append("RAPPORT DE SCAN DE VULNÉRABILITÉS")
    lines.append("=" * 80)
    lines.append(f"Date du scan: {scan_date}")
    lines.append(f"Système: {system_info['os']} {system_info['os_release']}")
    lines.append(f"Architecture: {system_info['architecture']}")
    lines.append(f"Python: {system_info['python_version']}")
    if stats['data_sources']:
        lines.append(f"Sources de données: {', '.join(stats['data_sources'])}")
    lines.append("")
    
    # Résumé exécutif
    lines.append("=" * 80)
    lines.append("RÉSUMÉ EXÉCUTIF")
    lines.append("=" * 80)
    lines.append(f"Total de vulnérabilités: {stats['total_vulnerabilities']}")
    lines.append(f"  🔴 CRITICAL: {stats['critical_count']}")
    lines.append(f"  🟠 HIGH:     {stats['high_count']}")
    lines.append(f"  🟡 MEDIUM:   {stats['medium_count']}")
    lines.append(f"  🟢 LOW:      {stats['low_count']}")
    if stats['unknown_count'] > 0:
        lines.append(f"  ⚪ UNKNOWN:  {stats['unknown_count']}")
    lines.append(f"\nScore CVSS moyen: {stats['average_cvss_score']}")
    lines.append(f"Score CVSS total: {stats['total_cvss_score']}")
    lines.append("")
    
    # Détails des vulnérabilités
    if vulnerabilities:
        lines.append("=" * 80)
        lines.append("DÉTAILS DES VULNÉRABILITÉS")
        lines.append("=" * 80)
        
        classified = classify_vulnerabilities_by_severity(vulnerabilities)
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            vulns = classified[severity]
            if not vulns:
                continue
            
            color = SEVERITY_LEVELS.get(severity, {"color": "⚪"})["color"]
            lines.append(f"\n{color} {severity} - {len(vulns)} vulnérabilités")
            lines.append("-" * 80)
            
            for i, vuln in enumerate(vulns, 1):
                lines.append(f"\n[{i}] {vuln['package']} v{vuln['installed_version']}")
                lines.append(f"    CVE ID: {vuln['cve_id']}")
                lines.append(f"    Source: {vuln['source']}")
                lines.append(f"    CVSS Score: {vuln['cvss_score']}")
                lines.append(f"    Description: {vuln['description']}")
                lines.append(f"    Plage affectée: {vuln['affected_range']}")
                lines.append(f"    Version corrigée: {vuln['fixed_version']}")
                
                if vuln.get('references'):
                    lines.append(f"    Références:")
                    for ref in vuln['references'][:2]:
                        lines.append(f"      - {ref}")
    
    return "\n".join(lines)


def save_json_report(vulnerabilities: List[Dict], stats: Dict, system_info: Dict, filepath: str) -> None:
    """Sauvegarde le rapport au format JSON."""
    report_data = {
        "scan_metadata": {
            "scan_date": datetime.now().isoformat(),
            "system_info": system_info,
            "scanner_version": "2.1.0"
        },
        "statistics": stats,
        "vulnerabilities": vulnerabilities
    }
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"   ✓ Rapport JSON: {os.path.basename(filepath)}")


def save_csv_report(vulnerabilities: List[Dict], filepath: str) -> None:
    """Sauvegarde le rapport au format CSV."""
    if not vulnerabilities:
        print("   ⚠ Aucune vulnérabilité à exporter en CSV")
        return
    
    fieldnames = [
        "package", "installed_version", "package_type", "source", "cve_id", 
        "cvss_score", "severity", "description", "fixed_version", "affected_range"
    ]
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(vulnerabilities)
    
    print(f"   ✓ Rapport CSV: {os.path.basename(filepath)}")


def save_text_report(report_text: str, filepath: str) -> None:
    """Sauvegarde le rapport au format texte."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    print(f"   ✓ Rapport texte: {os.path.basename(filepath)}")


# ============================================================================
# INTERFACE EN LIGNE DE COMMANDE (CLI)
# ============================================================================

def print_banner():
    """Affiche la bannière du programme."""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    🛡️  SIMPLE VULNERABILITY SCANNER 🛡️                       ║
║                                                                              ║
║                   Scanner de Vulnérabilités pour Python                     ║
║                          Version 2.1.0 - 2026                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_usage():
    """Affiche le manuel d'utilisation complet."""
    print_banner()
    
    usage = """
DESCRIPTION:
    SimpleVulnScan est un outil d'audit de sécurité qui scanne vos paquets
    Python installés et identifie les vulnérabilités connues (CVE) en 
    interrogeant des bases de données publiques de vulnérabilités.

USAGE:
    simplevulnscan [OPTIONS]
    python simplevulnscan.py [OPTIONS]

OPTIONS:
    -f, --fast          Scan rapide utilisant uniquement OSV (recommandé)
                        • Plus rapide (~30 secondes pour 100 paquets)
                        • Base de données la plus complète et à jour
                        • Couvre PyPI et de nombreux autres écosystèmes
    
    -d, --deep          Scan en profondeur avec toutes les sources
                        • Plus lent (~2-3 minutes pour 100 paquets)
                        • OSV + Safety DB pour une double vérification
                        • Détection plus exhaustive des vulnérabilités
    
    -h, --help          Affiche ce manuel d'utilisation

EXEMPLES:
    # Afficher le manuel (aucun argument)
    simplevulnscan
    
    # Scan rapide (recommandé pour usage quotidien)
    simplevulnscan --fast
    simplevulnscan -f
    
    # Scan en profondeur (audits de sécurité complets)
    simplevulnscan --deep
    simplevulnscan -d

SOURCES DE DONNÉES:
    • OSV (Open Source Vulnerabilities) - Base de données Google
      └─ Couvre: PyPI, npm, Go, Maven, NuGet, et plus
      └─ Mise à jour: Continue
      └─ Qualité: Excellente (agrégation de multiples sources)
    
    • Safety DB - Base de données PyUp.io (mode --deep uniquement)
      └─ Couvre: Packages Python uniquement
      └─ Mise à jour: Régulière
      └─ Qualité: Bonne (focus Python)

RAPPORTS GÉNÉRÉS:
    Les rapports sont automatiquement créés dans le dossier:
    rapports/scan_YYYYMMDD_HHMMSS/
    
    Fichiers générés:
    • vuln_report.txt        - Rapport texte détaillé
    • vuln_report.json       - Rapport JSON (pour automatisation)
    • vuln_report.csv        - Rapport CSV (pour tableurs)
    • remediation_plan.txt   - Plan de remédiation avec commandes

NIVEAUX DE SÉVÉRITÉ (CVSS):
    🔴 CRITICAL (9.0-10.0)  - Action immédiate requise
    🟠 HIGH     (7.0-8.9)   - Correction prioritaire
    🟡 MEDIUM   (4.0-6.9)   - Planifier une correction
    🟢 LOW      (0.1-3.9)   - Correction recommandée

SUPPORT:
    Pour signaler des bugs ou demander des fonctionnalités:
    GitHub: https://github.com/votre-repo
    Email: security@votre-domaine.com

LICENCE:
    MIT License - Libre d'utilisation et de modification
"""
    print(usage)
    print("=" * 80)


def parse_arguments():
    """
    Parse les arguments de ligne de commande.
    
    Returns:
        Namespace contenant les arguments parsés
    """
    parser = argparse.ArgumentParser(
        description="Scanner de vulnérabilités pour paquets Python",
        add_help=False  # On gère notre propre --help
    )
    
    parser.add_argument(
        '-f', '--fast',
        action='store_true',
        help='Scan rapide (OSV uniquement)'
    )
    
    parser.add_argument(
        '-d', '--deep',
        action='store_true',
        help='Scan en profondeur (toutes les sources)'
    )
    
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='Affiche le manuel d\'utilisation'
    )
    
    return parser.parse_args()


# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

def classified_max_priority(vulnerabilities: List[Dict]) -> str:
    """Détermine le niveau de priorité maximal."""
    classified = classify_vulnerabilities_by_severity(vulnerabilities)
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if classified[severity]:
            color = SEVERITY_LEVELS.get(severity, {"color": "⚪"})["color"]
            return f"{color} {severity}"
    
    return "NONE"


def main():
    """Fonction principale orchestrant le scan de vulnérabilités."""
    
    # Parser les arguments
    args = parse_arguments()
    
    # Si --help ou aucun argument, afficher le manuel
    if args.help or (not args.fast and not args.deep):
        print_usage()
        return
    
    # Déterminer le mode de scan
    if args.fast and args.deep:
        print("⚠️  Erreur: Les options --fast et --deep sont mutuellement exclusives")
        print("   Utilisez 'simplevulnscan --help' pour plus d'informations\n")
        sys.exit(1)
    
    scan_mode = SCAN_MODE_FAST if args.fast else SCAN_MODE_DEEP
    
    # Afficher la bannière
    print("\n" + "=" * 80)
    print("🛡️  SCANNER DE VULNÉRABILITÉS - Audit de Sécurité")
    print("=" * 80 + "\n")
    
    # Étape 1: Informations système
    print("📋 Collecte des informations système...")
    system_info = get_system_info()
    print(f"   Système: {system_info['os']} {system_info['os_release']}")
    print(f"   Python: {system_info['python_version']}\n")
    
    # Étape 2: Énumération des paquets
    packages = enumerate_all_packages()
    
    if not packages:
        print("❌ Aucun paquet détecté. Impossible de continuer le scan.")
        return
    
    # Étape 3: Scan des vulnérabilités
    vulnerabilities = scan_all_packages(packages, scan_mode)
    
    # Étape 4: Calcul des statistiques
    stats = calculate_risk_statistics(vulnerabilities)
    
    # Étape 5: Création de la structure de dossiers
    print("📁 Création de la structure de dossiers...")
    scan_dir = create_report_directory()
    
    # Étape 6: Génération des rapports
    print("📄 Génération des rapports...")
    
    # Rapport texte
    text_report = generate_text_report(vulnerabilities, stats, system_info)
    print("\n" + text_report)
    save_text_report(text_report, os.path.join(scan_dir, "vuln_report.txt"))
    
    # Rapport JSON
    save_json_report(vulnerabilities, stats, system_info, os.path.join(scan_dir, "vuln_report.json"))
    
    # Rapport CSV
    if vulnerabilities:
        save_csv_report(vulnerabilities, os.path.join(scan_dir, "vuln_report.csv"))
    
    # Rapport de remédiation
    if vulnerabilities:
        remediation = generate_remediation_report(vulnerabilities)
        print("\n" + remediation)
        save_text_report(remediation, os.path.join(scan_dir, "remediation_plan.txt"))
        print(f"   ✓ Plan de remédiation: remediation_plan.txt")
    else:
        print("\n" + "=" * 80)
        print("✅ EXCELLENT! Aucune vulnérabilité détectée.")
        print("=" * 80)
    
    # Résumé final
    print("\n" + "=" * 80)
    print("📊 RÉSUMÉ DU SCAN")
    print("=" * 80)
    print(f"Paquets analysés: {len(packages)}")
    print(f"Vulnérabilités détectées: {stats['total_vulnerabilities']}")
    if stats['data_sources']:
        print(f"Sources de données: {', '.join(stats['data_sources'])}")
    if vulnerabilities:
        print(f"Priorité maximale: {classified_max_priority(vulnerabilities)}")
    print(f"\n📂 Tous les rapports disponibles dans: {scan_dir}/")
    print("=" * 80 + "\n")


# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrompu par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)