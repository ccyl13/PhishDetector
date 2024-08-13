#!/usr/bin/env python3

import re
import sys
import os
import whois
import requests
import dkim
import spf
from email import message_from_binary_file
from email.header import decode_header
from urllib.parse import urlparse
import dns.resolver
from termcolor import colored

# Configuración de API para VirusTotal y Google Safe Browsing
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'
GOOGLE_SAFE_BROWSING_API_KEY = 'your_google_safe_browsing_api_key'

def decode_header_value(header_value):
    decoded_parts = decode_header(header_value)
    decoded_str = ''.join(part.decode(encoding or 'utf-8') if isinstance(part, bytes) else part for part, encoding in decoded_parts)
    return decoded_str

def analyze_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        if whois_info.domain_name:
            return f"Dominio registrado. Información WHOIS: Registrador: {whois_info.registrar}, Fecha de creación: {whois_info.creation_date}, Fecha de expiración: {whois_info.expiration_date}"
        else:
            return "Dominio no registrado."
    except Exception as e:
        return f"Error al obtener WHOIS: {e}"

def check_url_reputation(url):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        encoded_url = requests.utils.quote(url)
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{encoded_url}', headers=headers)
        data = response.json()
        if data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
            return "URL maliciosa en VirusTotal."
    except Exception as e:
        return f"Error en consulta VirusTotal: {e}"
    return None

def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "your_client_id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}', json=payload)
        data = response.json()
        if 'matches' in data:
            return "URL maliciosa en Google Safe Browsing."
    except Exception as e:
        return f"Error en consulta Google Safe Browsing: {e}"
    return None

def check_dkim(email):
    dkim_signature = email.get('DKIM-Signature', '')
    if dkim_signature:
        try:
            dkim_status = dkim.verify(email.as_bytes())
            return "DKIM válido." if dkim_status else "DKIM inválido."
        except Exception as e:
            return f"Error en verificación DKIM: {e}"
    return "No se encontró DKIM."

def check_spf(email_from):
    domain = email_from.split('@')[-1]
    try:
        result, explanation = spf.check2('192.0.2.1', domain, 'recipient@example.com')  # Reemplaza con la IP del servidor de correo real
        if result == 'pass':
            return "SPF válido."
        elif result == 'fail':
            return f"Error en verificación SPF: {explanation}"
        elif result == 'neutral':
            return "SPF neutral: El dominio no tiene una política clara."
        elif result == 'temperror':
            return "Error temporal en verificación SPF."
        elif result == 'permerror':
            return "Error permanente en verificación SPF."
        else:
            return f"Resultado SPF desconocido: {result}"
    except Exception as e:
        return f"Error en verificación SPF: {e}"

def analyze_headers(headers):
    anomalies = []
    from_header = headers.get('From', '')
    from_address = re.findall(r'<(.*?)>', from_header)
    if from_address:
        from_domain = from_address[0].split('@')[-1]
        trusted_domains = ['trusted.com', 'example.com']
        if from_domain not in trusted_domains:
            anomalies.append(colored(f"Dominio del remitente sospechoso: {from_domain}", 'yellow'))
        
        spf_result = check_spf(from_address[0])
        if 'Error' in spf_result:
            anomalies.append(colored(spf_result, 'red'))
        elif "sospechoso" in spf_result.lower():
            anomalies.append(colored(spf_result, 'yellow'))
    
    return anomalies

def analyze_attachments(email):
    suspicious_attachments = []
    for part in email.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        filename = part.get_filename()
        if filename and filename.lower().endswith(('.exe', '.bat')):
            suspicious_attachments.append(colored(f"Adjunto peligroso detectado: {filename}", 'red'))
    return suspicious_attachments

def es_phishing(email_file_path):
    report = []

    try:
        with open(email_file_path, 'rb') as f:
            email = message_from_binary_file(f)

        headers = dict(email.items())
        
        # Información adicional del correo
        subject = decode_header_value(headers.get('Subject', 'No Subject'))
        date = headers.get('Date', 'No Date')
        size = os.path.getsize(email_file_path)
        
        # Verifica si hay contenido en el mensaje
        if email.is_multipart():
            content = ''
            for part in email.walk():
                if part.get_content_type() == 'text/plain':
                    content = part.get_payload(decode=True)
                    break
        else:
            content = email.get_payload(decode=True)

        if content:
            content = content.decode('utf-8', errors='ignore')
        else:
            content = ""

        urls = re.findall(r'http[s]?://\S+', content)

        # Añadir encabezado y detalles
        report.append(colored(" _____  _     _     _     _____       _            _ ", 'cyan'))
        report.append(colored("|  __ \\| |   (_)   | |   |  __ \\     | |          | |", 'cyan'))
        report.append(colored("| |__) | |__  _ ___| |__ | |  | | ___| |_ ___  ___| |_ ___  _ __", 'cyan'))
        report.append(colored("|  ___/| '_ \\| / __| '_ \\| |  | |/ _ \\ __/ _ \\/ __| __/ _ \\| '__|", 'cyan'))
        report.append(colored("| |    | | | | \\__ \\ | | | |__| |  __/ ||  __/ (__| || (_) | |", 'cyan'))
        report.append(colored("|_|    |_| |_|_|___/_| |_|_____/ \\___|\\__\\___|\\___|\\__\\___/|_|", 'cyan'))
        report.append(colored("", 'cyan'))
        report.append(colored("Created by Thomas O'Neil", 'cyan'))
        report.append(colored("", 'cyan'))
        report.append(colored("Iniciando el análisis del correo electrónico...", 'cyan'))
        report.append(colored(f" - Asunto: {subject}", 'blue'))
        report.append(colored(f" - Fecha: {date}", 'blue'))
        report.append(colored(f" - Tamaño: {size} bytes", 'blue'))

        # Análisis DKIM
        dkim_status = check_dkim(email)
        report.append(colored(f"- DKIM: {dkim_status}", 'green'))

        # Análisis SPF
        spf_result = check_spf(headers.get('From', ''))
        if 'Error' in spf_result:
            report.append(colored(f"- SPF: {spf_result}", 'red'))
        elif "sospechoso" in spf_result.lower():
            report.append(colored(f"- SPF: {spf_result}", 'yellow'))

        # Análisis WHOIS
        from_domain = headers.get('From', '').split('@')[-1]
        whois_result = analyze_whois_info(from_domain)
        report.append(colored(f"- WHOIS: {whois_result}", 'green'))

        # Análisis de URL
        for url in urls:
            url_check = check_url_reputation(url) or check_google_safe_browsing(url)
            if url_check:
                report.append(colored(url_check, 'red'))

        # Análisis de archivos adjuntos
        attachments = analyze_attachments(email)
        if attachments:
            report.extend(attachments)

        # Resultados del análisis
        header_anomalies = analyze_headers(headers)
        if header_anomalies:
            report.extend(header_anomalies)

        if not any(["sospechoso" in line.lower() for line in report]):
            report.append(colored("No se encontraron problemas graves en el análisis del correo.", 'green'))
        else:
            report.append(colored("¡ALERTA: Posible correo de phishing detectado!", 'red'))

    except Exception as e:
        report.append(colored(f"Error al analizar el correo: {e}", 'red'))

    return '\n'.join(report)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(colored("Uso: ./phish_detector.py <archivo_de_correo>", 'red'))
        sys.exit(1)

    email_file_path = sys.argv[1]
    if not os.path.isfile(email_file_path):
        print(colored(f"El archivo {email_file_path} no existe.", 'red'))
        sys.exit(1)

    print(es_phishing(email_file_path))
