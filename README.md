# PhishDetector

PhishDetector es una herramienta para detectar correos electrónicos de phishing mediante análisis DKIM y SPF. 

## Captura de Pantalla

![PhishDetector Screenshot](https://github.com/ccyl13/PhishDetector/blob/main/2.png)

> **Nota:** Asegúrate de reemplazar `ruta/a/tu/imagen.png` con la URL correcta de la imagen en tu repositorio o en la web.

## Instalación
Dependencias

Antes de ejecutar el script, instala las siguientes dependencias de Python:

pip install dkimpy termcolor python-spf whois requests dnspython

Uso

Para ejecutar el análisis de un correo electrónico:

./phish_detector.py /ruta/al/correo/malwarebytes.eml

Reemplaza /ruta/al/correo/malwarebytes.eml con la ruta real al archivo .eml que deseas analizar.

1. **Clonar el Repositorio**

   ```bash
   git clone https://github.com/ccyl13/PhishDetector.git
   cd new_phish_detector
   chmod +x phish_detector.py
   ./phish_detector.py /ruta/detucorreo/nombredelcorreodescargado.eml
