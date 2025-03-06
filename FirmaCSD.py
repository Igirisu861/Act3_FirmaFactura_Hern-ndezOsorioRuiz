from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_der_x509_certificate
from lxml import etree
import base64

def load_private_key(key_path, password):
    # Carga la clave privada desde un archivo .key
    with open(key_path, "rb") as key_file:
        clave_privada = serialization.load_der_private_key(
            key_file.read(), password=password.encode(), backend=None
        )
    return clave_privada

def load_certificate(cer_path):
    # Carga el certificado desde un archivo .cer
    with open(cer_path, "rb") as cer_file:
        cert = load_der_x509_certificate(cer_file.read())
    return cert

def generate_sello(clave_privada, cadena_original):
    # Firma la cadena original con la clave privada
    signature = clave_privada.sign(
        cadena_original.encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()

# Rutas de los archivos 
cer_path = "tu_certificado.cer"
key_path = "tu_llave.KEY"
password = "12345678a"

# Cargar llave y certificado
clave_privada = load_private_key(key_path, password)
cert = load_certificate(cer_path)

# Supongamos que ya generaste la cadena original
cadena_original = "||3.3|2024-03-05T12:00:00|...||"  # Reemplázala con la real

# Generar el sello
sello_digital = generate_sello(clave_privada, cadena_original)

print(f"Sello digital generado:\n{sello_digital}")



def insert_sello_in_xml(xml_path, sello):
    # Inserta el sello en el CFDI
    tree = etree.parse(xml_path)
    root = tree.getroot()
    root.attrib["Sello"] = sello
    tree.write("cfdi_firmado.xml", xml_declaration=True, encoding="UTF-8")

xml_path = "cfdi.xml"
insert_sello_in_xml(xml_path, sello_digital)
