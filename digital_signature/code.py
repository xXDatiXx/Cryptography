from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# https://chatgpt.com/c/67298ccb-3d48-8009-8a91-9a6e37a58842
# Generar par de llaves (privada y pública)
# En este paso se generan dos llaves: una privada y una pública.
# La llave privada se utiliza para firmar los mensajes, mientras que la llave pública se utiliza para verificar la firma.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
print("Llave privada generada.")
print("Llave pública generada.")

# Mensaje a firmar
# Solicitamos al usuario que ingrese un mensaje, el cual será convertido a bytes para poder firmarlo.
mensaje = input("Ingrese el mensaje a firmar: ").encode()
print(f"Mensaje a firmar: {mensaje.decode()}")

# Firmar el mensaje
# Utilizamos la llave privada para firmar el mensaje.
# La firma se genera aplicando un esquema de padding PSS y el hash SHA-256 para garantizar la seguridad.
print("Firmando el mensaje...")
firma = private_key.sign(
    mensaje,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Firma generada con éxito.")
print(f"Firma generada: {firma}")

# Verificar la firma
# Utilizamos la llave pública para verificar la validez de la firma.
# Si la firma coincide con el mensaje y la llave pública, la verificación será exitosa; de lo contrario, fallará.
print("Verificando la firma...")
try:
    public_key.verify(
        firma,
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("La firma es válida.")
except Exception as e:
    print("La firma no es válida.")
