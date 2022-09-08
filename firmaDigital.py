import base64
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA

def firmar(mensaje):
    with open('ClavePrivada.txt') as f:
        key=f.read()
        rsakey= RSA.importKey(key)
        signer= Signature_pkcs1_v1_5.new(rsakey)
        digest=SHA.new()
        digest.update(mensaje)
        print('Contenido del documento: ', mensaje)
        print("Se genero el hash", digest.hexdigest())
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
    
    with open('firma.txt', 'wb') as fp1:
        fp1.write(signature)
        fp1.close()

    print("Firma creada", signature)
    print("Firma guardada en : firma.txt")

with open("datos.txt",'r') as f1:
    mensaje=f1.read()

mensaje=mensaje.encode()
signature=firmar(mensaje)

