from hmac import digest
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64
from Crypto import Random
from os import system


#limpiar la consola 
system("cls")

print("Cifrado de datos con python \n")
#Generar la llave publica y privada
random_generator= Random.new().read
rsa=RSA.generate(1024,random_generator)

ClavePrivada=rsa.exportKey()
with open('ClavePrivada.txt', 'wb') as f:
    f.write(ClavePrivada)

ClavePublica=rsa.publickey().exportKey()
with open('ClavePublica.txt','wb') as f:
    f.write(ClavePublica)

#Se muestran las llaves solo para ver que el programa funciona
print("Se crearon correctamente las llaves \n")
print("LLave privada ", ClavePrivada,"\n")
print("Llave publica ", ClavePublica, "\n")


#Funcion para crear la firma
def firmar(mensaje):
    with open('ClavePrivada.txt') as f:
        key=f.read()
        rsakey= RSA.importKey(key)
        signer= Signature_pkcs1_v1_5.new(rsakey)
        digest=SHA.new()
        digest.update(mensaje)
        print("\n")
        print('Contenido del documento: ', mensaje, "\n")
        print("Se genero el hash", digest.hexdigest(), "\n")
        sign = signer.sign(digest)
        signature = base64.b64encode(sign)
    
    with open('firma.txt', 'wb') as fp1:
        fp1.write(signature)
        fp1.close()

    print("Firma creada", signature, "\n")
    print("Firma guardada en : firma.txt", "\n")


#Funcion para verificar el mensaje y la firma de este
def verificar(mensaje, firma):
    with open('ClavePublica.txt') as f:
        key=f.read()
        rsakey= RSA.importKey(key)
        verifier=Signature_pkcs1_v1_5.new(rsakey)
        digest=SHA.new()

        digest.update(mensaje)
        print("\n")
        print("Calcular hash de documento recibido", digest.hexdigest(), "\n")
        print("Desencriptamos la firma, para sacar el hash original \n")
        is_verify=verifier.verify(digest,base64.b64decode(firma))
    if is_verify:
        print("Los hash coinciden \n")
        print("Documento no alterado, autor legitimo \n")
    else:
        print("Los hash no coinciden \n")
        print("Mensaje alterado, firma incorrecta \n")


#Pedir mensaje a usuario
mensaje=input("Ingrese el texto:")

mensaje=mensaje.encode()

signature=firmar(mensaje)
print("\n")
print("Se creara una firma del mensaje")

with open("firma.txt", 'r') as f2:
    firma=f2.read()
verificar(mensaje,firma)