from Crypto import Random
from Crypto.PublicKey import RSA

random_generator= Random.new().read
rsa=RSA.generate(1024,random_generator)

ClavePrivada=rsa.exportKey()
with open('ClavePrivada.txt', 'wb') as f:
    f.write(ClavePrivada)

ClavePublica=rsa.publickey().exportKey()
with open('ClavePublica.txt','wb') as f:
    f.write(ClavePublica)

print("Se crearon correctamente las llaves")
print("LLave privada", ClavePrivada)
print("Llave publica", ClavePublica)