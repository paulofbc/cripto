from flask import Flask, jsonify, request
import os
from cryptography.fernet import Fernet
import rsa
from hashlib import sha512


'''
Passos (emissário):

1 - Endpoint para receber mensagem a ser enviada via Postman

2 - Executar busca da chave pública do app_2 (vai estar em um txt)

3 - Buscar chave simétrica e criptografá-la com chave pública do app_2

4 - Enviar mensagem recebida no passo 1 (criptografada com a chave pública do passo 2) + 
        hash da mensagem para garantir completude de entrega (também criptografado) +
        chave simétrica criptografada resultado do passo 3
'''


# Environment + App Receptor (pra gerar os .pem)


app = Flask(__name__)
app.run()


@app.route('/send_message_to_2', methods=['POST'])
def send_message():

    # Separando mensagem original recebida
    message_content = request.json
    message = message_content['message']
    print('Mensagem original\n',message)
    print('\n========================================================================================\n')

    # Criando chave simétrica através do Fernet + encriptando mensagem
    key = Fernet.generate_key()
    fernet = Fernet(key)
    fernet_encrypted_message = fernet.encrypt(message.encode())
    print('Key simétrica do Fernet\n',key)
    print('\n')
    print('Mensagem encriptada com chave simétrica\n',fernet_encrypted_message)
    print('\n========================================================================================\n')

    # Criando hash a partir da mensagem encriptada com chave simétrica
    hash_before = hash(fernet_encrypted_message)

    # Lendo public_key criada pela aplicação "receptor"
    with open("../receptor/public_key.pem", "rb") as f:
        data_receiver_public_key = f.read()
    receiver_public_key = rsa.PublicKey.load_pkcs1(data_receiver_public_key)
    print('Chave pública assimétrica lida\n',receiver_public_key)
    print('\n')

    # Lendo private_key criada pela aplicação "receptor"
    with open("../receptor/private_key.pem", "rb") as f:
        data_receiver_private_key = f.read()
    receiver_private_key = rsa.PrivateKey.load_pkcs1(data_receiver_private_key)
    print('Chave privada assimétrica lida\n',receiver_private_key)
    print('\n========================================================================================\n')

    # Utilizando a chave pública assimétrica do rsa para encriptar tanto a mensagem (já encriptada)
    # quanto a própria chave simétrica
    rsa_enc_message = rsa.encrypt(fernet_encrypted_message, receiver_public_key)
    rsa_symmetric_key = rsa.encrypt(key, receiver_public_key)
    print('Chave simétrica encriptada com pública assimétrica\n',rsa_symmetric_key)
    print('\n')
    print('Mensagem duplamente encriptada (simétrica + pública assimétrica)\n',rsa_enc_message)
    print('\n========================================================================================\n')

    # Decriptando a chave simétrica e a mensagem com a private_key criada pelo rsa
    rsa_symmetric_decrypted_key = rsa.decrypt(rsa_symmetric_key, receiver_private_key)
    rsa_decrypted_message = rsa.decrypt(rsa_enc_message, receiver_private_key)
    print('Chave simétrica decriptada pela privada assimétrica\n',rsa_symmetric_decrypted_key)
    print('\n')
    print('Mensagem decriptada pela privada assimétrica\n',rsa_decrypted_message)
    print('\n========================================================================================\n')

    # Criando hash a partir do material resultante da decriptação da mensagem com a chave privada
    hash_after = hash(rsa_decrypted_message)
    print("Assinatura válida: ", hash_before == hash_after)
    print('\n========================================================================================\n')

    # Utilizando chave simétrica descriptada para desfazer criptografia com chave simétrica da mensagem original
    fernet_decrypted = Fernet(rsa_symmetric_decrypted_key)
    original_message = fernet_decrypted.decrypt(rsa_decrypted_message).decode()
    print('Mensagem original (decriptada pela chave simétrica que já havia sido decriptada)\n',original_message)

    # Tentativa de retorno para o postman (falha na forma de comunicação)
    data_to_return = {
        'encrypted message': str(rsa_enc_message),
        'symmetric key': str(rsa_symmetric_key),
    }

    return data_to_return, 200


@app.route('/receive_message', methods=['POST'])
def receive_message():
    message_content = request.json
    encrypted_message = message_content['encrypted message']
    symmetric_key = message_content['symmetric key']

    key = Fernet(symmetric_key)
    plain_text = key.decrypt(encrypted_message).decode()

    data = {
        'Mensagem encriptada': encrypted_message,
        'Mensagem limpa': plain_text,
    }

    return jsonify(data), 200
