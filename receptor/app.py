from flask import Flask, jsonify, request
import os
from cryptography.fernet import Fernet
import rsa


'''
Passos (receptor):

1 - Gerar par de chave e postar a chave pública no arquivo chave_publica.txt

2 - Descriptografar pacote enviado {'mensagem_cifrada': 'XXXXXXXXXXXXXXXX',
                                    'chave_simetrica_cifrada': 'YYYYYYYYYYYYYYYYY'}
    com chave privada.

3 - Usar conteúdo da 'chave_simetrica_cifrada' já descriptografada para descriptografar (mais um vez) a mensagem

4 - Fazer print da mensagem original
'''


# Função para gerar par de chaves e escrevê-las em 2 arquivos distintos
def generate_key_pair():
    public_key, private_key = rsa.newkeys(2048)

    with open("public_key.pem", "w") as f:
        f.write(public_key.save_pkcs1().decode('utf-8'))

    with open("private_key.pem", "w") as f:
        f.write(private_key.save_pkcs1().decode('utf-8'))

    return


class MyFlaskApp(Flask):
    def run(self, host=None, port=None, debug=None, load_dotenv=True, **options):
        if not self.debug or os.getenv('WERKZEUG_RUN_MAIN') == 'true':
            with self.app_context():
                generate_key_pair()
        super(MyFlaskApp, self).run(host=host, port=port, debug=debug, load_dotenv=load_dotenv, **options)


app = MyFlaskApp(__name__)
app.run()


@app.route('/receive_message', methods=['POST'])
def receive_message():

    message_content = request.json
    encrypted_message = message_content['encrypted message']
    simmetric_key = message_content['simmetric key']

    key = Fernet(simmetric_key)
    plain_text = key.decrypt(encrypted_message).decode()

    data = {
        'Mensagem encriptada': encrypted_message,
        'Mensagem limpa': plain_text,
    }

    return jsonify(data), 200

    # try:
    #     print('entrou na rota do receptor')
    #     recebido = request.json.get('message')
    #     print(recebido)

        # encrypted_symetric_key = content['chave_simetrica_cifrada']
        # encrypted_message = content['mensagem_cifrada']

        # with open("private_key.pem", "rb") as key_file:
        #     private_key = serialization.load_pem_private_key(
        #         key_file.read(),
        #         password=None,
        #         backend=default_backend()
        #     )

        # decrypted_symetric_key = private_key.decrypt(
        #     encrypted_symetric_key,
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )

        # decrypted_message = private_key.decrypt(
        #     encrypted_message,
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )

        # fernet = Fernet(decrypted_symetric_key)
        # message = fernet.decrypt(decrypted_message).decode()

        # print(message)

    #     sucesso = {
    #         'status': 'Mensagem lida com sucesso.'
    #     }

    #     return jsonify(sucesso), 200

    # except Exception as e:
    #     print(e)

    #     error = {
    #         'status': 'Error.'
    #     }

    #     return jsonify(error), 500
