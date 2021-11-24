import flask
import base64
from flask import request
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
import random

key = b"1234567890123456"
plain = b"Here's your secret!"
plain2 = b"Here's your data!"

iv = b"jvHJ1XFt0IXBrxxx"

app = flask.Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def handle_request():
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print(request.data)
    fulldata = cipher.decrypt(base64.urlsafe_b64decode(request.data))
    print(fulldata)
    if b"getSecret" not in fulldata:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encoded = base64.urlsafe_b64encode(cipher.encrypt(pad(plain2, AES.block_size)))
    else:
        ciphere = AES.new(key, AES.MODE_CBC, iv)
        encoded = base64.urlsafe_b64encode(ciphere.encrypt(pad(plain, AES.block_size)))
    print(encoded)
    return encoded

app.run(host="0.0.0.0", port=5000, debug=True)
