# app.py

from flask import Flask, request, jsonify
from encryption import encrypt_string, decrypt_string

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    return {"message": "AES Encryptor API running."}


@app.route("/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json()
    plaintext = data.get("plaintext")
    password = data.get("password")

    if not plaintext or not password:
        return jsonify({"error": "Both plaintext and password are required."}), 400

    try:
        encrypted = encrypt_string(plaintext, password)
        return jsonify({"encrypted": encrypted})
    except Exception as e:
        return jsonify({"error": "Encryption failed", "details": str(e)}), 500


@app.route("/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json()
    encrypted = data.get("encrypted")
    password = data.get("password")

    if not encrypted or not password:
        return jsonify({"error": "Both encrypted text and password are required."}), 400

    decrypted = decrypt_string(encrypted, password)
    if decrypted is None:
        return jsonify({"error": "Decryption failed. Check password or input."}), 400

    return jsonify({"decrypted": decrypted})


if __name__ == "__main__":
    app.run(debug=True)
