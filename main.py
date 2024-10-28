from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone
import base64
import json
import jwt
import sqlite3
import os
#used the outline from the zip codes provided by the professor from project 1
hostName = "localhost" 
serverPort = 8080 
DATABASE_FILE = "totally_not_my_privateKeys.db" #including the database
# Initialize the SQLite database
def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS keys")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid TEXT PRIMARY KEY,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    setup_keys() #keys for the databse

# Insert a new private key into the database
def insert_private_key(kid, pem_key, exp_time):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)
    ''', (kid, pem_key.decode("utf-8"), int(exp_time.timestamp()))) #Store PEM as UTF-8
    conn.commit()
    conn.close()
# Function to convert integers to base 64
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Generate and save initial private keys
def setup_keys():
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    expired_kid = "expiredKID"
    valid_kid = "goodKID"

    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Insert both keys into the database with expiration times
    insert_private_key(expired_kid, expired_pem, datetime.now(timezone.utc) - timedelta(hours=1))
    insert_private_key(valid_kid, valid_pem, datetime.now(timezone.utc) + timedelta(hours=1)) 
# expiration will fetch a key in the database
def get_key(expired=False):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT kid, key FROM keys WHERE exp < ?", (int(datetime.now(timezone.utc).timestamp()),))
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(datetime.now(timezone.utc).timestamp()),))
    result = cursor.fetchone()
    conn.close()
    return result if result else (None, None)
# Fetch all valid key for JWKS
def get_valid_keys():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(datetime.now(timezone.utc).timestamp()),))
    keys = cursor.fetchall()
    conn.close()
    return keys

#main class for the server
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            expired = 'expired' in params
            kid, pem_key = get_key(expired)
            if pem_key is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found")
                return

            # Deserialize PEM key for JWT signing
            private_key = serialization.load_pem_private_key(pem_key.encode("utf-8"), password=None)
            headers = {"kid": kid}
            token_payload = {
                "user": "username",
                "exp": datetime.now(timezone.utc) + timedelta(hours=1) if not expired else datetime.now(timezone.utc) - timedelta(hours=1)
            }
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            keys = get_valid_keys()
            jwks_keys = []
            for kid, key_pem in keys:
                private_key = serialization.load_pem_private_key(key_pem.encode("utf-8"), password=None)
                numbers = private_key.private_numbers().public_numbers
                jwks_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            jwks = json.dumps({"keys": jwks_keys})
            self.wfile.write(bytes(jwks, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

#starts the server
if __name__ == "__main__":
    initialize_database()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Server started at http://{hostName}:{serverPort}")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
