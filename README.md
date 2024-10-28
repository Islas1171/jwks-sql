# jwks-sql
A Python-based JWKS server that generates and serves RSA public keys to
validate JWTs. The server is designed to handle requests for valid and
expired JWTs also provides a public key endpoint for verifying these tokens.

# Server:
1. Generates RSA private keys and saves them to an SQLite database.
2. Provides a JWT issuance endpoint that returns a signed JWT using one of the private keys.
3. Offers a JWKS endpoint that serves the corresponding RSA public
keys for verification.

- JWT Generation: Issues signed tokens based on requested validity.
- JWKS Endpoint: Provides public keys in JWKS format for verifying JWT signatures.
- Database-Backed Key Storage: Stores keys in an SQLite database (`totally_not_my_privateKeys.db`).
- Configurable Expiration: Offers options to generate valid or expired tokens.

# Requirements
- Python 3.12
- SQLite (included with Python/PyCharm)
Install required libraries using `pip`:
pip install cryptography pyjwt

Run the main file then run the http commands to get the correct output.

![post](https://github.com/user-attachments/assets/40d3b9e9-640a-45b3-97a2-fc26cae9abd6)
![htttp](https://github.com/user-attachments/assets/77069b6a-2bb0-4929-9e4a-facd061908c2)
![response](https://github.com/user-attachments/assets/7bc0b7dd-59e9-4814-8654-fb090137aefe)
![getjwks](https://github.com/user-attachments/assets/0bd0920a-5ddb-4083-9324-227a89e186f2)


# Coverage 
![image](https://github.com/user-attachments/assets/b24fa98b-a6c7-460b-a13a-45a7b0cefb40)


# Gradebot

![image](https://github.com/user-attachments/assets/a1cc261c-ae50-48c3-b98d-95f1b45a567b)

