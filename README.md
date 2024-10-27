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
