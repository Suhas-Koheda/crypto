"""
CHAMP Auth Package
Provides bcrypt, Argon2id, and scrypt authentication modules.
"""
from auth.bcrypt_auth import hash_password as bcrypt_hash, verify_password as bcrypt_verify
from auth.argon2_auth import hash_password as argon2_hash, verify_password as argon2_verify
from auth.scrypt_auth import hash_password as scrypt_hash, verify_password as scrypt_verify

__all__ = [
    "bcrypt_hash", "bcrypt_verify",
    "argon2_hash", "argon2_verify",
    "scrypt_hash", "scrypt_verify",
]