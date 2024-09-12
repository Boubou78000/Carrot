import secrets
import hashlib

def XOR(a: bytes, b: bytes):
    return (int.from_bytes(a) ^ int.from_bytes(b)).to_bytes(len(a))

class Carrot256:

    @staticmethod
    def encrypt(data: bytes, master_key: bytes) -> tuple[bytes, bytes]:

        if len(master_key) != 32:
            raise RuntimeError(f"Invalid master key length ({len(master_key) * 8} isn't equal to 256).")
        
        key = secrets.token_bytes(32)
        shake = hashlib.shake_256(key)

        cipher = XOR(
            shake.digest(len(data)),
            data
        )

        key = XOR(
            master_key,
            key
        )

        return cipher, key


    @staticmethod
    def decrypt(cipher: bytes, master_key: bytes, key: bytes) -> bytes:

        if len(master_key) != 32:
            raise RuntimeError(f"Invalid master key length ({len(master_key) * 8} isn't equal to 256).")
        elif len(key) != 32:
            raise RuntimeError(f"Invalid key length ({len(key) * 8} isn't equal to 256).")
        
        key = XOR(
            master_key,
            key
        )

        shake = hashlib.shake_256(key)

        data = XOR(
            shake.digest(len(cipher)),
            cipher
        )

        return data