from base64 import b64decode, b64encode
from binascii import unhexlify
from os import urandom
from typing import Union

from cryptography.exceptions import AlreadyUpdated
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7 as padding
from fxa.crypto import verify_hmac


class KeyBundle(object):
    def __init__(self, key, hmac_key):
        if isinstance(key, str):
            self.__key = b64decode(key)
        elif isinstance(key, bytes):
            if len(key) == 32:
                self.__key = key
            else:
                raise ValueError('unsupported key type: key')
        else:
            raise ValueError('unsupported key type: key')

        if isinstance(hmac_key, str):
            self.__hmac_key = b64decode(hmac_key)
        elif isinstance(hmac_key, bytes):
            if len(hmac_key) == 32:
                self.__hmac_key = hmac_key
            else:
                raise ValueError('unsupported key type: key')
        else:
            raise ValueError('unsupported key type: key')

    @property
    def key(self):
        return self.__key

    @property
    def hmac_key(self):
        return self.__hmac_key


class AESCipher(object):
    def __init__(self, key: KeyBundle,
                 iv: Union[bytes, str] = None,
                 HMAC: Union[bytes, str] = None):
        self._acquire_iv = False

        self._key = key

        if iv is not None:
            if isinstance(iv, str):
                Warning("Cipher : imported iv is str.(b64encoded).")
                self._iv = b64decode(iv)
            else:
                self._iv = iv
        else:
            self._iv = urandom(16)
            self._acquire_iv = True

        if HMAC is not None:
            if isinstance(HMAC, str):
                Warning("Cipher : imported HMAC is str.(hexlified).")
                self._HMAC = unhexlify(HMAC)
            else:
                self._HMAC = HMAC

        self._cipher = Cipher(algorithm = AES(self._key.key),
                              mode = CBC(self._iv),
                              backend = default_backend()
                              )
        self._padding = padding(AES.block_size)

    def _make_encryptor(self):
        self.encryptor = self._cipher.encryptor()
        self.padder = self._padding.padder()

    def _make_decryptor(self):
        self.decryptor = self._cipher.decryptor()
        self.unpadder = self._padding.unpadder()

    def instantencrypt(self, text: bytes) -> bytes:
        self._make_encryptor()

        padded_text = self.padder.update(text) + self.padder.finalize()
        ciphedtext = self.encryptor.update(padded_text) + self.encryptor.finalize()
        return ciphedtext

    def instantdecrypt(self, ciphertext: bytes) -> bytes:
        self._make_decryptor()

        if self._HMAC is not None:
            verify_hmac(self._key.hmac_key, b64encode(ciphertext), self._HMAC)
        else:
            Warning('ciphertext is not verified by HMAC')

        padded_text = self.decryptor.update(ciphertext) + self.decryptor.finalize()  # type: bytes
        text = self.unpadder.update(padded_text) + self.unpadder.finalize()
        return text

    @property
    def iv(self):
        if self._acquire_iv == True:
            self._acquire_iv = False
            return self._iv
        else:
            raise AlreadyUpdated
