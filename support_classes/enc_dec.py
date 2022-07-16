import base64

from cryptography.fernet import Fernet


class EncDec():
    """Class for encrypting and decrypting strings"""

    def __init__(self, logger, password: str, cell: str):
        self.cell: str = cell
        self.pwd: bytes = bytes(password, 'UTF-8')
        self.logger = logger

    def fernetInit(self):
        key = base64.urlsafe_b64encode(self.pwd)
        f = Fernet(key)
        return f

    def encryptCell(self) -> str:
        """Encrypt string with password"""
        f = self.fernetInit()
        encCell = f.encrypt(self.cell.encode())
        self.logger.info('Encrypted cell')
        return encCell.decode('UTF-8')

    def decryptCell(self) -> str:
        """Decrypt string with password"""
        f = self.fernetInit()
        decCell = f.decrypt(bytes(self.cell, 'UTF-8')).decode()
        self.logger.info('Decrypted cell')
        return decCell


# if __name__ == '__main__':
#     msg = 'some message'
    # # ed = EncDec(logger, msg)
    # encrypt = ed.encryptCell()
    # print(encrypt)
    # ed.cell = encrypt
    # dec = ed.decryptCell()
    # print(dec)
