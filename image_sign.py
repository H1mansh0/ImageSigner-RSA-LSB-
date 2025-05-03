"""
ImageSigner: Uses RSA and LSB to sign and verify images
"""

import hashlib
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


class ImageSigner:
    """
    Class to sign images using RSA and LSB steganography,
    and verify the signature embedded in an image.
    """
    KEY_SIZE = 4096

    def __init__(self, image_path: str):
        self.image_path = image_path
        self.signed_image = None
        self.signature = None
        self.__generate_keys()

    def __generate_keys(self) -> None:
        """Generates RSA private and public keys in memory"""
        self.__private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.KEY_SIZE
        )
        self.__public_key = self.__private_key.public_key()

    def __generate_signature(self) -> None:
        """Digitally signs the image using the private RSA key"""
        # --- CHANGES ---
        img = Image.open(self.image_path).convert("RGB")
        img_arr = np.array(img)
        flat_img = img_arr.flatten()
        flat_img[:self.KEY_SIZE] &= 0b11111110
        cleared_img_arr = flat_img.reshape(img_arr.shape)

        image_bytes = cleared_img_arr.tobytes()

        hash_digest = hashlib.sha256(image_bytes).digest()
        # --- END CHANGES ---

        self.signature = self.__private_key.sign(
            hash_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def sign_image(self, output_path: str) -> None:
        """Embeds the RSA digital signature into the LSBs of the image pixels"""
        self.__generate_signature()
        signature_bits = ''.join(f'{byte:08b}' for byte in self.signature)
        bit_iter = iter(signature_bits)

        img = Image.open(self.image_path).convert('RGB')
        img_arr = np.array(img).flatten()

        for i, byte in enumerate(img_arr):
            try:
                img_arr[i] = (byte & 0b11111110) | int(next(bit_iter))
            except StopIteration:
                break

        signed_img = Image.fromarray(img_arr.reshape(*img.size[::-1], 3).astype('uint8'), 'RGB')
        signed_img.save(output_path)

    def _extract_signature(self, signed_img_path: str) -> bytes:
        """Extracts the signature from the LSBs of the image"""
        img = Image.open(signed_img_path).convert('RGB')
        img_arr = np.array(img).flatten()

        bits = ''.join(str(pixel & 1) for pixel in img_arr[:self.KEY_SIZE])
        bytes_out = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]
        return bytes(bytes_out)

    def check_for_signature(self, psble_signed_img_path: str) -> bool:
        """
        Checks whether the provided image contains a signature in the LSBs.
        Returns True if likely signed, otherwise False.
        """
        original = Image.open(self.image_path).convert("RGB")
        possible_signed = Image.open(psble_signed_img_path).convert("RGB")

        original_arr = np.array(original).flatten()
        signed_arr = np.array(possible_signed).flatten()

        if original_arr.shape != signed_arr.shape:
            print("Images have different shapes")
            return False

        if not np.array_equal(original_arr[4096:], signed_arr[4096:]):
            print("Images differ beyond the signature region")
            return False

        return True

    def verify_signature(self, signed_img_path: str) -> bool:
        """Verifies the extracted signature using the public key"""
        if not self.check_for_signature(signed_img_path):
            print("Verification aborted: No signature found")
            return False

        # --- CHANGES ---
        signed_img = Image.open(signed_img_path).convert("RGB")
        signed_img_arr = np.array(signed_img)
        flat_signed_img = signed_img_arr.flatten()
        flat_signed_img[:self.KEY_SIZE] &= 0b11111110
        cleared_signed_img_arr = flat_signed_img.reshape(signed_img_arr.shape)

        singed_hash_img = hashlib.sha256(cleared_signed_img_arr.tobytes()).digest()
        # --- END CHANGES ---

        extracted_signature = self._extract_signature(signed_img_path)

        try:
            self.__public_key.verify(
                extracted_signature,
                singed_hash_img,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature is valid")
            return True
        except InvalidSignature:
            print("Signature is invalid")
            return False
