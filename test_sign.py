"""Script to test implementation of ImageSigner class"""
from image_sign import ImageSigner

signer = ImageSigner(image_path="img/test_image.bmp")

signer.sign_image(output_path="img/test_image_signed.bmp")

assert signer.check_for_signature(psble_signed_img_path="img/test_image_signed.bmp") is True
assert signer.check_for_signature(psble_signed_img_path="img/test_image.bmp") is False

# Test must return True because this function only validate the signature existance
assert signer.check_for_signature(psble_signed_img_path="img/corrupted_sign.bmp") is True

assert signer.verify_signature(signed_img_path="img/test_image_signed.bmp") is True
assert signer.verify_signature(signed_img_path="img/test_image.bmp") is False # don't have signature
assert signer.verify_signature(signed_img_path="img/corrupted_sign.bmp") is False # corrupted sign

# Check statement from block "Додаткове"
signer.sign_image(output_path="img/test_image_signed.png")
signer.sign_image(output_path="img/test_image_signed.jpeg")

assert signer.verify_signature(signed_img_path="img/test_image_signed.png") is True
assert signer.verify_signature(signed_img_path="img/test_image_signed.jpeg") is False
