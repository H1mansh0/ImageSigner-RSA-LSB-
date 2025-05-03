"""NEW EXAMPLE OF WORKING"""
from image_sign import ImageSigner

signer = ImageSigner(image_path="img/test_image.bmp")

signer.sign_image(output_path="img/test_image_signed_2.bmp")

assert signer.verify_signature(signed_img_path="img/test_image_signed_2.bmp")
