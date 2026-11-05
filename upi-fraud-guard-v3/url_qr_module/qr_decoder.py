"""Local QR-image decoding for payment QR codes.

The decoded content is passed to the existing URL / QR analyser; images are
never stored on disk by this module.
"""
from io import BytesIO

from PIL import Image, UnidentifiedImageError
from pyzbar.pyzbar import decode


def decode_qr_image(content: bytes) -> str:
    if not content:
        raise ValueError("The selected image is empty.")
    if len(content) > 5 * 1024 * 1024:
        raise ValueError("QR images must be 5 MB or smaller.")
    try:
        image = Image.open(BytesIO(content)).convert("RGB")
    except UnidentifiedImageError as error:
        raise ValueError("Please upload a PNG, JPG or other supported image file.") from error
    decoded = decode(image)
    if not decoded:
        raise ValueError("No readable QR code was found in this image.")
    try:
        return decoded[0].data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("The QR payload is not valid UTF-8 text.") from error
