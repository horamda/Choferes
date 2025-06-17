# utils.py
from PIL import Image
from io import BytesIO

def redimensionar_imagen(blob, max_size=(300, 300)):
    """
    Redimensiona una imagen binaria a un tamaño máximo (por defecto 300x300 px)
    y la devuelve en formato JPEG.
    """
    imagen = Image.open(BytesIO(blob))
    imagen.thumbnail(max_size)
    buffer = BytesIO()
    imagen.save(buffer, format="JPEG")
    return buffer.getvalue()