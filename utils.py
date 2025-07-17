from PIL import Image
from io import BytesIO
from contextlib import contextmanager
from mysql.connector import connect, Error
from config import MYSQL_CONFIG

def redimensionar_imagen(blob, max_size=(300, 300), formato='JPEG', calidad=70):
    """
    Redimensiona una imagen binaria a un tamaño máximo (por defecto 300x300 px),
    conserva la proporción, y la devuelve en formato JPEG optimizado.
    """
    try:
        with Image.open(BytesIO(blob)) as imagen:
            imagen.thumbnail(max_size, Image.LANCZOS)  # mejor filtro de reducción
            buffer = BytesIO()
            imagen.convert("RGB").save(buffer, format=formato, quality=calidad, optimize=True)
            return buffer.getvalue()
    except Exception as e:
        print(f"[ERROR] No se pudo procesar la imagen: {e}")
        return None
    


@contextmanager
def db_cursor(dictionary=True):
    conn = connect(**MYSQL_CONFIG)
    cursor = conn.cursor(dictionary=dictionary)
    try:
        yield conn, cursor
        conn.commit()
    except Error as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()    
    
    