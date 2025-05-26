import os

MYSQL_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'use_pure': True,
    'port': 3306  # Asegurate de que esté este puerto si tu proveedor lo usa
}
