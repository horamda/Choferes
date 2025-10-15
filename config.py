import os
from decouple import config

# Configuración de base de datos
MYSQL_CONFIG = {
    'host': config('DB_HOST', default='localhost'),
    'user': config('DB_USER', default='root'),
    'password': config('DB_PASSWORD', default=''),
    'database': config('DB_NAME', default='choferes'),
    'use_pure': True,
    'port': int(config('DB_PORT', default=3306))
}

# Configuración de aplicación
APP_SECRET_KEY = config('APP_SECRET_KEY', default='cambia_esto_en_produccion')
JWT_SECRET = config('JWT_SECRET', default='cambia_esto_en_produccion_jwt')
JWT_EXPIRE_HRS = int(config('JWT_EXPIRE_HRS', default=8))

# Configuración de Firebase
FIREBASE_SERVICE_ACCOUNT = config('FIREBASE_SERVICE_ACCOUNT', default='firebase/service_account.json')

# Configuración de validaciones
RADIO_VALIDACION_METROS = int(config('RADIO_VALIDACION_METROS', default=50000))
TOLERANCIA_MINUTOS_REUNION = int(config('TOLERANCIA_MINUTOS_REUNION', default=120))

# Configuración de sesiones
SESSION_LIFETIME_MINUTES = int(config('SESSION_LIFETIME_MINUTES', default=30))

# Configuración de rate limiting
RATE_LIMIT_REQUESTS = int(config('RATE_LIMIT_REQUESTS', default=100))
RATE_LIMIT_WINDOW = int(config('RATE_LIMIT_WINDOW', default=60))  # segundos

