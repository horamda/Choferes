# Sistema de Gestión de Choferes

Aplicación web para la gestión de empleados, KPIs, reuniones y pedidos de mercadería.

## 🚀 Características

- Gestión completa de empleados (choferes)
- Sistema de KPIs por sector
- Control de asistencia a reuniones con geolocalización
- Gestión de pedidos de mercadería
- Notificaciones push via Firebase
- Panel administrativo con dashboards

## 🔒 Seguridad

Esta aplicación implementa múltiples capas de seguridad:

### Configuración de Variables de Entorno

Crea un archivo `.env` basado en `.env.example`:

```bash
cp .env.example .env
```

**IMPORTANTE**: Nunca commits el archivo `.env` al repositorio.

### Variables de Entorno Requeridas

- `APP_SECRET_KEY`: Clave secreta para sesiones Flask (mínimo 32 caracteres)
- `JWT_SECRET`: Clave secreta para tokens JWT (mínimo 32 caracteres)
- `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: Credenciales de base de datos
- `FIREBASE_SERVICE_ACCOUNT`: Ruta al archivo de credenciales de Firebase

### Generación de Claves Seguras

```python
import secrets
print(secrets.token_hex(32))  # Para APP_SECRET_KEY y JWT_SECRET
```

## 📦 Instalación

1. **Clona el repositorio:**
   ```bash
   git clone <url-del-repo>
   cd backend_choferes
   ```

2. **Instala dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configura variables de entorno:**
   ```bash
   cp .env.example .env
   # Edita .env con tus valores
   ```

4. **Configura Firebase:**
   - Coloca tu archivo `service_account.json` en `firebase/`
   - Actualiza `FIREBASE_SERVICE_ACCOUNT` en `.env`

5. **Ejecuta la aplicación:**
   ```bash
   python app.py
   ```

## 🛡️ Medidas de Seguridad Implementadas

### Rate Limiting
- Login admin: 5 intentos por minuto
- Login API: 10 intentos por minuto
- Registro de tokens: 20 intentos por minuto
- Rutas generales: 100 requests por minuto

### Validación de Inputs
- Sanitización de strings para prevenir XSS
- Validación de formato DNI (7-8 dígitos)
- Validación de emails
- Límites de longitud en campos

### Autenticación
- JWT con expiración configurable
- Sesiones seguras con tiempo límite
- Doble factor de validación en asistencia (ubicación + horario)

### Base de Datos
- Uso de prepared statements
- Conexiones con timeout
- Manejo seguro de transacciones

## 🔧 Configuración Avanzada

### Rate Limiting Personalizado
```python
# En config.py
RATE_LIMIT_REQUESTS = 50  # Requests por ventana
RATE_LIMIT_WINDOW = 60    # Ventana en segundos
```

### Sesiones
```python
# En config.py
SESSION_LIFETIME_MINUTES = 60  # Duración de sesión
```

### JWT
```python
# En config.py
JWT_EXPIRE_HRS = 24  # Expiración de tokens
```

## 🚨 Alertas de Seguridad

- **Nunca** uses las claves por defecto en producción
- **Siempre** configura HTTPS en producción
- **Regularmente** rota las claves secretas
- **Monitorea** los logs de rate limiting

## 📊 Monitoreo

La aplicación incluye logging detallado para:
- Intentos de login fallidos
- Rate limiting activado
- Errores de base de datos
- Problemas de geolocalización

## 🐛 Reporte de Vulnerabilidades

Si encuentras vulnerabilidades de seguridad, por favor contacta al equipo de desarrollo directamente.

## 📝 Licencia

[Tu licencia aquí]