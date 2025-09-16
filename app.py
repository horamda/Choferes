from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, flash
from flask_cors import CORS
import mysql.connector
from config import MYSQL_CONFIG
import os
from dotenv import load_dotenv
from io import BytesIO
from functools import wraps
from datetime import datetime, timedelta,date
from notificaciones import enviar_push
import re
import logging
from unicodedata import normalize
import base64
import jwt
from mysql.connector import Error  
from utils import redimensionar_imagen
import qrcode
from geopy.distance import geodesic
from PIL import Image
import pandas as pd
from flask import send_file
from config import RADIO_VALIDACION_METROS, TOLERANCIA_MINUTOS_REUNION



# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


load_dotenv()


def generar_qr(contenido, nombre_base, logo_path="static/logo.png"):
    """
    Genera un QR en static/qrcodes con logo opcional.
    Devuelve la ruta relativa (para guardar en DB) y absoluta (para guardar el archivo).
    """
    output_dir = os.path.join("static", "qrcodes")
    os.makedirs(output_dir, exist_ok=True)

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(contenido)
    qr.make(fit=True)
    img_qr = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    try:
        if os.path.exists(logo_path):
            logo = Image.open(logo_path).convert("RGBA")
            logo_size = int(img_qr.size[0] * 0.25)
            logo = logo.resize((logo_size, logo_size))
            pos = ((img_qr.size[0] - logo_size) // 2, (img_qr.size[1] - logo_size) // 2)
            img_qr.paste(logo, pos, mask=logo if logo.mode == 'RGBA' else None)
    except Exception as e:
        print(f"⚠️ Error al agregar logo al QR: {e}")

    # Asegurar extensión correcta
    if not nombre_base.endswith(".png"):
        nombre_base += ".png"

    filename = os.path.join(output_dir, nombre_base)
    img_qr.save(filename)

    # Ruta relativa para la base de datos (sin "static/")
    ruta_relativa = os.path.relpath(filename, "static")
    return ruta_relativa, filename



        
#def generar_qr(contenido, nombre_archivo):
#    """
#    Genera un código QR PNG y lo guarda en /static/qrcodes.
#    Devuelve la ruta relativa del archivo generado.
#    """
#    img = qrcode.make(contenido)
#    path = f'static/qrcodes/{nombre_archivo}.png'
#    img.save(path)
#    return path


app = Flask(__name__)
CORS(app)

app.secret_key = 'clave-super-secreta'
app.permanent_session_lifetime = timedelta(minutes=30)

def jwt_required_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "message": "Token faltante"}), 401
        token = auth_header.split(" ")[1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated




def get_connection():
    """Obtiene una conexión a la base de datos con configuración robusta."""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        # Configurar la conexión para mejor manejo de errores
        conn.autocommit = False
        return conn
    except mysql.connector.Error as err:
        logger.error(f"Error connecting to database: {err}")
        raise

def check_database_locks():
    """Verifica si hay locks activos en la base de datos."""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Verificar procesos bloqueados (solo si tenemos permisos)
        cursor.execute("""
            SELECT
                r.trx_id waiting_trx_id,
                r.trx_mysql_thread_id waiting_thread,
                r.trx_query waiting_query,
                b.trx_id blocking_trx_id,
                b.trx_mysql_thread_id blocking_thread,
                b.trx_query blocking_query
            FROM information_schema.innodb_lock_waits w
            INNER JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_trx_id
            INNER JOIN information_schema.innodb_trx r ON r.trx_id = w.requesting_trx_id
        """)

        locks = cursor.fetchall()
        if locks:
            logger.warning(f"Active database locks found: {len(locks)} lock(s)")
            for lock in locks:
                logger.warning(f"Lock: {lock}")
        else:
            logger.info("No active database locks found")

        return locks

    except mysql.connector.errors.DatabaseError as db_err:
        if "PROCESS" in str(db_err) or "Access denied" in str(db_err):
            logger.info("Cannot check database locks: insufficient privileges (PROCESS permission required)")
            return []
        else:
            logger.error(f"Database error checking locks: {db_err}")
            return []
    except Exception as e:
        logger.error(f"Error checking database locks: {e}")
        return []
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def force_unlock_blocking_transactions():
    """
    Fuerza liberación de transacciones bloqueadoras.
    Como experto en DB, esta función identifica y mata transacciones que están bloqueando.
    """
    logger.info("🔧 Intentando liberar transacciones bloqueadoras...")

    admin_conn = None
    admin_cursor = None

    try:
        # Crear conexión administrativa
        admin_conn = get_connection()
        admin_cursor = admin_conn.cursor()

        # 1. Identificar transacciones bloqueadoras
        admin_cursor.execute("""
            SELECT DISTINCT
                b.trx_mysql_thread_id as blocking_thread,
                b.trx_id as blocking_trx_id,
                b.trx_started as started_time,
                TIMESTAMPDIFF(SECOND, b.trx_started, NOW()) as duration_seconds
            FROM information_schema.innodb_lock_waits w
            INNER JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_trx_id
            WHERE TIMESTAMPDIFF(SECOND, b.trx_started, NOW()) > 30  -- Transacciones > 30 segundos
        """)

        blocking_transactions = admin_cursor.fetchall()

        if not blocking_transactions:
            logger.info("✅ No se encontraron transacciones bloqueadoras activas")
            return True

        logger.warning(f"🚨 Encontradas {len(blocking_transactions)} transacciones bloqueadoras")

        # 2. Kill transacciones bloqueadoras (con precaución)
        killed_count = 0
        for trx in blocking_transactions:
            thread_id = trx[0]
            trx_id = trx[1]
            duration = trx[3]

            try:
                logger.warning(f"Killing blocking transaction - Thread: {thread_id}, Duration: {duration}s")
                admin_cursor.execute(f"KILL {thread_id}")
                killed_count += 1

                # Log detallado
                logger.info(f"✅ Killed blocking transaction {trx_id} (thread {thread_id})")

            except Exception as kill_err:
                logger.error(f"❌ Error killing transaction {trx_id}: {kill_err}")

        if killed_count > 0:
            logger.info(f"🎯 Liberadas {killed_count} transacciones bloqueadoras")
            # Esperar un momento para que se liberen los locks
            import time
            time.sleep(0.5)
            return True
        else:
            logger.warning("⚠️ No se pudieron liberar transacciones bloqueadoras")
            return False

    except mysql.connector.errors.DatabaseError as db_err:
        if "PROCESS" in str(db_err) or "Access denied" in str(db_err):
            logger.warning("⚠️ Sin permisos PROCESS - no se pueden liberar locks automáticamente")
            logger.info("💡 Solución manual: Ejecutar 'SHOW PROCESSLIST' y 'KILL [thread_id]' en phpMyAdmin")
            return False
        else:
            logger.error(f"❌ Error de DB liberando locks: {db_err}")
            return False

    except Exception as e:
        logger.error(f"❌ Error liberando transacciones bloqueadoras: {e}")
        return False

    finally:
        if admin_cursor:
            try:
                admin_cursor.close()
            except:
                pass
        if admin_conn:
            try:
                admin_conn.close()
            except:
                pass

def diagnose_lock_issue(table_name, column_name, value):
    """
    Diagnóstico avanzado de problemas de lock en un registro específico.
    Como experto en DB, proporciona análisis detallado del problema.
    """
    logger.info(f"🔍 Diagnosticando lock en {table_name}.{column_name} = {value}")

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Verificar si el registro existe
        cursor.execute(f"SELECT COUNT(*) as count FROM {table_name} WHERE {column_name} = %s", (value,))
        exists = cursor.fetchone()['count'] > 0

        if not exists:
            logger.info(f"ℹ️ El registro {value} no existe en {table_name}")
            return {"issue": "record_not_found", "exists": False}

        # 2. Verificar locks específicos en este registro (compatible con versiones anteriores de MySQL)
        try:
            cursor.execute("""
                SELECT
                    lk.lock_type,
                    lk.lock_mode,
                    lk.lock_table,
                    trx.trx_id,
                    trx.trx_state,
                    trx.trx_mysql_thread_id,
                    TIMESTAMPDIFF(SECOND, trx.trx_started, NOW()) as duration
                FROM information_schema.innodb_lock_waits w
                RIGHT JOIN information_schema.innodb_locks lk ON w.requesting_trx_id = lk.lock_trx_id
                LEFT JOIN information_schema.innodb_trx trx ON lk.lock_trx_id = trx.trx_id
                WHERE lk.lock_table LIKE %s
            """, (f"%{table_name}%",))
        except mysql.connector.errors.DatabaseError:
            # Fallback para versiones de MySQL que no tienen innodb_locks
            logger.info("ℹ️ Tabla innodb_locks no disponible, usando diagnóstico básico")
            cursor.execute("""
                SELECT
                    trx_id,
                    trx_state,
                    trx_mysql_thread_id,
                    TIMESTAMPDIFF(SECOND, trx_started, NOW()) as duration
                FROM information_schema.innodb_trx
                WHERE trx_state = 'RUNNING'
            """)

        locks = cursor.fetchall()

        # 3. Verificar transacciones activas relacionadas
        cursor.execute("""
            SELECT
                trx_id,
                trx_state,
                trx_started,
                trx_mysql_thread_id,
                trx_query,
                TIMESTAMPDIFF(SECOND, trx_started, NOW()) as duration
            FROM information_schema.innodb_trx
            WHERE trx_state = 'RUNNING' AND TIMESTAMPDIFF(SECOND, trx_started, NOW()) > 10
        """)

        active_trx = cursor.fetchall()

        diagnosis = {
            "issue": "lock_detected" if locks else "no_locks_found",
            "exists": True,
            "locks_found": len(locks),
            "active_transactions": len(active_trx),
            "locks": locks,
            "transactions": active_trx
        }

        if locks:
            logger.warning(f"🚨 Locks encontrados: {len(locks)}")
            for lock in locks:
                logger.warning(f"Lock: {lock}")
        else:
            logger.info("✅ No se encontraron locks específicos")

        if active_trx:
            logger.warning(f"📊 Transacciones activas: {len(active_trx)}")
            for trx in active_trx:
                logger.warning(f"TRX: {trx}")

        return diagnosis

    except Exception as e:
        logger.error(f"❌ Error en diagnóstico: {e}")
        return {"issue": "diagnostic_error", "error": str(e)}

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('login_admin'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login_admin'))

@app.route('/login', methods=['GET', 'POST'])
def login_admin():
    error = None
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE usuario = %s AND password = %s", (usuario, password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            session['admin'] = usuario
            return redirect(url_for('dashboard'))
        else:
            error = "Usuario o contraseña incorrectos"

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('login_admin'))

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('login_admin'))
        return f(*args, **kwargs)
    return decorated

def slug(txt: str) -> str:
    """Normaliza y quita tildes para comparar sin importar mayúsculas."""
    if txt is None:     # por si viene None
        return ''
    txt = normalize('NFKD', txt).encode('ascii', 'ignore').decode('ascii')
    return txt.lower().strip()

@app.route('/dashboard')
@login_required
def dashboard():
    # ───────────────────── 1) Parámetro de entrada ─────────────────────
    sector_nombre_raw = request.args.get('sector_nombre', default=None, type=str)

    # ───────────────────── 2) Conexión y lista de sectores ─────────────
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, nombre FROM sectores ORDER BY id")
    sectores = cursor.fetchall()                        # [{'id':1,'nombre':'Almacén'}, …]

    # Construimos un dict {slug(nombre): id}
    mapa_nombre_id = { slug(s['nombre']): s['id'] for s in sectores }

    # Resuelve el id (default = primer sector si no hay match)
    clave = slug(sector_nombre_raw)
    sector_id      = mapa_nombre_id.get(clave, sectores[0]['id'])
    sector_nombre  = next( s['nombre'] for s in sectores if s['id'] == sector_id )

    # ───────────────────── 3) Fechas ───────────────────────────────────
    fi_str = request.args.get('fecha_inicio')
    ff_str = request.args.get('fecha_fin')
    hoy = date.today()
    if not fi_str or not ff_str:
        fecha_ini, fecha_fin = hoy - timedelta(days=6), hoy
    else:
        fecha_ini = datetime.strptime(fi_str, '%Y-%m-%d').date()
        fecha_fin = datetime.strptime(ff_str, '%Y-%m-%d').date()

    # ───────────────────── 4) Indicadores activos ──────────────────────
    cursor.execute("""
        SELECT id, nombre,
               color_grafico AS color,
               tipo_grafico  AS tipo,
               fill_grafico  AS fill
          FROM indicadores
         WHERE sector_id = %s AND activo = 1
        ORDER BY nombre
    """, (sector_id,))
    indicadores = cursor.fetchall()

    # ───────────────────── 5) Tarjetas y series ────────────────────────
    tarjetas, graficos = [], []

    for ind in indicadores:
        iid, nombre = ind['id'], ind['nombre']

        # Tarjeta (total de hoy)
        cursor.execute("""
            SELECT COALESCE(SUM(valor),0) AS total
              FROM kpis
             WHERE indicador_id=%s AND sector_id=%s AND fecha=CURDATE()
        """, (iid, sector_id))
        total_hoy = cursor.fetchone()['total']

        tarjetas.append({
            'indicador': nombre,
            'valor'    : int(total_hoy),
            'color'    : ind['color'],
            'tipo'     : ind['tipo'],
            'fill'     : bool(ind['fill']),
            'indicador_id': iid          # lo necesita el front
        })

        # Serie histórica para el gráfico
        cursor.execute("""
            SELECT fecha, COALESCE(SUM(valor),0) AS total
              FROM kpis
             WHERE indicador_id=%s AND sector_id=%s
               AND fecha BETWEEN %s AND %s
          GROUP BY fecha
          ORDER BY fecha
        """, (iid, sector_id, fecha_ini, fecha_fin))
        rows = cursor.fetchall()

        graficos.append({
            'indicador': nombre,
            'labels'   : [r['fecha'].strftime('%d/%m') for r in rows],
            'data'     : [int(r['total']) for r in rows],
            'color'    : ind['color'],
            'tipo'     : ind['tipo'],
            'fill'     : bool(ind['fill'])
        })

    cursor.close()
    conn.close()

    # ───────────────────── 6) Render ───────────────────────────────────
    return render_template(
        'dashboard.html',
        sectores      = sectores,               # para poblar el <select>
        sector_nombre = sector_nombre,          # dejar marcado el elegido
        fecha_inicio  = fecha_ini.strftime('%Y-%m-%d'),
        fecha_fin     = fecha_fin.strftime('%Y-%m-%d'),
        tarjetas      = tarjetas,
        graficos      = graficos
    )
    
@app.route('/panel', methods=['GET', 'POST'])
@login_required
def panel():
    if request.method == 'POST':
        # Handle both single DNI (legacy) and multiple DNIs (new)
        dnis = request.form.getlist('dnis')  # New way: multiple DNIs
        dni_single = request.form.get('dni')  # Legacy way: single DNI

        if dnis:
            # New way: multiple DNIs
            dnis_list = [d.strip() for d in dnis if d.strip()]
        elif dni_single:
            # Legacy way: single DNI
            dnis_list = [dni_single.strip()]
        else:
            dnis_list = []

        mensaje = request.form.get('mensaje', '').strip()

        if not dnis_list or not mensaje:
            return jsonify({"success": False, "message": "Todos los campos son obligatorios"}), 400

        # Validate all DNIs
        invalid_dnis = []
        for dni in dnis_list:
            if not dni.isdigit() or not (7 <= len(dni) <= 8):
                invalid_dnis.append(dni)

        if invalid_dnis:
            return jsonify({"success": False, "message": f"DNIs inválidos: {', '.join(invalid_dnis)}. Deben tener entre 7 y 8 dígitos numéricos"}), 400

        # Nueva estrategia: Procesar mensajes y push notifications por separado
        # para evitar conflictos de locks complejos

        sent_count = 0
        failed_count = 0
        push_sent_count = 0
        push_failed_count = 0

        logger.info(f"Sending message to {len(dnis_list)} employees: {dnis_list}")

        # FASE 1: Guardar mensajes en DB (sistema experto anti-locks)
        logger.info("=== FASE 1: Guardando mensajes en DB (Sistema Experto Anti-Locks) ===")

        # PASO 1: Diagnóstico proactivo de locks
        locks_before = check_database_locks()
        if locks_before:
            logger.warning(f"🚨 Locks detectados ANTES de procesar: {len(locks_before)}")

            # Intentar liberación automática de locks bloqueadores
            unlock_success = force_unlock_blocking_transactions()
            if unlock_success:
                logger.info("✅ Liberación automática de locks exitosa")
            else:
                logger.warning("⚠️ No se pudieron liberar locks automáticamente")

        # PASO 2: Procesar cada empleado con estrategia experta
        messages_saved = []
        problematic_dnis = []  # DNIs con problemas persistentes

        for dni in dnis_list:
            employee_conn = None
            employee_cursor = None

            # Estrategia experta de recuperación múltiple
            max_attempts = 3
            success = False
            diagnosis_done = False

            for attempt in range(max_attempts):
                try:
                    logger.info(f"Procesando DNI: {dni} (intento {attempt + 1}/{max_attempts})")

                    # Conexión individual por empleado
                    employee_conn = get_connection()
                    employee_cursor = employee_conn.cursor()

                    # Configuración experta anti-locks
                    employee_cursor.execute("SET SESSION innodb_lock_wait_timeout = 2")
                    employee_cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")

                    # PASO 3: Diagnóstico específico si es el último intento
                    if attempt == max_attempts - 1 and not diagnosis_done:
                        diagnosis = diagnose_lock_issue('avisos', 'dni', dni)
                        if diagnosis['issue'] == 'lock_detected':
                            logger.warning(f"🔍 Diagnóstico: Lock persistente en DNI {dni}")
                            # Intentar liberación específica una vez más
                            unlock_success = force_unlock_blocking_transactions()
                            if unlock_success:
                                logger.info(f"🔧 Liberación específica exitosa para DNI {dni}")
                                diagnosis_done = True
                        elif diagnosis['issue'] == 'record_not_found':
                            logger.warning(f"ℹ️ DNI {dni} no existe en avisos - puede ser lock en otra tabla")

                    # PASO 4: Técnica de liberación de locks
                    if attempt > 0:
                        try:
                            # Técnica 1: SELECT FOR UPDATE NOWAIT
                            employee_cursor.execute("SELECT 1 FROM avisos WHERE dni = %s FOR UPDATE NOWAIT", (dni,))
                            result = employee_cursor.fetchone()
                            logger.info(f"🔓 Lock liberado para DNI {dni} en intento {attempt + 1}")

                        except mysql.connector.errors.DatabaseError as lock_err:
                            if "Lock wait timeout" in str(lock_err):
                                logger.warning(f"⏳ Lock aún activo para DNI {dni} en intento {attempt + 1}")
                                # Técnica 2: Intentar con tabla relacionada
                                try:
                                    employee_cursor.execute("SELECT 1 FROM choferes WHERE dni = %s FOR UPDATE NOWAIT", (dni,))
                                    employee_cursor.fetchone()
                                    logger.info(f"🔓 Lock liberado en tabla relacionada para DNI {dni}")
                                except:
                                    pass
                            else:
                                logger.warning(f"Error específico de lock para DNI {dni}: {lock_err}")

                    # PASO 5: Intentar la inserción final
                    employee_cursor.execute("INSERT INTO avisos (dni, mensaje) VALUES (%s, %s)", (dni, mensaje))
                    employee_conn.commit()

                    messages_saved.append(dni)
                    logger.info(f"✅ Mensaje guardado exitosamente para DNI: {dni}")
                    success = True
                    break

                except mysql.connector.errors.DatabaseError as db_err:
                    error_msg = str(db_err)
                    if "Lock wait timeout" in error_msg:
                        if attempt < max_attempts - 1:
                            wait_time = 1 if attempt == 0 else 0.5
                            logger.warning(f"⏰ Lock timeout DNI {dni} (intento {attempt + 1}), esperando {wait_time}s...")
                            import time
                            time.sleep(wait_time)
                            continue
                        else:
                            logger.error(f"⏰ Lock timeout PERSISTENTE para DNI {dni} - {max_attempts} intentos agotados")
                            problematic_dnis.append(dni)
                    elif "deadlock" in error_msg.lower():
                        if attempt < max_attempts - 1:
                            logger.warning(f"🔄 Deadlock DNI {dni} (intento {attempt + 1}), reintentando...")
                            import time
                            time.sleep(0.5)
                            continue
                        else:
                            logger.error(f"🔄 Deadlock PERSISTENTE para DNI {dni} - {max_attempts} intentos agotados")
                            problematic_dnis.append(dni)
                    else:
                        logger.error(f"❌ Error de DB para DNI {dni}: {error_msg}")
                        break

                except Exception as e:
                    logger.error(f"❌ Error inesperado procesando DNI {dni}: {e}")
                    break

                finally:
                    # Cerrar conexión individual después de cada intento
                    if employee_cursor:
                        try:
                            employee_cursor.close()
                        except:
                            pass
                    if employee_conn:
                        try:
                            employee_conn.close()
                        except:
                            pass

            if not success:
                logger.error(f"❌ No se pudo procesar DNI {dni} después de {max_attempts} intentos")
                failed_count += 1

        sent_count = len(messages_saved)
        logger.info(f"=== FASE 1 COMPLETADA: {sent_count} mensajes guardados, {failed_count} fallidos ===")

        # PASO 6: Reporte final de diagnóstico
        if problematic_dnis:
            logger.warning(f"🚨 DNIs con problemas persistentes: {problematic_dnis}")
            logger.info("💡 Recomendación: Revisar conexiones abiertas en phpMyAdmin")
            logger.info("💡 Ejecutar: SHOW PROCESSLIST; y KILL [thread_id];")

        # FASE 2: Enviar push notifications (operación separada, no crítica)
        # Esta fase puede fallar sin afectar los mensajes guardados
        if messages_saved:
            logger.info(f"Sending push notifications to {len(messages_saved)} employees")

            for dni in messages_saved:
                try:
                    # Conexión individual para cada verificación de token
                    push_conn = get_connection()
                    push_cursor = push_conn.cursor()

                    try:
                        # Verificar si el empleado tiene token
                        push_cursor.execute("SELECT token FROM tokens WHERE dni = %s", (dni,))
                        result = push_cursor.fetchone()

                        if result and result[0]:
                            token = result[0]
                            logger.info(f"Found token for DNI {dni}, sending push notification")
                            try:
                                enviar_push(token, "📢 Nuevo aviso", mensaje)
                                push_sent_count += 1
                                logger.info(f"Push notification sent successfully to DNI: {dni}")
                            except Exception as push_error:
                                logger.error(f"Failed to send push notification to DNI {dni}: {push_error}")
                                push_failed_count += 1
                        else:
                            logger.warning(f"No token found for DNI: {dni}")

                    finally:
                        push_cursor.close()
                        push_conn.close()

                except Exception as e:
                    logger.error(f"Error checking token for DNI {dni}: {e}")
                    push_failed_count += 1

        logger.info(f"Phase 1 - Messages: {sent_count} saved, {failed_count} failed")
        logger.info(f"Phase 2 - Push notifications: {push_sent_count} sent, {push_failed_count} failed")

        # Preparar mensaje de respuesta con diagnóstico experto
        if failed_count == 0:
            if push_failed_count == 0:
                response_message = f"✅ Mensaje enviado correctamente a {sent_count} empleado{'s' if sent_count != 1 else ''}"
                return jsonify({"success": True, "message": response_message})
            else:
                response_message = f"⚠️ Mensajes guardados para {sent_count} empleado{'s' if sent_count != 1 else ''}, pero {push_failed_count} notificación{'es' if push_failed_count != 1 else ''} push fallaron"
                return jsonify({"success": True, "message": response_message, "warning": True})
        else:
            # Respuesta detallada para casos con fallos
            response_message = f"⚠️ {sent_count} mensaje{'s' if sent_count != 1 else ''} guardado{'s' if sent_count != 1 else ''}, {failed_count} fallido{'s' if failed_count != 1 else ''}"

            if push_sent_count > 0:
                response_message += f". Push: {push_sent_count} enviado{'s' if push_sent_count != 1 else ''}"

            if problematic_dnis:
                response_message += f". DNIs con locks persistentes: {', '.join(problematic_dnis)}"
                logger.warning(f"🚨 DNIs que requieren atención manual: {problematic_dnis}")

                # Agregar recomendaciones específicas
                recommendations = []
                if len(problematic_dnis) > 0:
                    recommendations.append("Revisar conexiones abiertas en phpMyAdmin")
                    recommendations.append("Ejecutar: SHOW PROCESSLIST; y KILL [thread_id];")
                    recommendations.append("Verificar transacciones no confirmadas")

                return jsonify({
                    "success": True,
                    "message": response_message,
                    "warning": True,
                    "problematic_dnis": problematic_dnis,
                    "recommendations": recommendations
                })

            return jsonify({"success": True, "message": response_message, "warning": True})

    # Obtener estadísticas de mensajes enviados hoy
    conn = get_connection()
    cursor = conn.cursor()

    # Estadísticas generales de hoy
    cursor.execute("""
        SELECT COUNT(*) as total_hoy,
               COUNT(DISTINCT DATE(fecha)) as dias_con_mensajes
        FROM avisos
        WHERE DATE(fecha) = CURDATE()
    """)
    stats_hoy = cursor.fetchone()

    # Mensajes por sector hoy
    cursor.execute("""
        SELECT c.sector, COUNT(a.id) as cantidad
        FROM avisos a
        JOIN choferes c ON a.dni = c.dni
        WHERE DATE(a.fecha) = CURDATE()
        GROUP BY c.sector
        ORDER BY cantidad DESC
    """)
    mensajes_por_sector = cursor.fetchall()

    # Mensajes por sucursal hoy
    cursor.execute("""
        SELECT COALESCE(s.nombre, 'Sin sucursal') as sucursal, COUNT(a.id) as cantidad
        FROM avisos a
        LEFT JOIN choferes c ON a.dni = c.dni
        LEFT JOIN sucursales s ON c.sucursal_id = s.id
        WHERE DATE(a.fecha) = CURDATE()
        GROUP BY s.nombre
        ORDER BY cantidad DESC
    """)
    mensajes_por_sucursal = cursor.fetchall()

    # Comparación con días anteriores
    cursor.execute("""
        SELECT
            COUNT(CASE WHEN DATE(fecha) = CURDATE() THEN 1 END) as hoy,
            COUNT(CASE WHEN DATE(fecha) = DATE_SUB(CURDATE(), INTERVAL 1 DAY) THEN 1 END) as ayer,
            COUNT(CASE WHEN DATE(fecha) = DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 END) as semana_pasada
        FROM avisos
        WHERE DATE(fecha) >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    """)
    comparacion = cursor.fetchone()

    # Obtener últimos 10 avisos con información del empleado
    avisos_cursor = conn.cursor(dictionary=True)
    avisos_cursor.execute("""
        SELECT a.dni, a.mensaje, a.fecha, c.nombre, c.sector,
               COALESCE(s.nombre, 'Sin sucursal') as sucursal
        FROM avisos a
        LEFT JOIN choferes c ON a.dni = c.dni
        LEFT JOIN sucursales s ON c.sucursal_id = s.id
        ORDER BY a.fecha DESC LIMIT 10
    """)
    avisos = avisos_cursor.fetchall()
    avisos_cursor.close()

    # Obtener lista de empleados para el selector
    empleados_cursor = conn.cursor(dictionary=True)
    empleados_cursor.execute("""
        SELECT c.dni, c.nombre, c.sector, s.nombre AS sucursal
        FROM choferes c
        LEFT JOIN sucursales s ON c.sucursal_id = s.id
        ORDER BY c.nombre
    """)
    empleados = empleados_cursor.fetchall()
    empleados_cursor.close()

    cursor.close()
    conn.close()

    # Preparar datos para el template
    estadisticas_hoy = {
        'total': stats_hoy[0] if stats_hoy else 0,
        'dias_con_mensajes': stats_hoy[1] if stats_hoy else 0,
        'por_sector': dict(mensajes_por_sector) if mensajes_por_sector else {},
        'por_sucursal': dict(mensajes_por_sucursal) if mensajes_por_sucursal else {},
        'comparacion': {
            'hoy': comparacion[0] if comparacion else 0,
            'ayer': comparacion[1] if comparacion else 0,
            'semana_pasada': comparacion[2] if comparacion else 0
        }
    }

    return render_template('panel.html', avisos=avisos, empleados=empleados, estadisticas_hoy=estadisticas_hoy)

@app.route('/avisos_push')
@login_required
def historial_push():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT dni, titulo, mensaje, fecha
        FROM avisos_push
        ORDER BY fecha DESC
        LIMIT 20
    """)
    avisos = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('avisos_push.html', avisos=avisos)


@app.route('/admin/choferes')
@login_required
def listar_choferes():
    sucursal_id = request.args.get('sucursal_id')  # viene del select
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Cargar todas las sucursales para el select
    cursor.execute("SELECT id, nombre FROM sucursales WHERE activa = TRUE")
    sucursales = cursor.fetchall()

    if sucursal_id:
        cursor.execute("""
            SELECT c.dni, c.nombre, c.sector, s.nombre AS sucursal
            FROM choferes c
            LEFT JOIN sucursales s ON c.sucursal_id = s.id
            WHERE c.sucursal_id = %s
        """, (sucursal_id,))
    else:
        cursor.execute("""
            SELECT c.dni, c.nombre, c.sector, s.nombre AS sucursal
            FROM choferes c
            LEFT JOIN sucursales s ON c.sucursal_id = s.id
        """)
    
    choferes = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('choferes.html', choferes=choferes, sucursales=sucursales, sucursal_id=sucursal_id)



@app.route('/admin/choferes/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_chofer():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Obtener sucursales para el combo
    cursor.execute("SELECT id, nombre FROM sucursales WHERE activa = TRUE")
    sucursales = cursor.fetchall()

    if request.method == 'POST':
        dni = request.form['dni']
        nombre = request.form['nombre']
        sector = request.form['sector']
        sucursal_id = request.form['sucursal_id']
        imagen = request.files['imagen']

        imagen_blob = None
        if imagen and imagen.filename:
            imagen_blob = redimensionar_imagen(imagen.read())

        cursor.execute("SELECT 1 FROM choferes WHERE dni = %s", (dni,))
        if cursor.fetchone():
            flash("❌ Ya existe un empleado con ese DNI", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('nuevo_chofer'))

        cursor.execute("""
            INSERT INTO choferes (dni, nombre, sector, sucursal_id, imagen)
            VALUES (%s, %s, %s, %s, %s)
        """, (dni, nombre, sector, sucursal_id, imagen_blob))

        conn.commit()
        cursor.close()
        conn.close()

        flash("✅ Empleado creado correctamente", "success")
        return redirect(url_for('listar_choferes'))

    cursor.close()
    conn.close()
    return render_template('nuevo_chofer.html', sucursales=sucursales)

@app.route('/admin/choferes/editar/<dni>', methods=['GET', 'POST'])
@login_required
def editar_chofer(dni):
    # Validar formato del DNI
    if not re.match(r'^\d{7,8}$', dni):
        flash("❌ DNI inválido", "danger")
        return redirect(url_for('listar_choferes'))

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Obtener sucursales para dropdown
        cursor.execute("SELECT id, nombre FROM sucursales WHERE activa = TRUE")
        sucursales = cursor.fetchall()

        if request.method == 'POST':
            nombre = request.form.get('nombre', '').strip()
            sector = request.form.get('sector', '').strip()
            sucursal_id = request.form.get('sucursal_id', '').strip()
            imagen = request.files.get('imagen')

            # Validaciones básicas
            if not nombre or not sector or not sucursal_id:
                flash("❌ Todos los campos obligatorios deben completarse", "danger")
                return redirect(request.url)

            if len(nombre) < 2:
                flash("❌ El nombre debe tener al menos 2 caracteres", "danger")
                return redirect(request.url)

            # Verificar que la sucursal existe
            cursor.execute("SELECT id FROM sucursales WHERE id = %s AND activa = TRUE", (sucursal_id,))
            if not cursor.fetchone():
                flash("❌ Sucursal inválida", "danger")
                return redirect(request.url)

            # Procesar imagen si existe
            imagen_blob = None
            if imagen and imagen.filename:
                try:
                    imagen_blob = redimensionar_imagen(imagen.read())
                except Exception as img_err:
                    logger.error(f"Error processing image for employee {dni}: {img_err}")
                    flash("❌ Error al procesar la imagen", "danger")
                    return redirect(request.url)

            # Actualizar empleado
            if imagen_blob:
                cursor.execute("""
                    UPDATE choferes
                    SET nombre = %s, sector = %s, sucursal_id = %s, imagen = %s
                    WHERE dni = %s
                """, (nombre, sector, sucursal_id, imagen_blob, dni))
            else:
                cursor.execute("""
                    UPDATE choferes
                    SET nombre = %s, sector = %s, sucursal_id = %s
                    WHERE dni = %s
                """, (nombre, sector, sucursal_id, dni))

            conn.commit()
            flash("✅ Datos del Empleado actualizados correctamente", "success")
            return redirect(url_for('listar_choferes'))

        # GET: Cargar datos actuales del chofer
        cursor.execute("""
            SELECT nombre, sector, sucursal_id
            FROM choferes WHERE dni = %s
        """, (dni,))
        chofer = cursor.fetchone()

        if not chofer:
            flash("❌ Empleado no encontrado", "danger")
            return redirect(url_for('listar_choferes'))

        return render_template('editar_chofer.html', dni=dni, nombre=chofer['nombre'],
                               sector=chofer['sector'], sucursal_id=chofer['sucursal_id'],
                               sucursales=sucursales)

    except mysql.connector.errors.DatabaseError as db_err:
        if conn:
            conn.rollback()
        logger.error(f"Database error editing employee {dni}: {db_err}")
        flash(f"❌ Error de base de datos: {str(db_err)}", "danger")
        return redirect(url_for('listar_choferes'))

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Unexpected error editing employee {dni}: {e}")
        flash(f"❌ Error inesperado: {str(e)}", "danger")
        return redirect(url_for('listar_choferes'))

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    
@app.route('/admin/choferes/eliminar/<dni>', methods=['POST'])
@login_required
def eliminar_chofer(dni):
    # Validar formato del DNI
    if not re.match(r'^\d{7,8}$', dni):
        flash("❌ DNI inválido", "danger")
        return redirect(url_for('listar_choferes'))

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Verificar que el empleado existe antes de eliminar
        cursor.execute("SELECT nombre FROM choferes WHERE dni = %s", (dni,))
        empleado = cursor.fetchone()

        if not empleado:
            flash("❌ Empleado no encontrado", "danger")
            return redirect(url_for('listar_choferes'))

        # Intentar múltiples estrategias para manejar locks
        try:
            # Estrategia 1: Timeout más largo
            cursor.execute("SET SESSION innodb_lock_wait_timeout = 30")
            cursor.execute("DELETE FROM choferes WHERE dni = %s", (dni,))
            conn.commit()
            flash(f"🗑️ Empleado '{empleado[0]}' eliminado correctamente", "success")
            return redirect(url_for('listar_choferes'))

        except mysql.connector.errors.DatabaseError as lock_err:
            if "Lock wait timeout" in str(lock_err):
                logger.warning(f"Lock timeout for employee {dni}, trying alternative approach")

                # Estrategia 2: Forzar rollback y reintentar
                try:
                    conn.rollback()
                    # Esperar un momento y reintentar
                    import time
                    time.sleep(1)

                    cursor.execute("SET SESSION innodb_lock_wait_timeout = 10")
                    cursor.execute("DELETE FROM choferes WHERE dni = %s", (dni,))
                    conn.commit()
                    flash(f"🗑️ Empleado '{empleado[0]}' eliminado correctamente", "success")
                    return redirect(url_for('listar_choferes'))

                except mysql.connector.errors.DatabaseError:
                    # Estrategia 3: Usar SELECT FOR UPDATE para verificar locks
                    try:
                        cursor.execute("SELECT * FROM choferes WHERE dni = %s FOR UPDATE NOWAIT", (dni,))
                        cursor.execute("DELETE FROM choferes WHERE dni = %s", (dni,))
                        conn.commit()
                        flash(f"🗑️ Empleado '{empleado[0]}' eliminado correctamente", "success")
                        return redirect(url_for('listar_choferes'))

                    except mysql.connector.errors.DatabaseError:
                        # Si todo falla, informar al usuario
                        flash("⚠️ No se pudo eliminar el empleado debido a bloqueos en la base de datos. "
                              "Por favor, contacte al administrador del sistema.", "danger")
                        return redirect(url_for('listar_choferes'))
            else:
                raise lock_err

    except mysql.connector.errors.DatabaseError as db_err:
        if conn:
            try:
                conn.rollback()
            except:
                pass
        logger.error(f"Database error deleting employee {dni}: {db_err}")

        if "Lock wait timeout" in str(db_err):
            flash("⚠️ La base de datos está ocupada. Intente nuevamente en unos segundos.", "warning")
        elif "Deadlock found" in str(db_err):
            flash("⚠️ Conflicto de concurrencia. Intente nuevamente.", "warning")
        else:
            flash(f"❌ Error de base de datos al eliminar empleado: {str(db_err)}", "danger")

        return redirect(url_for('listar_choferes'))

    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except:
                pass
        logger.error(f"Unexpected error deleting employee {dni}: {e}")
        flash(f"❌ Error inesperado al eliminar empleado: {str(e)}", "danger")
        return redirect(url_for('listar_choferes'))

    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass
        if conn:
            try:
                conn.close()
            except:
                pass

@app.route('/chofer/imagen/<dni>')
def imagen_chofer(dni):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT imagen FROM choferes WHERE dni = %s", (dni,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result and result[0]:
         return send_file(BytesIO(redimensionar_imagen(result[0])), mimetype='image/jpeg')
    else:
        return "", 204


JWT_SECRET = os.getenv("JWT_SECRET", "cambia_esto_en_produccion")
JWT_EXPIRE_HRS = int(os.getenv("JWT_EXPIRE_HRS", 8))  # 8 h por defecto

@app.route("/api/login", methods=["POST"])
def login_chofer():
    data = request.get_json(silent=True) or {}
    dni = data.get("dni")

    if not dni:
        return jsonify(success=False, message="DNI requerido"), 400

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT nombre, sector FROM choferes WHERE dni = %s",
            (dni,),
        )
        row = cursor.fetchone()
    except Error as e:
        logger.error(f"Error de base de datos: {e}")
        return jsonify(success=False, message="Error de base de datos"), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    if not row:
        return jsonify(success=False, message="Empleado no encontrado"), 404

    nombre, sector = row

    # Generar JWT (expira en JWT_EXPIRE_HRS)
    exp = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HRS)
    token = jwt.encode({"dni": dni, "exp": exp}, JWT_SECRET, algorithm="HS256")

    return jsonify(
        success=True,
        nombre=nombre,
        sector=sector,
        dni=dni,
        token=token,
        expires_in=JWT_EXPIRE_HRS * 3600,
    )


@app.route('/kpis/<dni>')
def kpis(dni):
    conn = get_connection()
    cursor = conn.cursor()
    # 1) Obtener sector_id numérico del chofer
    cursor.execute("SELECT sector_id FROM choferes WHERE dni = %s", (dni,))
    result = cursor.fetchone()
    if not result:
        cursor.close(); conn.close()
        return jsonify({'message': 'Chofer no encontrado'}), 404
    sector_id = result[0]

    # 2) Traer los últimos 20 KPIs, uniendo con indicadores para el nombre
    cursor.execute("""
        SELECT k.fecha, i.nombre AS indicador, k.valor
          FROM kpis k
          JOIN indicadores i ON k.indicador_id = i.id
         WHERE k.dni = %s AND k.sector_id = %s
         ORDER BY k.fecha DESC
         LIMIT 20
    """, (dni, sector_id))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if not rows:
        return jsonify({'message': 'No se encontraron KPIs'}), 404

    # Armar el JSON
    latest_date = rows[0][0].strftime('%Y-%m-%d')
    kpis_dict = {'fecha': latest_date}
    for fecha, indicador, valor in rows:
        kpis_dict[indicador] = valor

    return jsonify(kpis_dict)

@app.route('/kpis/historial/<dni>')
def historial_kpis(dni):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT fecha, indicador_id, valor 
        FROM kpis 
        WHERE dni = %s 
        ORDER BY fecha DESC
    """, (dni,))
    rows = cursor.fetchall()
    # Retornar JSON
    return jsonify([
        {'fecha': r[0].isoformat(), 'indicador_id': r[1], 'valor': float(r[2])}
        for r in rows
    ])

@app.route('/avisos/<dni>')
def avisos(dni):
    if not dni.isdigit():
        return jsonify({'error': 'DNI inválido'}), 400

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, fecha, mensaje
            FROM avisos
            WHERE dni = %s
            ORDER BY fecha DESC
            LIMIT 5
        """, (dni,))
        rows = cursor.fetchall()
        avisos = [
            {
                'id': r[0],
                'fecha': r[1].strftime('%Y-%m-%d %H:%M'),
                'mensaje': r[2]
            }
            for r in rows
        ]
        return jsonify(avisos)

    except Exception as e:
        print(f"Error en /avisos/{dni}: {e}")
        return jsonify({'error': 'Error al consultar los avisos'}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/avisosh/<dni>')
def avisosh(dni):
    if not dni.isdigit():
        return jsonify({'error': 'DNI inválido'}), 400

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, fecha, mensaje
            FROM avisos
            WHERE dni = %s
            ORDER BY fecha DESC
            LIMIT 5
        """, (dni,))
        rows = cursor.fetchall()
        avisos = [
            {
                'id': r[0],
                'fecha': r[1].strftime('%Y-%m-%d %H:%M'),
                'mensaje': r[2]
            }
            for r in rows
        ]
        return jsonify(avisos)

    except Exception as e:
        print(f"Error en /avisos/{dni}: {e}")
        return jsonify({'error': 'Error al consultar los avisos'}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/admin/subida', methods=['GET', 'POST'])
@login_required
def subida_resultados():
    registros = []

    if request.method == 'POST':
        archivo = request.files['archivo']
        if not archivo or not archivo.filename.endswith('.txt'):
            flash("❌ El archivo debe ser .txt", "danger")
            return redirect(url_for('subida_resultados'))

        registros_insertados = 0
        lineas_invalidas = 0

        try:
            with get_connection() as conn:
                cursor = conn.cursor()

                for i, linea in enumerate(archivo.stream.readlines(), start=1):
                    try:
                        decoded = linea.decode('utf-8').strip()
                        if not decoded or decoded.startswith('#'):
                            continue

                        partes = decoded.split(',')
                        if len(partes) != 5:
                            print(f"[Línea {i}] ❌ Formato incorrecto: {decoded}")
                            lineas_invalidas += 1
                            continue

                        dni, fecha_str, indicador_id, sector_id, valor = partes

                        # Validar tipos
                        try:
                            fecha = datetime.strptime(fecha_str, '%Y-%m-%d').date()
                            indicador_id = int(indicador_id)
                            sector_id = int(sector_id)
                            valor = float(valor)
                        except ValueError as ve:
                            print(f"[Línea {i}] ❌ Error de conversión: {ve} - {decoded}")
                            lineas_invalidas += 1
                            continue

                        cursor.execute("""
                            INSERT INTO kpis (dni, fecha, indicador_id, sector_id, valor)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (dni, fecha, indicador_id, sector_id, valor))

                        cursor.execute("SELECT nombre FROM indicadores WHERE id = %s", (indicador_id,))
                        resultado = cursor.fetchone()
                        nombre_indicador = resultado[0] if resultado else f"ID {indicador_id}"

                        registros.append({
                            'dni': dni,
                            'fecha': fecha,
                            'indicador': nombre_indicador,
                            'valor': valor
                        })

                        registros_insertados += 1

                    except Exception as e:
                        print(f"[Línea {i}] ⚠️ Error al procesar la línea: {e} - {decoded}")
                        lineas_invalidas += 1

                conn.commit()

            mensaje = f"✅ {registros_insertados} registros cargados correctamente."
            if lineas_invalidas:
                mensaje += f" ⚠️ {lineas_invalidas} líneas fueron ignoradas por formato incorrecto."
            flash(mensaje, "success")

        except Exception as e:
            flash(f"❌ Error general al procesar el archivo: {str(e)}", "danger")

    return render_template('subida_resultados.html', registros=registros)

@app.route('/kpis/hoy_o_ultimo/<dni>')
def kpis_hoy_o_ultimo(dni):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Intentar traer el KPI más reciente por indicador de HOY
    cursor.execute("""
        SELECT k.fecha, k.indicador_id, i.nombre AS indicador, k.valor
        FROM kpis k
        JOIN indicadores i ON k.indicador_id = i.id
        JOIN (
            SELECT indicador_id, MAX(id) AS max_id
            FROM kpis
            WHERE dni = %s AND fecha = CURDATE()
            GROUP BY indicador_id
        ) ult ON k.id = ult.max_id
        WHERE k.dni = %s
        ORDER BY i.nombre
    """, (dni, dni))
    kpis_hoy = cursor.fetchall()

    if kpis_hoy:
        return jsonify({"fecha": str(date.today()), "kpis": kpis_hoy})

    # Si no hay KPIs de hoy, buscar el más reciente por indicador
    cursor.execute("""
        SELECT k1.fecha, k1.indicador_id, i.nombre AS indicador, k1.valor
        FROM kpis k1
        JOIN (
            SELECT indicador_id, MAX(fecha) AS max_fecha
            FROM kpis
            WHERE dni = %s
            GROUP BY indicador_id
        ) ult ON k1.indicador_id = ult.indicador_id AND k1.fecha = ult.max_fecha
        JOIN indicadores i ON k1.indicador_id = i.id
        JOIN (
            SELECT indicador_id, MAX(id) AS max_id
            FROM kpis
            WHERE dni = %s
            GROUP BY indicador_id
        ) maxk ON k1.id = maxk.max_id
        WHERE k1.dni = %s
        ORDER BY i.nombre
    """, (dni, dni, dni))
    ultimos_kpis = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify({"fecha": "último disponible", "kpis": ultimos_kpis})


@app.route('/admin/kpis')
@login_required
def vista_kpis():
    return render_template('kpis.html')

@app.route('/admin/kpis1')
@login_required
def vista_kpis1():
    return render_template('kpisFecha.html')

@app.route('/testdb')
def testdb():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT DATABASE()")
        db_name = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return f"✅ Conectado a la base de datos: {db_name}"
    except Exception as e:
        return f"❌ Error de conexión: {e}"

@app.route('/admin/db-status')
@login_required
def db_status():
    """Página de diagnóstico del estado de la base de datos."""
    locks = check_database_locks()

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Información general de la base de datos
        cursor.execute("SELECT DATABASE() as db_name, USER() as user, VERSION() as version")
        db_info = cursor.fetchone()

        # Contar registros en tablas principales
        cursor.execute("SELECT COUNT(*) as choferes FROM choferes")
        choferes_count = cursor.fetchone()['choferes']

        cursor.execute("SELECT COUNT(*) as reuniones FROM reuniones")
        reuniones_count = cursor.fetchone()['reuniones']

        cursor.execute("SELECT COUNT(*) as kpis FROM kpis")
        kpis_count = cursor.fetchone()['kpis']

        # Verificar conexiones activas
        cursor.execute("""
            SELECT COUNT(*) as active_connections
            FROM information_schema.processlist
            WHERE command != 'Sleep' OR time > 60
        """)
        active_connections = cursor.fetchone()['active_connections']

        return render_template('db_status.html',
                             db_info=db_info,
                             locks=locks,
                             choferes_count=choferes_count,
                             reuniones_count=reuniones_count,
                             kpis_count=kpis_count,
                             active_connections=active_connections)

    except Exception as e:
        logger.error(f"Error getting database status: {e}")
        return f"❌ Error obteniendo estado de la base de datos: {e}"
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    # ─────────────────────── utilidades ────────────────────────
def cargar_sectores(cursor):
    """
    Devuelve:
      • lista  =  [{'id': 1, 'nombre': 'ALMACEN'}, …]  (ordenada por id)
      • mapa   =  {1: 'ALMACEN', 2: 'ENTREGA', …}
    """
    cursor.execute("SELECT id, nombre FROM sectores ORDER BY id")
    lista = cursor.fetchall()
    mapa  = {s['id']: s['nombre'] for s in lista}
    return lista, mapa


def obtener_sectores():
    """
    Igual que cargar_sectores, pero abre y cierra conexión.
    Pensado para usar en las views de 'nuevo' y 'editar'.
    """
    conn   = get_connection()
    cur    = conn.cursor(dictionary=True)
    lista, _ = cargar_sectores(cur)
    cur.close()
    conn.close()
    return lista
# ────────────────────────────────────────────────────────────

# ╭───────────────────────── LISTADO ─────────────────────────╮
@app.route('/admin/indicadores', methods=['GET'])
@login_required
def admin_indicadores():
    sector_id = request.args.get('sector_id', type=int)
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Sectores
    sectores, _ = cargar_sectores(cursor)

    # Indicadores + sector + objetivo vigente + (tipo/color/fill)
    query = """
        SELECT i.id, i.nombre, i.sector_id, i.activo,
               i.tipo_grafico, i.color_grafico, i.fill_grafico,
               s.nombre AS sector_nombre,
               o.objetivo_tipo, o.objetivo_valor
          FROM indicadores i
          JOIN sectores s ON s.id = i.sector_id
     LEFT JOIN objetivos_indicadores o
            ON o.indicador_id = i.id AND o.anio = %s
    """
    params = [datetime.now().year]

    if sector_id:
        query += " WHERE i.sector_id = %s"
        params.append(sector_id)

    query += " ORDER BY s.nombre, i.nombre"
    cursor.execute(query, tuple(params))
    indicadores = cursor.fetchall()

    cursor.close(); conn.close()

    return render_template(
        "admin_indicadores.html",
        indicadores=indicadores,
        sectores=sectores,
        sector_id=sector_id,
        current_year=datetime.now().year
    )
# ╰───────────────────────────────────────────────────────────╯


# ╭───────────────────────── ALTA ────────────────────────────╮
@app.route('/admin/indicadores/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_indicador():
    sectores = obtener_sectores()
    form = {
        "nombre": "",
        "sector_id": "",
        "activo": "1",
        "tipo_grafico": "",
        "color_grafico": "",
        "fill_grafico": ""  # checkbox
    }

    if request.method == 'POST':
        form["nombre"]        = request.form.get('nombre', '').strip().upper()
        form["sector_id"]     = request.form.get('sector_id') or ""
        form["activo"]        = request.form.get('activo') or "0"
        form["tipo_grafico"]  = (request.form.get('tipo_grafico') or '').strip() or None
        color_hex = (request.form.get('color_grafico') or '').strip()
        form["color_grafico"] = color_hex if color_hex else None
        # checkbox: 'on' si marcado, None si no
        fill = request.form.get('fill_grafico')
        form["fill_grafico"]  = 1 if fill else None  # None = no definido

        if not form["nombre"]:
            flash("❌ El nombre es obligatorio.", "danger")
        elif not form["sector_id"]:
            flash("❌ Debe seleccionar un sector.", "danger")
        else:
            conn = get_connection()
            cur  = conn.cursor()

            # validar duplicado por nombre+sector
            cur.execute("""
                SELECT 1 FROM indicadores
                 WHERE LOWER(nombre)=%s AND sector_id=%s
            """, (form["nombre"].lower(), int(form["sector_id"])))
            if cur.fetchone():
                flash("❌ Ya existe un indicador con ese nombre en ese sector.", "danger")
            else:
                cur.execute("""
                    INSERT INTO indicadores
                        (nombre, sector_id, activo, tipo_grafico, color_grafico, fill_grafico)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    form["nombre"], int(form["sector_id"]), int(form["activo"]),
                    form["tipo_grafico"], form["color_grafico"], form["fill_grafico"]
                ))
                conn.commit()
                flash("✅ Indicador creado correctamente.", "success")
                cur.close(); conn.close()
                return redirect(url_for('admin_indicadores'))

            cur.close(); conn.close()

    return render_template(
        'nuevo_indicador.html',
        sectores=sectores, form=form,
        current_year=datetime.now().year
    )
# ╰───────────────────────────────────────────────────────────╯


# ╭───────────────────────── EDICIÓN ─────────────────────────╮
@app.route('/admin/indicadores/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_indicador(id):
    sectores = obtener_sectores()
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        nombre        = request.form.get('nombre', '').strip().upper()
        sector_id     = int(request.form.get('sector_id'))
        activo        = int(request.form.get('activo'))

        tipo_grafico  = (request.form.get('tipo_grafico') or '').strip() or None
        color_hex     = (request.form.get('color_grafico') or '').strip()
        color_grafico = color_hex if color_hex else None
        fill_grafico  = 1 if request.form.get('fill_grafico') else None  # None = sin definir

        # Duplicado en el mismo sector (excluyendo el actual)
        cursor.execute("""
            SELECT id FROM indicadores
             WHERE LOWER(nombre) = %s
               AND sector_id = %s
               AND id <> %s
        """, (nombre.lower(), sector_id, id))
        if cursor.fetchone():
            flash("❌ Ya existe un indicador con ese nombre en ese sector.", "danger")
        else:
            cursor.execute("""
                UPDATE indicadores
                   SET nombre=%s, sector_id=%s, activo=%s,
                       tipo_grafico=%s, color_grafico=%s, fill_grafico=%s
                 WHERE id=%s
            """, (nombre, sector_id, activo,
                  tipo_grafico, color_grafico, fill_grafico, id))
            conn.commit()
            flash("✅ Indicador actualizado correctamente.", "success")
            cursor.close(); conn.close()
            return redirect(url_for('admin_indicadores'))

    # GET: cargar indicador
    cursor.execute("SELECT * FROM indicadores WHERE id=%s", (id,))
    indicador = cursor.fetchone()
    if not indicador:
        cursor.close(); conn.close()
        flash("❌ Indicador no encontrado.", "danger")
        return redirect(url_for('admin_indicadores'))

    # GET: objetivos del indicador
    cursor.execute("""
        SELECT id, indicador_id, anio, objetivo_tipo, objetivo_valor
          FROM objetivos_indicadores
         WHERE indicador_id=%s
         ORDER BY anio DESC
    """, (id,))
    objetivos = cursor.fetchall()
    cursor.close(); conn.close()

    return render_template(
        "editar_indicador.html",
        indicador=indicador,
        sectores=sectores,
        objetivos=objetivos,
        current_year=datetime.now().year
    )
# ╰───────────────────────────────────────────────────────────╯


# ╭───────────────────────── TOGGLE ─────────────────────────╮
@app.route('/admin/indicadores/toggle/<int:id>', methods=['POST'])
@login_required
def toggle_indicador(id):
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE indicadores
           SET activo = NOT activo
         WHERE id = %s
    """, (id,))
    conn.commit()

    cursor.close(); conn.close()
    return redirect(request.referrer or url_for('admin_indicadores'))
# ╰───────────────────────────────────────────────────────────╯

# ╭───────────────────────── CRUD OBJETIVOS ─────────────────────────╮
@app.route('/admin/objetivos/nuevo/<int:indicador_id>', methods=['GET', 'POST'])
@login_required
def nuevo_objetivo(indicador_id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Verificar que el indicador existe
    cursor.execute("SELECT * FROM indicadores WHERE id = %s", (indicador_id,))
    indicador = cursor.fetchone()
    if not indicador:
        flash("❌ Indicador no encontrado.", "danger")
        return redirect(url_for('admin_indicadores'))

    if request.method == 'POST':
        anio          = request.form['anio']
        objetivo_tipo = request.form['objetivo_tipo']
        objetivo_valor = request.form['objetivo_valor']

        cursor.execute("""
            INSERT INTO objetivos_indicadores (indicador_id, anio, objetivo_tipo, objetivo_valor)
            VALUES (%s, %s, %s, %s)
        """, (indicador_id, anio, objetivo_tipo, objetivo_valor))
        conn.commit()

        flash("✅ Objetivo agregado correctamente.", "success")
        cursor.close(); conn.close()
        return redirect(url_for('editar_indicador', id=indicador_id))

    cursor.close(); conn.close()
    return render_template("nuevo_objetivo.html", indicador=indicador)


@app.route('/admin/objetivos/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_objetivo(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM objetivos_indicadores WHERE id = %s", (id,))
    objetivo = cursor.fetchone()

    if not objetivo:
        flash("❌ Objetivo no encontrado.", "danger")
        return redirect(url_for('admin_indicadores'))

    if request.method == 'POST':
        anio          = request.form['anio']
        objetivo_tipo = request.form['objetivo_tipo']
        objetivo_valor = request.form['objetivo_valor']

        cursor.execute("""
            UPDATE objetivos_indicadores
               SET anio = %s, objetivo_tipo = %s, objetivo_valor = %s
             WHERE id = %s
        """, (anio, objetivo_tipo, objetivo_valor, id))
        conn.commit()

        flash("✅ Objetivo actualizado correctamente.", "success")
        cursor.close(); conn.close()
        return redirect(url_for('editar_indicador', id=objetivo['indicador_id']))

    cursor.close(); conn.close()
    return render_template("editar_objetivo.html", objetivo=objetivo)


@app.route('/admin/objetivos/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_objetivo(id):
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT indicador_id FROM objetivos_indicadores WHERE id = %s", (id,))
    objetivo = cursor.fetchone()

    if not objetivo:
        flash("❌ Objetivo no encontrado.", "danger")
        return redirect(url_for('admin_indicadores'))

    indicador_id = objetivo['indicador_id']

    cursor.execute("DELETE FROM objetivos_indicadores WHERE id = %s", (id,))
    conn.commit()

    flash("🗑️ Objetivo eliminado.", "warning")
    cursor.close(); conn.close()
    return redirect(url_for('editar_indicador', id=indicador_id))
# ╰───────────────────────────────────────────────────────────╯


@app.route('/registrar_token', methods=['POST'])
def registrar_token():
    conn = None
    cursor = None
    
    try:
        # Verificar que la petición contenga JSON
        if not request.is_json:
            return jsonify({
                "status": "error",
                "mensaje": "Contenido debe ser JSON"
            }), 400
        
        data = request.json
        
        # Validar que existan los campos requeridos
        if not data:
            return jsonify({
                "status": "error",
                "mensaje": "Datos JSON vacíos"
            }), 400
            
        if 'dni' not in data or 'token' not in data:
            return jsonify({
                "status": "error",
                "mensaje": "Faltan campos requeridos: dni y token"
            }), 400
        
        dni = data['dni']
        token = data['token']
        
        # Validar DNI
        if not dni:
            return jsonify({
                "status": "error",
                "mensaje": "DNI no puede estar vacío"
            }), 400
            
        # Convertir DNI a string y validar formato (ejemplo para DNI argentino: 8 dígitos)
        dni_str = str(dni).strip()
        if not re.match(r'^\d{7,8}$', dni_str):
            return jsonify({
                "status": "error",
                "mensaje": "DNI debe contener entre 7 y 8 dígitos"
            }), 400
        
        # Validar token
        if not token or not isinstance(token, str):
            return jsonify({
                "status": "error",
                "mensaje": "Token debe ser una cadena de texto válida"
            }), 400
            
        token = token.strip()
        if len(token) < 10:  # Asumiendo longitud mínima del token
            return jsonify({
                "status": "error",
                "mensaje": "Token demasiado corto (mínimo 10 caracteres)"
            }), 400
        
        # Operaciones de base de datos
        conn = get_connection()
        cursor = conn.cursor()
        
        # Verificar si la conexión es válida
        if not conn or not cursor:
            raise Exception("Error al conectar con la base de datos")
        
        # Ejecutar la consulta
        cursor.execute("""
            INSERT INTO tokens (dni, token, fecha_registro, fecha_actualizacion)
            VALUES (%s, %s, NOW(), NOW())
            ON DUPLICATE KEY UPDATE 
                token = VALUES(token),
                fecha_actualizacion = NOW()
        """, (dni_str, token))
        
        # Verificar si se afectaron filas
        if cursor.rowcount == 0:
            raise Exception("No se pudo registrar el token")
        
        conn.commit()
        
        # Registrar la operación exitosa
        logger.info(f"Token registrado/actualizado exitosamente para DNI: {dni_str}")
        
        return jsonify({
            "status": "exitoso",
            "mensaje": "Token registrado correctamente",
            "dni": dni_str
        }), 200
        
    except ValueError as ve:
        logger.error(f"Error de validación: {str(ve)}")
        return jsonify({
            "status": "error",
            "mensaje": "Error en la validación de datos"
        }), 400
        
    except Exception as e:
        logger.error(f"Error al registrar token: {str(e)}")
        
        # Rollback si hay transacción activa
        if conn:
            try:
                conn.rollback()
            except:
                pass
                
        return jsonify({
            "status": "error",
            "mensaje": "Error interno del servidor"
        }), 500
        
    finally:
        # Cerrar recursos de base de datos
        if cursor:
            try:
                cursor.close()
            except Exception as e:
                logger.error(f"Error cerrando cursor: {str(e)}")
                
        if conn:
            try:
                conn.close()
            except Exception as e:
                logger.error(f"Error cerrando conexión: {str(e)}")


# Función auxiliar para validar DNI más específicamente (opcional)
def validar_dni_argentino(dni):
    """
    Valida formato de DNI argentino y calcula dígito verificador si es necesario
    """
    dni_str = str(dni).strip()
    
    # Verificar que solo contenga dígitos
    if not dni_str.isdigit():
        return False
    
    # Verificar longitud (7-8 dígitos)
    if len(dni_str) < 7 or len(dni_str) > 8:
        return False
    
    # Aquí podrías agregar validación del dígito verificador si lo necesitas
    
    return True


# Endpoint adicional para verificar si un token existe (opcional)
@app.route('/verificar_token', methods=['GET'])
def verificar_token():
    dni = request.args.get('dni')
    
    if not dni:
        return jsonify({
            "status": "error",
            "mensaje": "DNI requerido"
        }), 400
    
    conn = None
    cursor = None
    
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT token FROM tokens WHERE dni = %s", (dni,))
        resultado = cursor.fetchone()
        
        if resultado:
            return jsonify({
                "status": "exitoso",
                "existe": True,
                "dni": dni
            }), 200
        else:
            return jsonify({
                "status": "exitoso",
                "existe": False,
                "dni": dni
            }), 200
            
    except Exception as e:
        logger.error(f"Error verificando token: {str(e)}")
        return jsonify({
            "status": "error",
            "mensaje": "Error interno del servidor"
        }), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()



@app.route('/avisos_push', methods=['GET', 'POST'])
#@login_required
def avisos_push():
    conn = get_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        dni = request.form['dni'].strip()
        mensaje = request.form['mensaje'].strip()
        titulo = "📢 Nuevo aviso"

        if not dni or not mensaje:
            flash("❌ Todos los campos son obligatorios", "danger")
            return redirect(url_for('avisos_push'))

        # Buscar token FCM
        cursor.execute("SELECT token FROM tokens WHERE dni = %s", (dni,))
        fila = cursor.fetchone()

        if not fila or not fila[0]:
            flash(f"⚠️ No se encontró token registrado para el DNI {dni}", "warning")
            return redirect(url_for('avisos_push'))

        token = fila[0]

        try:
            status_code, respuesta = enviar_push(token, titulo, mensaje)

            if status_code == 200:
                cursor.execute("""
                    INSERT INTO avisos_push (dni, titulo, mensaje)
                    VALUES (%s, %s, %s)
                """, (dni, titulo, mensaje))
                conn.commit()
                flash("✅ Aviso push enviado correctamente", "success")
            else:
                flash(f"❌ Error al enviar push: {respuesta}", "danger")

        except Exception as e:
            flash(f"❌ Error inesperado: {e}", "danger")

        return redirect(url_for('avisos_push'))

    # Mostrar últimos avisos
    cursor.execute("""
        SELECT dni, titulo, mensaje, fecha
        FROM avisos_push
        ORDER BY fecha DESC
        LIMIT 20
    """)
    historial = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template("avisos_push.html", historial=historial)


@app.route('/api/indicadores_activos/<int:sector_id>')
def api_indicadores_activos(sector_id):
    """
    Devuelve los indicadores activos (id, nombre) de un sector en formato JSON.
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, nombre
        FROM indicadores
        WHERE sector_id = %s AND activo = 1
        ORDER BY nombre
    """, (sector_id,))
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

@app.route('/kpis/historial_detallado/<dni>')
def historial_kpis_detallado(dni):
    """
    Devuelve historial de KPIs con el nombre del indicador en lugar del ID.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT k.fecha, i.nombre AS indicador, k.valor
        FROM kpis k
        JOIN indicadores i ON k.indicador_id = i.id
        WHERE k.dni = %s
        ORDER BY k.fecha DESC
    """, (dni,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([
        {'fecha': r[0].isoformat(), 'indicador': r[1], 'valor': float(r[2])}
        for r in rows
    ])
    
# ────────────────────────────────────────────────────────────────
# 1. Resumen compacto – tarjetas (suma en el rango):
#    /api/resumen_dashboard?sector_id=2&from=2025-06-01&to=2025-06-10
# ────────────────────────────────────────────────────────────────
@app.route('/api/resumen_dashboard')
def api_resumen_dashboard():
    try:
        sector_id = int(request.args.get('sector_id', 1))
        fecha_ini = request.args.get('from')
        fecha_fin = request.args.get('to')
        if not fecha_ini or not fecha_fin:
            return jsonify({'tarjetas': []})

        conn   = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Traer indicadores activos de este sector
        cursor.execute("""
            SELECT id, nombre, tipo_grafico, color_grafico, fill_grafico
              FROM indicadores
             WHERE sector_id = %s
               AND activo = 1
            ORDER BY nombre
        """, (sector_id,))
        indicadores = cursor.fetchall()

        tarjetas = []
        for ind in indicadores:
            cursor.execute("""
                SELECT ROUND(AVG(valor), 2) AS promedio
                  FROM kpis
                 WHERE indicador_id = %s
                   AND sector_id    = %s
                   AND fecha BETWEEN %s AND %s
            """, (ind['id'], sector_id, fecha_ini, fecha_fin))
            prom = cursor.fetchone()['promedio'] or 0
            tarjetas.append({
                'indicador':  ind['nombre'],
                'valor':       float(prom),
                'indicador_id': ind['id'],
                'tipo':        ind['tipo_grafico'],
                'color':       ind['color_grafico'],
                'fill':        bool(ind['fill_grafico'])
            })

        cursor.close()
        conn.close()
        return jsonify({'tarjetas': tarjetas})

    except Exception as e:
        logger.error(f"Error en resumen_dashboard: {e}")
        return jsonify({'tarjetas': []}), 500


# ────────────────────────────────────────────────────────────────
# 2. Serie histórica por indicador:
#    /api/serie_indicador?indicador_id=1&sector_id=2&from=2025-06-01&to=2025-06-10
# ────────────────────────────────────────────────────────────────
@app.route('/api/serie_indicador')
def api_serie_indicador():
    try:
        indicador_id = int(request.args.get('indicador_id'))
        sector_id    = int(request.args.get('sector_id', 1))
        fecha_ini    = request.args.get('from')
        fecha_fin    = request.args.get('to')
        if not (fecha_ini and fecha_fin):
            return jsonify({'labels': [], 'data': [], 'indicador': 'Sin datos'})

        conn   = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Parámetros del indicador
        cursor.execute("""
            SELECT nombre, tipo_grafico, color_grafico, fill_grafico
              FROM indicadores
             WHERE id = %s
        """, (indicador_id,))
        ind = cursor.fetchone() or {}

        # Serie histórica filtrada por sector_id
        cursor.execute("""
            SELECT fecha, ROUND(AVG(valor),2) AS promedio
              FROM kpis
             WHERE indicador_id = %s
               AND sector_id    = %s
               AND fecha BETWEEN %s AND %s
          GROUP BY fecha
          ORDER BY fecha
        """, (indicador_id, sector_id, fecha_ini, fecha_fin))
        rows = cursor.fetchall()

        labels = [r['fecha'].strftime('%d/%m') for r in rows]
        data   = [float(r['promedio'])             for r in rows]

        cursor.close()
        conn.close()

        return jsonify({
            'indicador': ind.get('nombre', 'Desconocido'),
            'tipo':       ind.get('tipo_grafico', 'bar'),
            'color':      ind.get('color_grafico', '#0d6efd'),
            'fill':       bool(ind.get('fill_grafico', False)),
            'labels':     labels,
            'data':       data
        })

    except Exception as e:
        logger.error(f"Error en serie_indicador: {e}")
        return jsonify({'labels': [], 'data': [], 'indicador': 'Error'}), 500
    
    
@app.route('/api/serie_indicador_dni')
#@jwt_required_api
def serie_indicador_dni():
    dni          = request.args.get('dni')
    indicador_id = request.args.get('indicador_id', type=int)
    f_ini        = request.args.get('from', default='2024-01-01')
    f_fin        = request.args.get('to',   default='2050-01-01')

    conn = get_connection()
    cur  = conn.cursor(dictionary=True)

    # datos de la serie
    cur.execute("""
        SELECT fecha, ROUND(SUM(valor),2) total
          FROM kpis
         WHERE dni = %s
           AND indicador_id = %s
           AND fecha BETWEEN %s AND %s
      GROUP BY fecha
      ORDER BY fecha
    """, (dni, indicador_id, f_ini, f_fin))
    rows = cur.fetchall()

    # estilo del indicador
    cur.execute("""
        SELECT color_grafico color,
               tipo_grafico  tipo,
               fill_grafico  fill
          FROM indicadores
         WHERE id = %s
    """, (indicador_id,))
    est = cur.fetchone() or {}

    cur.close(); conn.close()

    return jsonify({
        'labels': [r['fecha'].strftime('%d/%m') for r in rows],
        'data'  : [r['total'] for r in rows],
        'color' : est.get('color', '#0d6efd'),
        'tipo'  : est.get('tipo',  'bar'),
        'fill'  : bool(est.get('fill', 0))
    })
    

@app.route('/api/kpis_por_dni/<dni>')
def kpis_por_dni(dni):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    # ── Datos del chofer ───────────────────────────────
    cur.execute("""
        SELECT c.nombre, c.sector, c.imagen, MAX(k.fecha) AS ultima_fecha
          FROM choferes c
     LEFT JOIN kpis k ON k.dni = c.dni
         WHERE c.dni = %s
         GROUP BY c.nombre, c.sector, c.imagen
         LIMIT 1
    """, (dni,))
    row = cur.fetchone()
    chofer = {}

    if row:
        chofer['nombre'] = row['nombre']
        chofer['sector'] = row['sector']
        chofer['foto'] = (
            "data:image/jpeg;base64," + base64.b64encode(row['imagen']).decode()
        ) if row['imagen'] else None
        chofer['fecha'] = row['ultima_fecha'].strftime('%Y-%m-%d') if row['ultima_fecha'] else 'Sin registros'

    # ── KPIs agregados ────────────────────────────────
    cur.execute("""
        SELECT i.id indicador_id,
               i.nombre indicador,
               i.color_grafico color,
               i.tipo_grafico  tipo,
               i.fill_grafico  fill,
               ROUND(AVG(k.valor),2) valor
          FROM kpis k
          JOIN indicadores i ON i.id = k.indicador_id
         WHERE k.dni = %s
      GROUP BY i.id, i.nombre, i.color_grafico, i.tipo_grafico, i.fill_grafico
    """, (dni,))
    tarjetas = [dict(r) for r in cur.fetchall()]

    cur.close()
    conn.close()

    return jsonify({'chofer': chofer, 'tarjetas': tarjetas})


@app.route('/api/empleados/<dni>/kpis/resumen')
#@jwt_required_api
def kpis_resumen(dni):
    # ── 1) Parámetros de fecha ───────────────────────────────
    fecha_inicio = request.args.get('from')  or request.args.get('fecha_inicio')
    fecha_fin    = request.args.get('to')    or request.args.get('fecha_fin')

    cond_fecha   = ""
    params_fecha = []
    try:
        if fecha_inicio:
            dt_ini = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
            cond_fecha += " AND DATE(k.fecha) >= %s"
            params_fecha.append(dt_ini)
        if fecha_fin:
            dt_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
            cond_fecha += " AND DATE(k.fecha) <= %s"
            params_fecha.append(dt_fin)
    except ValueError:
        return jsonify({"error": "Formato de fecha inválido. Use YYYY-MM-DD"}), 400

    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    # ── 2) Datos del empleado ────────────────────────────────
    cursor.execute("""
        SELECT nombre, sector, imagen
          FROM choferes
         WHERE dni = %s
         LIMIT 1
    """, (dni,))
    chofer = cursor.fetchone() or {}

    if chofer.get('imagen'):
        chofer['foto'] = (
            "data:image/jpeg;base64," +
            base64.b64encode(chofer['imagen']).decode()
        )
    else:
        chofer['foto'] = None
    chofer.pop('imagen', None)

    # ── 3) KPIs promediados (filtrados) ──────────────────────
    sql = f"""
        SELECT i.id            AS indicador_id,
               i.nombre        AS indicador,
               i.color_grafico AS color,
               i.tipo_grafico  AS tipo,
               i.fill_grafico  AS fill,
               ROUND(AVG(k.valor),2) AS valor
          FROM kpis k
          JOIN indicadores i ON i.id = k.indicador_id
         WHERE k.dni = %s
           {cond_fecha}
      GROUP BY i.id, i.nombre, i.color_grafico, i.tipo_grafico, i.fill_grafico
      ORDER BY i.nombre
    """

    # DEBUG opcional (sin mogrify, imprime la consulta y los params)
    if app.debug:
        app.logger.debug("SQL: %s", sql)
        app.logger.debug("PARAMS: %s", (dni, *params_fecha))

    cursor.execute(sql, (dni, *params_fecha))
    tarjetas = [dict(r) for r in cursor.fetchall()]

    cursor.close()
    conn.close()
    return jsonify({"empleado": chofer, "kpis": tarjetas})

@app.route('/api/empleados/<dni>/indicadores/<int:indicador_id>/serie')
#@jwt_required_api
def serie_indicador(dni, indicador_id):
    # 1) Parámetros de rango ---------------------------------------
    fecha_inicio = request.args.get('from')
    fecha_fin    = request.args.get('to')
    if not (fecha_inicio and fecha_fin):
        return jsonify({"error": "Debe enviar from y to"}), 400
    try:
        dt_ini = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
        dt_fin = datetime.strptime(fecha_fin,    '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Formato de fecha inválido"}), 400

    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    # 2) Metadatos del indicador -----------------------------------
    cursor.execute("""
        SELECT nombre, tipo_grafico, color_grafico, fill_grafico
          FROM indicadores
         WHERE id = %s
    """, (indicador_id,))
    meta = cursor.fetchone()
    if not meta:
        cursor.close(); conn.close()
        return jsonify({"error": "Indicador no encontrado"}), 404

    # 3) Serie histórica (agrupada por día) ------------------------
    cursor.execute("""
        SELECT DATE(fecha)  AS fecha,
               ROUND(AVG(valor), 2) AS avg_val
          FROM kpis
         WHERE dni          = %s
           AND indicador_id = %s
           AND DATE(fecha) BETWEEN %s AND %s
      GROUP BY DATE(fecha)
      ORDER BY DATE(fecha)
    """, (dni, indicador_id, dt_ini, dt_fin))
    rows = cursor.fetchall()

    cursor.close(); conn.close()

    labels = [r['fecha'].strftime('%Y-%m-%d') for r in rows]
    data   = [float(r['avg_val']) for r in rows]

    return jsonify({
        "labels": labels,
        "data":   data,
        "color":  meta['color_grafico'] or "#1565C0",
        "fill":   bool(meta['fill_grafico']),
        "tipo":   meta['tipo_grafico'] or "line"
    })

@app.route('/kpis/promedio_mes/<dni>')
#@jwt_required_api
def promedio_mes_kpis(dni):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT i.nombre AS indicador, AVG(k.valor) as promedio
        FROM kpis k
        JOIN indicadores i ON k.indicador_id = i.id
        WHERE k.dni = %s
          AND YEAR(k.fecha) = YEAR(CURDATE())
          AND MONTH(k.fecha) = MONTH(CURDATE())
        GROUP BY k.indicador_id
    """, (dni,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if not rows:
        return jsonify({'message': 'No hay datos para este mes'}), 404

    # Armar respuesta
    return jsonify([
        {'indicador': r[0], 'promedio': float(r[1])}
        for r in rows
    ])

@app.route('/api/solicitar_vale', methods=['POST'])
def solicitar_vale():
    try:
        data = request.get_json(force=True)
        dni = data.get('dni')
        if not dni:
            raise ValueError("DNI vacío o nulo")
    except Exception as e:
        print(f"❌ Error parseando JSON o DNI inválido: {e}")
        return jsonify({"success": False, "message": "Error en datos enviados"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    hoy = date.today()
    mes_actual = hoy.month
    anio_actual = hoy.year

    try:
        cursor.execute("""
            SELECT 1 FROM vales_solicitados
            WHERE dni = %s AND MONTH(fecha_solicitud) = %s AND YEAR(fecha_solicitud) = %s
        """, (dni, mes_actual, anio_actual))

        if cursor.fetchone():
            return jsonify({"success": False, "message": "Ya solicitaste un vale este mes"}), 400

        cursor.execute("""
            INSERT INTO vales_solicitados (dni, fecha_solicitud)
            VALUES (%s, %s)
        """, (dni, hoy))
        conn.commit()
        return jsonify({"success": True, "message": "Vale solicitado correctamente"}), 200

    except Exception as e:
        conn.rollback()
        print(f"❌ Error en base de datos: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/dashboard/vales', methods=['GET'])
@login_required
def ver_vales():
    if 'admin' not in session:
        return redirect(url_for('login'))

    mes = request.args.get('mes')
    anio = request.args.get('anio')

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        condiciones = []
        valores = []

        if mes:
            condiciones.append("v.mes = %s")
            valores.append(mes)

        if anio:
            condiciones.append("v.anio = %s")
            valores.append(anio)

        where_clause = "WHERE " + " AND ".join(condiciones) if condiciones else ""

        cursor.execute(f"""
            SELECT 
                v.dni,
                c.nombre,
                c.sector,
                v.mes,
                v.anio,
                COUNT(*) AS cantidad_vales
            FROM vales_solicitados v
            JOIN choferes c ON v.dni = c.dni
            {where_clause}
            GROUP BY v.dni, v.anio, v.mes
            ORDER BY v.anio DESC, v.mes DESC, c.nombre;
        """, valores)
        vales = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template('vales_dashboard.html', vales=vales, mes_filtro=mes, anio_filtro=anio)


@app.route('/api/empleados/<string:dni>/indicadores/series')
def indicadores_series(dni):
    # 1) Obtener parámetros de fecha -------------------------------
    fecha_inicio = request.args.get('from')
    fecha_fin    = request.args.get('to')

    if not fecha_inicio or not fecha_fin:
        return jsonify({"error": "Debe enviar parámetros 'from' y 'to' en formato YYYY-MM-DD"}), 400

    try:
        dt_ini = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
        dt_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Formato de fecha inválido"}), 400

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # 🧠 Obtener sector_id del chofer
        cursor.execute("SELECT sector_id FROM choferes WHERE dni = %s", (dni,))
        chofer = cursor.fetchone()
        if not chofer:
            return jsonify({"error": "DNI no encontrado"}), 404

        sector_id = chofer['sector_id']

        # 2) Traer indicadores del sector del chofer ----------------
        cursor.execute("""
            SELECT id, nombre, tipo_grafico, color_grafico, fill_grafico
              FROM indicadores
             WHERE sector_id = %s
        """, (sector_id,))
        indicadores = cursor.fetchall()

        resultado = []

        for indicador in indicadores:
            indicador_id = indicador['id']

            # 3) Obtener la serie histórica por indicador ------------
            cursor.execute("""
                SELECT DATE(fecha) AS fecha,
                       ROUND(AVG(valor), 2) AS avg_val
                  FROM kpis
                 WHERE dni = %s
                   AND indicador_id = %s
                   AND DATE(fecha) BETWEEN %s AND %s
              GROUP BY DATE(fecha)
              ORDER BY DATE(fecha)
            """, (dni, indicador_id, dt_ini, dt_fin))

            rows = cursor.fetchall()
            labels = [r['fecha'].strftime('%Y-%m-%d') for r in rows]
            data   = [float(r['avg_val']) for r in rows]

            resultado.append({
                "id": indicador_id,
                "nombre": indicador['nombre'],
                "tipo": indicador.get('tipo_grafico') or "line",
                "color": indicador.get('color_grafico') or "#1565C0",
                "fill": bool(indicador.get('fill_grafico')),
                "labels": labels,
                "data": data
            })

        return jsonify({"indicadores": resultado})

    except Exception as e:
        return jsonify({"error": "Error interno del servidor", "detalle": str(e)}), 500

    finally:
        if cursor: cursor.close()
        if conn: conn.close()
        
@app.route('/api/pedidos', methods=['POST'])
def guardar_pedido():
    try:
        data = request.get_json()

        # 1) Validar campos obligatorios
        dni         = data.get('dni')
        sucursal_id = data.get('sucursal_id')
        observaciones = data.get('observaciones', '')
        items       = data.get('items', [])

        if not dni or not sucursal_id or not items:
            return jsonify({"error": "Debe enviar 'dni', 'sucursal_id' y 'items'"}), 400

        conn = get_connection()
        cursor = conn.cursor()

        # 2) Insertar pedido en encabezado
        cursor.execute("""
            INSERT INTO pedidos_mercaderia (dni, sucursal_id, observaciones)
            VALUES (%s, %s, %s)
        """, (dni, sucursal_id, observaciones))
        pedido_id = cursor.lastrowid

        # 3) Insertar detalle
        for item in items:
            articulo_id = item.get('articulo_id')
            cantidad    = item.get('cantidad')
            descripcion = item.get('descripcion', '')

            if not articulo_id or not cantidad:
                continue  # ignoramos ítems incompletos

            cursor.execute("""
                INSERT INTO detalle_pedido_mercaderia (pedido_id, articulo_id, cantidad, descripcion)
                VALUES (%s, %s, %s, %s)
            """, (pedido_id, articulo_id, cantidad, descripcion))

        conn.commit()

        return jsonify({
            "mensaje": "✅ Pedido guardado correctamente",
            "pedido_id": pedido_id
        }), 201

    except Exception as e:
        if conn:
            conn.rollback()
        return jsonify({
            "error": "Error interno del servidor",
            "detalle": str(e)
        }), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



@app.route('/api/buscar_articulos', methods=['GET'])
def buscar_articulos():
    descripcion = request.args.get('q', '').strip()
    marca = request.args.get('marca', '').strip()
    calibre = request.args.get('calibre', '').strip()

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT Articulo AS codigo, DescripcionArticulo AS descripcion, Marca, Calibre
            FROM articulosCSV
            WHERE Activo = 'SI'
              AND UsadoEnDispositivoMovil = 'SI'
              AND Anulado = 'NO'
        """
        params = []

        if descripcion:
            query += " AND DescripcionArticulo LIKE %s"
            params.append(f"%{descripcion}%")

        if marca:
            query += " AND Marca LIKE %s"
            params.append(f"%{marca}%")

        if calibre:
            query += " AND Calibre LIKE %s"
            params.append(f"%{calibre}%")

        query += " ORDER BY DescripcionArticulo"

        cursor.execute(query, params)
        resultados = cursor.fetchall()

        return jsonify(resultados)

    except Exception as e:
        return jsonify({"error": "Error en la búsqueda", "detalle": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/api/filtros_articulos')
def obtener_filtros_articulos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT DISTINCT marca FROM articuloscsv WHERE marca IS NOT NULL AND marca != ''")
        marcas = [row['marca'] for row in cursor.fetchall()]

        cursor.execute("SELECT DISTINCT calibre FROM articuloscsv WHERE calibre IS NOT NULL AND calibre != ''")
        calibres = [row['calibre'] for row in cursor.fetchall()]

        return jsonify({
            "marcas": marcas,
            "calibres": calibres
        })
    finally:
        cursor.close()
        conn.close()

@app.route('/api/marcas')
def obtener_marcas():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT Marca 
            FROM articulosCSV 
            WHERE Marca IS NOT NULL AND Marca != '' 
            ORDER BY Marca
        """)
        marcas = [row[0] for row in cursor.fetchall()]
        return jsonify({"marcas": marcas})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        
@app.route('/api/calibres')
def obtener_calibres():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT Calibre 
            FROM articulosCSV 
            WHERE Calibre IS NOT NULL AND Calibre != '' 
            ORDER BY Calibre
        """)
        calibres = [row[0] for row in cursor.fetchall()]
        return jsonify({"calibres": calibres})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/dashboard/pedido/<int:pedido_id>')
def detalle_pedido(pedido_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM pedidos_mercaderia WHERE id = %s", (pedido_id,))
    pedido = cursor.fetchone()

    cursor.execute("""
        SELECT articulo_id, descripcion, cantidad
        FROM detalle_pedido_mercaderia
        WHERE pedido_id = %s
    """, (pedido_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('pedido_detalle.html', pedido=pedido, items=items)


@app.route('/dashboard/pedido/<int:pedido_id>/estado', methods=['POST'])
def cambiar_estado_pedido(pedido_id):
    if 'admin' not in session:
        return redirect(url_for('login'))

    nuevo_estado = request.form.get('estado')
    if nuevo_estado not in ['pendiente', 'procesando', 'completado', 'cancelado']:
        flash('Estado inválido', 'danger')
        return redirect(url_for('admin_pedidos'))

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE pedidos_mercaderia SET estado = %s WHERE id = %s", (nuevo_estado, pedido_id))
    conn.commit()
    cursor.close()
    conn.close()

    flash(f'Pedido #{pedido_id} actualizado a "{nuevo_estado}"', 'success')
    return redirect(url_for('admin_pedidos'))

@app.route('/dashboard/pedidos')
@login_required
def admin_pedidos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.id, p.dni, c.nombre, p.sucursal_id, p.fecha, p.estado
        FROM pedidos_mercaderia p
        LEFT JOIN choferes c ON p.dni = c.dni
        ORDER BY p.fecha DESC
    """)
    pedidos = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('pedidos_admin.html', pedidos=pedidos)
           
@app.route('/api/historial_pedidos/<dni>', methods=['GET'])
def historial_pedidos(dni):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
             SELECT p.id, p.dni, p.fecha, p.estado, p.sucursal_id, p.observaciones, c.nombre
             FROM pedidos_mercaderia p
             LEFT JOIN choferes c ON p.dni = c.dni
             WHERE p.dni = %s
             ORDER BY p.fecha DESC
             """, (dni,))
        pedidos = cursor.fetchall()

        for pedido in pedidos:
            cursor.execute("""
             SELECT articulo_id, descripcion, cantidad
             FROM detalle_pedido_mercaderia
             WHERE pedido_id = %s
             """, (pedido['id'],))
            pedido['items'] = cursor.fetchall()

        return jsonify(pedidos)
    finally:
        cursor.close()
        conn.close()   
#///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#
@app.route('/admin/reuniones')
def admin_reuniones():
    if 'admin' not in session:
        return redirect(url_for('login_admin'))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM reuniones WHERE activa = TRUE ORDER BY id DESC")
        reuniones = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_reuniones.html', reuniones=reuniones)        


#NUEVA REUNION
@app.route("/admin/reuniones/nueva", methods=["GET", "POST"])
def nueva_reunion_admin():
    if request.method == "POST":
        try:
            titulo = request.form["titulo"]
            frecuencia = request.form["frecuencia"]
            dia_semana = int(request.form["dia_semana"])
            hora = request.form["hora"]
            latitud = float(request.form["latitud"])
            longitud = float(request.form["longitud"])

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO reuniones (titulo, frecuencia, dia_semana, hora, latitud, longitud)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (titulo, frecuencia, dia_semana, hora, latitud, longitud))
            conn.commit()
            reunion_id = cursor.lastrowid

            qr_url = f"https://tusitio.com/asistencia_qr/{reunion_id}"
            qr_filename_base = f"reunion_{reunion_id}"
            ruta_relativa, _ = generar_qr(qr_url, qr_filename_base)

            cursor.execute("UPDATE reuniones SET qr_code = %s WHERE id = %s", (ruta_relativa, reunion_id))
            conn.commit()
            cursor.close()
            conn.close()

            return redirect(url_for('admin_reuniones'))

        except Exception as e:
            return f"❌ Error al procesar el formulario: {e}"

    return render_template("admin_reunion_nueva.html")


#MARCAR ASISTENCIA

# REGISTRAR ASISTENCIA CON VALIDACION DE HORA, FECHA Y UBICACION DINAMICA
@app.route('/api/marcar_asistencia', methods=['POST'])
def marcar_asistencia():
    data = request.get_json()

    dni = data.get('dni')
    reunion_id = data.get('reunion_id')
    lat_raw = data.get('lat')
    lon_raw = data.get('lon')

    if dni is None or reunion_id is None or lat_raw is None or lon_raw is None:
        return jsonify({"error": "❌ Faltan datos obligatorios: dni, reunion_id, lat, lon"}), 400

    try:
        lat = float(lat_raw)
        lon = float(lon_raw)
    except ValueError:
        return jsonify({"error": "❌ Coordenadas inválidas"}), 400

    ventana_tolerancia = timedelta(minutes=TOLERANCIA_MINUTOS_REUNION)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT dia_semana, hora, latitud, longitud
        FROM reuniones
        WHERE id = %s AND activa = TRUE
    """, (reunion_id,))
    row = cursor.fetchone()

    if not row:
        cursor.close(); conn.close()
        return jsonify({"error": "❌ Reunión no encontrada o inactiva"}), 404

    dia_semana, hora_reunion, latitud_db, longitud_db = row

    if latitud_db is None or longitud_db is None:
        cursor.close(); conn.close()
        return jsonify({"error": "📍 La reunión no tiene ubicación configurada"}), 400

    ahora = datetime.now()

    # ✅ Validar día
    if ahora.weekday() != dia_semana:
        mensaje = f"📅 Día incorrecto: hoy={ahora.weekday()} esperado={dia_semana}"
        print(mensaje)
        logger.warning(mensaje)
        cursor.close(); conn.close()
        return jsonify({"error": mensaje}), 403

    # ✅ Validar horario
    hora_reunion_dt = datetime.combine(
        ahora.date(),
        datetime.strptime(str(hora_reunion), "%H:%M:%S").time()
    )
    dentro_de_horario = (hora_reunion_dt - ventana_tolerancia <= ahora <= hora_reunion_dt + ventana_tolerancia)
    if not dentro_de_horario:
        mensaje = f"⏰ Fuera del horario permitido. Ahora={ahora.time()}, reunión={hora_reunion}, tolerancia=±{TOLERANCIA_MINUTOS_REUNION}min"
        print(mensaje)
        logger.warning(mensaje)
        cursor.close(); conn.close()
        return jsonify({"error": mensaje}), 403

    # ✅ Validar ubicación
    distancia = geodesic((lat, lon), (latitud_db, longitud_db)).meters
    mensaje_geo = (
        f"📍 Ubicación usuario: ({lat}, {lon})\n"
        f"📍 Ubicación reunión: ({latitud_db}, {longitud_db})\n"
        f"📏 Distancia: {distancia:.2f} m / Permitido: {RADIO_VALIDACION_METROS} m"
    )
    print(mensaje_geo)
    logger.info(mensaje_geo)

    if distancia > RADIO_VALIDACION_METROS:
        mensaje = f"📍 Fuera del rango permitido: distancia={distancia:.1f}m"
        print(mensaje)
        logger.warning(mensaje)
        cursor.close(); conn.close()
        return jsonify({"error": mensaje}), 403

    # Validar asistencia previa
    fecha_actual = ahora.date()
    cursor.execute("""
        SELECT id FROM asistencias_reuniones
        WHERE id_reunion = %s AND dni_chofer = %s AND fecha = %s
    """, (reunion_id, dni, fecha_actual))
    if cursor.fetchone():
        cursor.close(); conn.close()
        return jsonify({"error": "✅ Ya registraste tu asistencia"}), 409

    # Registrar asistencia
    cursor.execute("""
        INSERT INTO asistencias_reuniones 
        (id_reunion, dni_chofer, fecha, hora_entrada, latitud, longitud, asistencia)
        VALUES (%s, %s, %s, %s, %s, %s, TRUE)
    """, (reunion_id, dni, fecha_actual, ahora.time(), lat, lon))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({"mensaje": "🟢 Asistencia registrada correctamente"}), 200



#EDITAR REUNION
@app.route("/admin/reuniones/<int:id>/editar", methods=["GET", "POST"])
def editar_reunion_admin(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM reuniones WHERE id = %s", (id,))
    reunion = cursor.fetchone()

    if reunion and isinstance(reunion["hora"], timedelta):
        reunion["hora"] = (datetime.min + reunion["hora"]).time()

    if request.method == "POST":
        titulo = request.form["titulo"]
        frecuencia = request.form["frecuencia"]
        dia_semana = int(request.form["dia_semana"])
        hora = request.form["hora"]
        latitud = float(request.form["latitud"])
        longitud = float(request.form["longitud"])

        cursor.execute("""
            UPDATE reuniones 
            SET titulo = %s, frecuencia = %s, dia_semana = %s, hora = %s,
                latitud = %s, longitud = %s
            WHERE id = %s
        """, (titulo, frecuencia, dia_semana, hora, latitud, longitud, id))
        conn.commit()

        cursor.close()
        conn.close()
        return redirect(url_for("admin_reuniones"))

    cursor.close()
    conn.close()
    return render_template("admin_reunion_editar.html", reunion=reunion)

#BORRAR REUNION
from datetime import datetime, timedelta

@app.route("/admin/reuniones/<int:id>/eliminar", methods=["GET", "POST"])
def eliminar_reunion_admin(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM reuniones WHERE id = %s", (id,))
    reunion = cursor.fetchone()
    cursor.close()
    conn.close()

    # 🛠️ Solución: convertir hora de timedelta a objeto time
    if isinstance(reunion["hora"], timedelta):
        reunion["hora"] = (datetime.min + reunion["hora"]).time()

    if request.method == "POST":
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM reuniones WHERE id = %s", (id,))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect(url_for("admin_reuniones"))

    return render_template("admin_reunion_eliminar.html", reunion=reunion)


@app.route("/admin/reuniones/<int:id_reunion>/regenerar_qr", methods=["GET"])
def regenerar_qr_reunion(id_reunion):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM reuniones WHERE id = %s", (id_reunion,))
        reunion = cursor.fetchone()
        cursor.close()
        conn.close()

        if not reunion:
            flash("⚠️ Reunión no encontrada", "danger")
            return redirect(url_for("listar_reuniones_admin"))

        data = f"REUNION:{id_reunion}|{reunion['titulo']}|{reunion['frecuencia']}|{reunion['dia_semana']}|{reunion['hora']}"
        nombre_archivo = f"reunion_{id_reunion}"
        generar_qr(data, nombre_archivo)  # ✅ sin path ni extensión

        flash("✅ QR regenerado correctamente", "success")
        return redirect(url_for("admin_reuniones"))

    except Exception as e:
        return f"❌ Error al regenerar QR: {e}"


@app.route("/admin/reuniones/<int:id_reunion>/asignaciones/nuevo", methods=["GET"])
def agregar_asignacion(id_reunion):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Obtener info de la reunión
    cursor.execute("SELECT * FROM reuniones WHERE id = %s", (id_reunion,))
    reunion = cursor.fetchone()

    # Obtener choferes que NO estén asignados aún a esta reunión
    cursor.execute("""
        SELECT c.dni, c.nombre, c.sector
        FROM choferes c
        WHERE c.dni NOT IN (
            SELECT dni_chofer FROM asignaciones_reuniones WHERE id_reunion = %s
        )
    """, (id_reunion,))
    choferes_disponibles = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template("asignaciones_nuevo.html", reunion=reunion, choferes=choferes_disponibles)

@app.route("/admin/reuniones/<int:id_reunion>/asignar", methods=["POST"])
def guardar_asignacion(id_reunion):
    try:
        dni_chofer = request.form["dni_chofer"]

        conn = get_connection()
        cursor = conn.cursor()

        # Verificar si ya está asignado para evitar duplicados
        cursor.execute("""
            SELECT COUNT(*) FROM asignaciones_reuniones 
            WHERE id_reunion = %s AND dni_chofer = %s
        """, (id_reunion, dni_chofer))
        ya_asignado = cursor.fetchone()[0]

        if ya_asignado:
            flash("⚠️ El chofer ya está asignado a esta reunión.", "warning")
        else:
            cursor.execute("""
                INSERT INTO asignaciones_reuniones (id_reunion, dni_chofer)
                VALUES (%s, %s)
            """, (id_reunion, dni_chofer))
            conn.commit()
            flash("✅ Chofer asignado correctamente.", "success")

        cursor.close()
        conn.close()
        return redirect(url_for("ver_asignaciones_reunion", id_reunion=id_reunion))

    except Exception as e:
        return f"❌ Error al guardar la asignación: {e}"

@app.route("/admin/reuniones/<int:id_reunion>/asignaciones")
def ver_asignaciones_reunion(id_reunion):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Obtener datos de la reunión
        cursor.execute("SELECT * FROM reuniones WHERE id = %s", (id_reunion,))
        reunion = cursor.fetchone()

        if not reunion:
            flash("⚠️ Reunión no encontrada", "danger")
            return redirect(url_for("listar_reuniones_admin"))

        # Obtener asignaciones con datos del chofer
        cursor.execute("""
            SELECT ar.id, c.dni, c.nombre, c.sector
            FROM asignaciones_reuniones ar
            JOIN choferes c ON ar.dni_chofer = c.dni
            WHERE ar.id_reunion = %s
        """, (id_reunion,))
        asignaciones = cursor.fetchall()

        cursor.close()
        conn.close()

        return render_template("ver_asignaciones_reunion.html", reunion=reunion, asignaciones=asignaciones)

    except Exception as e:
        return f"❌ Error al listar asignaciones: {e}"
    
@app.route("/admin/reuniones/<int:id_reunion>/asignaciones/<int:id_asignacion>/eliminar", methods=["POST"])
def eliminar_asignacion(id_reunion, id_asignacion):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Eliminar la asignación
        cursor.execute("DELETE FROM asignaciones_reuniones WHERE id = %s", (id_asignacion,))
        conn.commit()

        cursor.close()
        conn.close()

        flash("✅ Asignación eliminada correctamente", "success")
        return redirect(url_for('ver_asignaciones_reunion', id_reunion=id_reunion))

    except Exception as e:
        return f"❌ Error al eliminar asignación: {e}"

def obtener_reunion(id_reunion):
    conexion = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conexion.cursor(dictionary=True)
    cursor.execute("SELECT * FROM reuniones WHERE id = %s", (id_reunion,))
    reunion = cursor.fetchone()
    conexion.close()
    return reunion

def obtener_asignaciones(id_reunion):
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, id_reunion, dni_chofer, obligatorio
            FROM asignaciones_reuniones
            WHERE id_reunion = %s
        """, (id_reunion,))

        asignaciones = []
        for row in cursor.fetchall():
            asignaciones.append({
                'id': row[0],
                'id_reunion': row[1],
                'dni_chofer': row[2],
                'obligatorio': bool(row[3]),
            })

        return asignaciones

    except mysql.connector.Error as err:
        print(f"Error al obtener asignaciones: {err}")
        return []

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    
@app.route('/admin/reuniones/<int:id_reunion>/asignaciones_parcial')
def ver_asignaciones_parcial(id_reunion):
    reunion = obtener_reunion(id_reunion)
    asignaciones = obtener_asignaciones(id_reunion)
    return render_template('fragmento_asignaciones.html',
                           reunion=reunion,
                           asignaciones=asignaciones)

@app.route("/admin/reuniones/<int:id_reunion>/asignaciones/<int:id_asignacion>/editar", methods=["GET", "POST"])
def editar_asignacion(id_reunion, id_asignacion):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT ar.id, ar.dni_chofer, ar.obligatorio, c.nombre, c.sector
        FROM asignaciones_reuniones ar
        JOIN choferes c ON ar.dni_chofer = c.dni
        WHERE ar.id = %s
    """, (id_asignacion,))
    asignacion = cursor.fetchone()

    cursor.execute("SELECT * FROM reuniones WHERE id = %s", (id_reunion,))
    reunion = cursor.fetchone()

    if request.method == "POST":
        obligatorio = int(request.form.get("obligatorio", 0))
        cursor.execute("UPDATE asignaciones_reuniones SET obligatorio = %s WHERE id = %s", (obligatorio, id_asignacion))
        conn.commit()
        cursor.close()
        conn.close()
        flash("✅ Asignación actualizada", "success")
        return redirect(url_for("ver_asignaciones_reunion", id_reunion=id_reunion))

    cursor.close()
    conn.close()
    return render_template("asignaciones_editar.html", reunion=reunion, asignacion=asignacion)


@app.route("/admin/asignaciones/<int:id_asignacion>/toggle_obligatorio")
def toggle_obligatorio(id_asignacion):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT obligatorio, id_reunion FROM asignaciones_reuniones WHERE id = %s", (id_asignacion,))
    asignacion = cursor.fetchone()

    if not asignacion:
        flash("Asignación no encontrada", "danger")
        return redirect(url_for("reuniones_admin"))

    nuevo_estado = 0 if asignacion["obligatorio"] else 1
    cursor.execute(
        "UPDATE asignaciones_reuniones SET obligatorio = %s WHERE id = %s",
        (nuevo_estado, id_asignacion)
    )
    conn.commit()

    reunion_id = asignacion["id_reunion"]

    cursor.close()
    conn.close()

    flash("Estado de obligatoriedad actualizado", "success")
    return redirect(url_for("reuniones_admin", _anchor=f"asignaciones-reunion-{reunion_id}"))

def obtener_asignaciones(id_reunion):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT ar.id, ar.dni_chofer, ar.obligatorio,
               c.nombre, c.sector
        FROM asignaciones_reuniones ar
        JOIN choferes c ON ar.dni_chofer = c.dni
        WHERE ar.id_reunion = %s
    """, (id_reunion,))

    asignaciones = cursor.fetchall()
    cursor.close()
    conn.close()
    return asignaciones

def obtener_reuniones_con_asignaciones():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT r.*, COUNT(ar.id) AS cantidad_asignados
        FROM reuniones r
        LEFT JOIN asignaciones_reuniones ar ON r.id = ar.id_reunion
        GROUP BY r.id
        ORDER BY r.id DESC
    """)
    reuniones = cursor.fetchall()
    cursor.close()
    conn.close()
    return reuniones



@app.route("/admin/asignaciones")
def asignaciones_global():
    sector = request.args.get("sector")
    reunion_id = request.args.get("reunion_id")
    exportar = request.args.get("exportar")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT ar.id, ar.dni_chofer, ar.obligatorio, 
               c.nombre, c.sector, r.titulo AS reunion
        FROM asignaciones_reuniones ar
        JOIN choferes c ON ar.dni_chofer = c.dni
        LEFT JOIN reuniones r ON ar.id_reunion = r.id
        WHERE 1=1
    """
    params = []

    if sector:
        query += " AND c.sector = %s"
        params.append(sector)

    if reunion_id:
        query += " AND r.id = %s"
        params.append(reunion_id)

    query += " ORDER BY ar.id DESC"
    cursor.execute(query, tuple(params))
    asignaciones = cursor.fetchall()

    # Si el usuario solicitó exportar
    if exportar == "excel":
       
        from io import BytesIO

        df = pd.DataFrame(asignaciones)
        df.rename(columns={
            "dni_chofer": "DNI",
            "nombre": "Nombre",
            "sector": "Sector",
            "reunion": "Reunión",
            "obligatorio": "Obligatoria"
        }, inplace=True)

        # Convertir booleanos a texto
        df["Obligatoria"] = df["Obligatoria"].map({1: "Sí", 0: "No"})

        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Asignaciones")
        output.seek(0)
        return send_file(output, download_name="asignaciones_globales.xlsx", as_attachment=True)

    # Selects de filtros
    cursor.execute("SELECT DISTINCT sector FROM choferes")
    sectores = [row["sector"] for row in cursor.fetchall()]

    cursor.execute("SELECT id, titulo FROM reuniones WHERE activa = TRUE")
    reuniones = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "asignaciones_global.html",
        asignaciones=asignaciones,
        sectores=sectores,
        reuniones=reuniones,
        filtro_sector=sector,
        filtro_reunion=reunion_id,
    )

from utils import db_cursor
@app.route("/admin/asignaciones/nueva", methods=["GET", "POST"])
def asignacion_nueva():
    next_view = None
    with db_cursor() as (conn, cursor):
        if request.method == "POST":
            dni = request.form["dni"]
            reunion_id = request.form["reunion_id"]
            obligatorio = int("obligatorio" in request.form)

            cursor.execute("""
                SELECT id FROM asignaciones_reuniones 
                WHERE dni_chofer = %s AND id_reunion = %s
            """, (dni, reunion_id))
            existente = cursor.fetchone()

            if existente:
                flash("⚠️ Ya existe esta asignación", "warning")
                next_view = "asignacion_nueva"

            else:
                cursor.execute("""
                    INSERT INTO asignaciones_reuniones (dni_chofer, id_reunion, obligatorio)
                    VALUES (%s, %s, %s)
                """, (dni, reunion_id, obligatorio))
                flash("✅ Asignación creada correctamente", "success")
                next_view = "asignaciones_global"

        cursor.execute("SELECT dni, nombre, sector FROM choferes")
        choferes = cursor.fetchall()

        cursor.execute("SELECT id, titulo FROM reuniones WHERE activa = TRUE")
        reuniones = cursor.fetchall()

    if next_view:
        return redirect(url_for(next_view))

    return render_template("asignaciones_nuevo.html", choferes=choferes, reuniones=reuniones)



@app.route('/api/reuniones/<dni>', methods=['GET'])
def reuniones_por_dni(dni):
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT r.id, r.titulo, r.frecuencia, r.dia_semana, r.hora, r.qr_code
        FROM reuniones r
        JOIN asignaciones_reuniones a ON r.id = a.id_reunion
        WHERE a.dni_chofer = %s AND r.activa = 1
        ORDER BY r.id DESC;
    """
    cursor.execute(query, (dni,))
    reuniones = cursor.fetchall()
    cursor.close()
    conn.close()

    def calcular_proxima_fecha(frecuencia, dia_semana):
        hoy = datetime.now().date()

        if frecuencia == 'diaria':
            return hoy.strftime('%Y-%m-%d')

        elif frecuencia == 'semanal':
            dias_a_sumar = (dia_semana - hoy.weekday() + 7) % 7
            if dias_a_sumar == 0:
                dias_a_sumar = 7
            proxima = hoy + timedelta(days=dias_a_sumar)
            return proxima.strftime('%Y-%m-%d')

        elif frecuencia == 'mensual':
            hoy_dt = datetime.now()
            dia_objetivo = dia_semana
            try:
                proxima = hoy_dt.replace(day=dia_objetivo)
                if proxima.date() <= hoy_dt.date():
                    if hoy_dt.month == 12:
                        proxima = proxima.replace(year=hoy_dt.year + 1, month=1)
                    else:
                        proxima = proxima.replace(month=hoy_dt.month + 1)
            except ValueError:
                proxima = hoy_dt.replace(day=28)
            return proxima.strftime('%Y-%m-%d')

        return None

    for r in reuniones:
        # Manejo seguro de hora
        if isinstance(r["hora"], timedelta):
            total_seconds = int(r["hora"].total_seconds())
            horas = total_seconds // 3600
            minutos = (total_seconds % 3600) // 60
            r["hora"] = f"{horas:02d}:{minutos:02d}"
        else:
            r["hora"] = str(r["hora"])

        r["proxima_fecha"] = calcular_proxima_fecha(r["frecuencia"], r["dia_semana"])

    return jsonify(reuniones)

#probamos reuniones

@app.route("/admin/asignaciones/<int:id_asignacion>/editar", methods=["GET", "POST"])
def asignacion_editar(id_asignacion):
    with db_cursor() as (conn, cursor):
        if request.method == "POST":
            nuevo_dni = request.form["dni"]
            nuevo_reunion_id = request.form["reunion_id"]
            nuevo_obligatorio = int("obligatorio" in request.form)

            # Verificar si ya existe esa combinación (excepto para la actual)
            cursor.execute("""
                SELECT id FROM asignaciones_reuniones 
                WHERE dni_chofer = %s AND id_reunion = %s AND id != %s
            """, (nuevo_dni, nuevo_reunion_id, id_asignacion))
            duplicado = cursor.fetchone()

            if duplicado:
                flash("⚠️ Ya existe otra asignación con ese chofer y reunión", "warning")
                return redirect(url_for("asignacion_editar", id_asignacion=id_asignacion))

            cursor.execute("""
                UPDATE asignaciones_reuniones 
                SET dni_chofer = %s, id_reunion = %s, obligatorio = %s 
                WHERE id = %s
            """, (nuevo_dni, nuevo_reunion_id, nuevo_obligatorio, id_asignacion))

            flash("✅ Asignación actualizada correctamente", "success")
            return redirect(url_for("asignaciones_global"))

        # GET: Cargar datos para edición
        cursor.execute("SELECT * FROM asignaciones_reuniones WHERE id = %s", (id_asignacion,))
        asignacion = cursor.fetchone()

        cursor.execute("SELECT dni, nombre, sector FROM choferes")
        choferes = cursor.fetchall()

        cursor.execute("SELECT id, titulo FROM reuniones WHERE activa = TRUE")
        reuniones = cursor.fetchall()

    return render_template(
        "asignaciones_editar.html",
        asignacion=asignacion,
        choferes=choferes,
        reuniones=reuniones
    )

@app.route("/admin/gastos")
def admin_gastos():
    return render_template("gastos/gastos_list.html")

@app.route("/admin/ordenes")
def admin_ordenes():
    return render_template("gastos/gastos_list.html")
@app.route('/indicadores/eliminar/<int:id>', methods=['POST', 'GET'])
@login_required
def eliminar_indicador(id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM indicadores WHERE id = %s", (id,))
        mysql.connection.commit()
        flash("Indicador eliminado correctamente", "success")
    except Exception as e:
        flash(f"Error al eliminar indicador: {e}", "danger")
    finally:
        cur.close()
    return redirect(url_for('admin_indicadores'))


# ---------------CRUD RUBROS ------------------#
@app.route("/admin/rubros")
@login_required
def admin_rubros():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM rubros ORDER BY id DESC")
    rubros = cursor.fetchall()
    cursor.close(); conn.close()
    return render_template("rubros/rubros_list.html", rubros=rubros)
# ─────────────── GET todos ──────────────
@app.route('/api/rubros', methods=['GET'])
def get_rubros():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM rubros")
    rubros = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(rubros)

# ─────────────── GET por ID ───────────────
@app.route('/api/rubros/<int:id>', methods=['GET'])
def get_rubro(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM rubros WHERE id = %s", (id,))
    rubro = cursor.fetchone()
    cursor.close(); conn.close()
    return jsonify(rubro) if rubro else ('', 404)

# ─────────────── POST crear ───────────────
@app.route('/api/rubros', methods=['POST'])
def create_rubro():
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO rubros (nombre, descripcion) VALUES (%s, %s)", 
                   (data['nombre'], data.get('descripcion')))
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'message': 'Rubro creado correctamente'}), 201

# ─────────────── PUT actualizar ───────────────
@app.route('/api/rubros/<int:id>', methods=['PUT'])
def update_rubro(id):
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE rubros 
        SET nombre = %s, descripcion = %s 
        WHERE id = %s
    """, (data['nombre'], data.get('descripcion'), id))
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'message': 'Rubro actualizado correctamente'})

# ─────────────── DELETE eliminar ───────────────
@app.route('/api/rubros/<int:id>', methods=['DELETE'])
def delete_rubro(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rubros WHERE id = %s", (id,))
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'message': 'Rubro eliminado correctamente'})

# -----------------------------
# CRUD Proveedores (API REST)
# -----------------------------

# ✅ Listar todos los proveedores con JOIN a rubros
@app.route('/api/proveedores', methods=['GET'])
def get_proveedores():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.id, p.nombre, p.cuit, p.localidad, p.provincia, p.direccion,
               p.telefono, p.atencion_por, p.nivel_servicio,
               r.id AS rubro_id, r.nombre AS rubro_nombre
        FROM proveedores p
        LEFT JOIN rubros r ON p.rubro_id = r.id
        ORDER BY p.nombre
    """)
    proveedores = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(proveedores)


# ✅ Obtener un proveedor por ID
@app.route('/api/proveedores/<int:id>', methods=['GET'])
def get_proveedor(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.id, p.nombre, p.cuit, p.localidad, p.provincia, p.direccion,
               p.telefono, p.atencion_por, p.nivel_servicio,
               r.id AS rubro_id, r.nombre AS rubro_nombre
        FROM proveedores p
        LEFT JOIN rubros r ON p.rubro_id = r.id
        WHERE p.id = %s
    """, (id,))
    proveedor = cursor.fetchone()
    cursor.close(); conn.close()
    return jsonify(proveedor) if proveedor else ('', 404)


# ✅ Crear proveedor
@app.route('/api/proveedores', methods=['POST'])
def create_proveedor():
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO proveedores
        (nombre, cuit, rubro_id, localidad, provincia, direccion, telefono, atencion_por, nivel_servicio)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        data['nombre'], data.get('cuit'), data.get('rubro_id'),
        data.get('localidad'), data.get('provincia'), data.get('direccion'),
        data.get('telefono'), data.get('atencion_por'),
        data.get('nivel_servicio', 0.00)
    ))
    conn.commit()
    new_id = cursor.lastrowid
    cursor.close(); conn.close()
    return jsonify({'message': 'Proveedor creado correctamente', 'id': new_id}), 201


# ✅ Actualizar proveedor
@app.route('/api/proveedores/<int:id>', methods=['PUT'])
def update_proveedor(id):
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE proveedores
        SET nombre=%s, cuit=%s, rubro_id=%s, localidad=%s, provincia=%s,
            direccion=%s, telefono=%s, atencion_por=%s, nivel_servicio=%s
        WHERE id=%s
    """, (
        data['nombre'], data.get('cuit'), data.get('rubro_id'),
        data.get('localidad'), data.get('provincia'), data.get('direccion'),
        data.get('telefono'), data.get('atencion_por'),
        data.get('nivel_servicio', 0.00), id
    ))
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'message': 'Proveedor actualizado correctamente'})


# ✅ Eliminar proveedor
@app.route('/api/proveedores/<int:id>', methods=['DELETE'])
def delete_proveedor(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM proveedores WHERE id=%s", (id,))
    conn.commit()
    cursor.close(); conn.close()
    return jsonify({'message': 'Proveedor eliminado correctamente'})

from flask import render_template, request, redirect, url_for, flash
from contextlib import closing

# 🔹 Utilidad para obtener rubros
def get_rubros():
    conn = get_connection()
    with closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM rubros ORDER BY nombre")
        rubros = cursor.fetchall()
    conn.close()
    return rubros


from flask import render_template, request, redirect, url_for, flash
from contextlib import closing

# ============================
#   LISTAR PROVEEDORES
# ============================
@app.route("/admin/proveedores")
def admin_proveedores():
    conn = get_connection()
    with closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("""
            SELECT p.id, p.nombre, p.cuit, p.localidad, p.provincia, p.direccion,
                   p.telefono, p.email, p.sitio_web, p.codigo_postal,
                   p.atencion_por, p.nivel_servicio, p.observaciones, p.activo,
                   r.nombre AS rubro_nombre
            FROM proveedores p
            LEFT JOIN rubros r ON p.rubro_id = r.id
            ORDER BY p.nombre
        """)
        proveedores = cursor.fetchall()
    conn.close()
    return render_template("proveedores/proveedores_list.html", proveedores=proveedores)


# ============================
#   CREAR PROVEEDOR
# ============================
@app.route("/admin/proveedores/new", methods=["GET", "POST"])
def create_proveedor_form():
    if request.method == "POST":
        data = request.form
        try:
            conn = get_connection()
            with closing(conn.cursor()) as cursor:
                cursor.execute("""
                    INSERT INTO proveedores
                        (nombre, cuit, rubro_id, localidad, provincia, direccion, telefono,
                         email, sitio_web, codigo_postal, atencion_por, nivel_servicio,
                         observaciones, activo)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    data.get("nombre"), data.get("cuit"), data.get("rubro_id"),
                    data.get("localidad"), data.get("provincia"), data.get("direccion"),
                    data.get("telefono"), data.get("email"), data.get("sitio_web"),
                    data.get("codigo_postal"), data.get("atencion_por"),
                    data.get("nivel_servicio", 0.00),
                    data.get("observaciones"),
                    1 if data.get("activo") else 0
                ))
                conn.commit()
            flash("✅ Proveedor creado correctamente", "success")
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al crear proveedor: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for("admin_proveedores"))

    rubros = get_rubros()
    return render_template("proveedores/proveedores_new.html", rubros=rubros)


# ============================
#   EDITAR PROVEEDOR
# ============================
@app.route("/admin/proveedores/<int:id>/edit", methods=["GET", "POST"])
def update_proveedor_form(id):
    conn = get_connection()
    if request.method == "POST":
        data = request.form
        try:
            with closing(conn.cursor()) as cursor:
                cursor.execute("""
                    UPDATE proveedores
                    SET nombre=%s, cuit=%s, rubro_id=%s, localidad=%s, provincia=%s,
                        direccion=%s, telefono=%s, email=%s, sitio_web=%s, codigo_postal=%s,
                        atencion_por=%s, nivel_servicio=%s, observaciones=%s, activo=%s
                    WHERE id=%s
                """, (
                    data.get("nombre"), data.get("cuit"), data.get("rubro_id"),
                    data.get("localidad"), data.get("provincia"), data.get("direccion"),
                    data.get("telefono"), data.get("email"), data.get("sitio_web"),
                    data.get("codigo_postal"), data.get("atencion_por"),
                    data.get("nivel_servicio", 0.00),
                    data.get("observaciones"),
                    1 if data.get("activo") else 0,
                    id
                ))
                conn.commit()
            flash("✅ Proveedor actualizado correctamente", "success")
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al actualizar proveedor: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for("admin_proveedores"))

    with closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM proveedores WHERE id=%s", (id,))
        proveedor = cursor.fetchone()
    conn.close()

    if not proveedor:
        flash("⚠️ Proveedor no encontrado", "warning")
        return redirect(url_for("admin_proveedores"))

    rubros = get_rubros()
    return render_template("proveedores/proveedores_edit.html", proveedor=proveedor, rubros=rubros)


# ============================
#   ELIMINAR PROVEEDOR
# ============================
@app.route("/admin/proveedores/<int:id>/delete", methods=["GET", "POST"])
def delete_proveedor_form(id):
    conn = get_connection()
    if request.method == "POST":
        try:
            with closing(conn.cursor()) as cursor:
                cursor.execute("DELETE FROM proveedores WHERE id=%s", (id,))
                conn.commit()
            flash("✅ Proveedor eliminado correctamente", "success")
        except Exception as e:
            conn.rollback()
            flash(f"❌ Error al eliminar proveedor: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for("admin_proveedores"))

    with closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM proveedores WHERE id=%s", (id,))
        proveedor = cursor.fetchone()
    conn.close()

    if not proveedor:
        flash("⚠️ Proveedor no encontrado", "warning")
        return redirect(url_for("admin_proveedores"))

    return render_template("proveedores/proveedores_delete.html", proveedor=proveedor)



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
    