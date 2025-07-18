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
    return mysql.connector.connect(**MYSQL_CONFIG)

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
        dni = request.form['dni'].strip()
        mensaje = request.form['mensaje'].strip()

        if not dni or not mensaje:
            flash("❌ Todos los campos son obligatorios", "danger")

        elif not dni.isdigit() or not (7 <= len(dni) <= 8):
            flash("⚠️ El DNI debe tener entre 7 y 8 dígitos numéricos", "warning")

        else:
            try:
                conn = get_connection()
                cursor = conn.cursor()

                # Insertar el aviso
                cursor.execute("INSERT INTO avisos (dni, mensaje) VALUES (%s, %s)", (dni, mensaje))
                conn.commit()

                # Buscar el token
                cursor.execute("SELECT token FROM tokens WHERE dni = %s", (dni,))
                result = cursor.fetchone()

                if result and result[0]:
                    token = result[0]
                    enviar_push(token, "📢 Nuevo aviso", mensaje)

                flash("✅ Aviso enviado correctamente", "success")

            except Exception as e:
                flash(f"❌ Error al enviar aviso: {str(e)}", "danger")

            finally:
                cursor.close()
                conn.close()

    # Obtener últimos 10 avisos
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dni, mensaje, fecha FROM avisos ORDER BY fecha DESC LIMIT 10")
    avisos = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('panel.html', avisos=avisos)

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
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Obtener sucursales para dropdown
    cursor.execute("SELECT id, nombre FROM sucursales WHERE activa = TRUE")
    sucursales = cursor.fetchall()

    if request.method == 'POST':
        nombre = request.form['nombre']
        sector = request.form['sector']
        sucursal_id = request.form['sucursal_id']
        imagen = request.files['imagen']

        if imagen and imagen.filename:
            imagen_blob = redimensionar_imagen(imagen.read())
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
        cursor.close()
        conn.close()
        flash("✅ Datos del Empleado actualizados", "success")
        return redirect(url_for('listar_choferes'))

    # Cargar datos actuales del chofer
    cursor.execute("""
        SELECT nombre, sector, sucursal_id
        FROM choferes WHERE dni = %s
    """, (dni,))
    chofer = cursor.fetchone()
    cursor.close()
    conn.close()

    if not chofer:
        flash("❌ Empleado no encontrado", "danger")
        return redirect(url_for('listar_choferes'))

    return render_template('editar_chofer.html', dni=dni, nombre=chofer['nombre'],
                           sector=chofer['sector'], sucursal_id=chofer['sucursal_id'],
                           sucursales=sucursales)
    
    
@app.route('/admin/choferes/eliminar/<dni>', methods=['POST'])
@login_required
def eliminar_chofer(dni):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM choferes WHERE dni = %s", (dni,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("🗑️ Empleado eliminado", "warning")
    return redirect(url_for('listar_choferes'))

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

    # 1) Sectores verdaderos
    sectores, mapa_id_nombre = cargar_sectores(cursor)

    # 2) Indicadores (filtrados o no)
    if sector_id:
        cursor.execute("""
            SELECT i.*, %s AS sector_nombre
              FROM indicadores i
             WHERE i.sector_id = %s
        """, (mapa_id_nombre.get(sector_id, 'Desconocido'), sector_id))
    else:
        cursor.execute("SELECT *, NULL AS sector_nombre FROM indicadores")

    indicadores = cursor.fetchall()

    # 3) Añadir nombre si no se filtró
    if not sector_id:
        for ind in indicadores:
            ind['sector_nombre'] = mapa_id_nombre.get(ind['sector_id'], 'Desconocido')

    cursor.close(); conn.close()

    return render_template(
        "admin_indicadores.html",
        indicadores = indicadores,
        sectores    = sectores,   # ← lista real para el combo
        sector_id   = sector_id
    )
# ╰───────────────────────────────────────────────────────────╯



# ╭───────────────────────── ALTA ────────────────────────────╮
# Si NO usas Blueprint, cambia admin_bp por app
# admin_bp = Blueprint('admin', __name__, url_prefix='/admin')



@app.route('/admin/indicadores/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_indicador():
    sectores = obtener_sectores()
    form = {"nombre": "", "sector_id": "", "activo": "1"}

    if request.method == 'POST':
        form["nombre"]    = request.form['nombre'].strip().upper()
        form["sector_id"] = request.form['sector_id']
        form["activo"]    = request.form['activo']

        if not form["sector_id"]:
            flash("❌ Debe seleccionar un sector.", "danger")
            return render_template('nuevo_indicador.html',
                                   sectores=sectores, form=form)

        conn   = get_connection()
        cur    = conn.cursor()

        cur.execute("""
            SELECT 1 FROM indicadores
             WHERE LOWER(nombre)=%s AND sector_id=%s
        """, (form["nombre"].lower(), int(form["sector_id"])))
        if cur.fetchone():
            flash("❌ Ya existe un indicador con ese nombre en ese sector.", "danger")
        else:
            cur.execute("""
                INSERT INTO indicadores (nombre, sector_id, activo)
                VALUES (%s, %s, %s)
            """, (form["nombre"], int(form["sector_id"]), int(form["activo"])))
            conn.commit()
            flash("✅ Indicador creado correctamente.", "success")
            cur.close(); conn.close()
            return redirect(url_for('admin_indicadores'))   # ← aquí

        cur.close(); conn.close()

    return render_template('nuevo_indicador.html',
                           sectores=sectores, form=form)
# ╰───────────────────────────────────────────────────────────╯



# ╭───────────────────────── EDICIÓN ─────────────────────────╮
@app.route('/admin/indicadores/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_indicador(id):
    sectores = obtener_sectores()

    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        nombre     = request.form['nombre'].strip().upper()
        sector_id  = int(request.form['sector_id'])
        activo     = int(request.form['activo'])

        # Verificar duplicado (mismo nombre y sector, distinto id)
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
                   SET nombre = %s,
                       sector_id = %s,
                       activo = %s
                 WHERE id = %s
            """, (nombre, sector_id, activo, id))
            conn.commit()
            flash("✅ Indicador actualizado correctamente.", "success")
            cursor.close(); conn.close()
            return redirect(url_for('admin_indicadores'))

    # GET – cargar registro
    cursor.execute("SELECT * FROM indicadores WHERE id = %s", (id,))
    indicador = cursor.fetchone()
    cursor.close(); conn.close()

    if not indicador:
        flash("❌ Indicador no encontrado.", "danger")
        return redirect(url_for('admin_indicadores'))

    return render_template("editar_indicador.html",
                           indicador=indicador,
                           sectores =sectores)
# ╰───────────────────────────────────────────────────────────╯

# ─────────────────────────── TOGGLE indicador ──────────────────────────
#  Activa ⇆ Inactiva un indicador y vuelve a la lista conservando filtros
@app.route('/admin/indicadores/toggle/<int:id>', methods=['POST'])
@login_required
def toggle_indicador(id):
    conn   = get_connection()
    cursor = conn.cursor()

    # invertir el campo activo (0→1  /  1→0)
    cursor.execute("""
        UPDATE indicadores
           SET activo = NOT activo
         WHERE id = %s
    """, (id,))
    conn.commit()

    cursor.close(); conn.close()

    # redirige a la página de la que vino (mantiene ?sector_id=… si existía)
    return redirect(request.referrer or url_for('admin_indicadores'))

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
        return redirect(url_for('login'))

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

            conn = get_connection()
            cursor = conn.cursor()

            # Insertar la reunión
            cursor.execute("""
                INSERT INTO reuniones (titulo, frecuencia, dia_semana, hora)
                VALUES (%s, %s, %s, %s)
            """, (titulo, frecuencia, dia_semana, hora))
            conn.commit()

            reunion_id = cursor.lastrowid
            qr_url = f"https://tusitio.com/asistencia_qr/{reunion_id}"
            qr_filename_base = f"reunion_{reunion_id}"  # sin extensión

            # 🧠 Generar QR y obtener ruta relativa
            ruta_relativa, _ = generar_qr(qr_url, qr_filename_base)

            # Guardar solo la ruta relativa en la base (ej. 'qrcodes/reunion_13.png')
            cursor.execute("UPDATE reuniones SET qr_code = %s WHERE id = %s", (ruta_relativa, reunion_id))
            conn.commit()

            cursor.close()
            conn.close()

            return redirect(url_for('admin_reuniones'))

        except Exception as e:
            return f"❌ Error al procesar el formulario: {e}"

    return render_template("admin_reunion_nueva.html")

#MARCAR ASISTENCIA

@app.route('/api/marcar_asistencia', methods=['POST'])
def marcar_asistencia():
    data = request.get_json()
    reunion_id = data['reunion_id']
    dni = data['dni']
    lat = float(data['lat'])
    lon = float(data['lon'])

    RADIO_METROS = 50
    LAT_CENTRO = -36.778300
    LON_CENTRO = -58.941200
    ventana_tolerancia = timedelta(minutes=30)

    conn = get_connection()
    cursor = conn.cursor()

    # Buscar la reunión
    cursor.execute("""
        SELECT dia_semana, hora
        FROM reuniones
        WHERE id = %s AND activa = TRUE
    """, (reunion_id,))
    row = cursor.fetchone()

    if not row:
        cursor.close()
        conn.close()
        return jsonify({"error": "❌ Reunión no encontrada o inactiva"}), 404

    dia_semana, hora_reunion = row
    ahora = datetime.now()

    # Validar día de la semana
    if ahora.weekday() != dia_semana:
        cursor.close()
        conn.close()
        return jsonify({"error": "📅 No es el día programado para la reunión"}), 403

    # Validar hora con tolerancia
    hora_reunion_dt = datetime.combine(
        ahora.date(),
        datetime.strptime(str(hora_reunion), "%H:%M:%S").time()
    )
    if not (hora_reunion_dt - ventana_tolerancia <= ahora <= hora_reunion_dt + ventana_tolerancia):
        cursor.close()
        conn.close()
        return jsonify({"error": "⏰ Fuera del horario permitido"}), 403
    print("ventana_tolerancia =", ventana_tolerancia)
    print("hora_reunion_dt =", hora_reunion_dt)
    # Validar geolocalización
    distancia = geodesic((lat, lon), (LAT_CENTRO, LON_CENTRO)).meters
    if distancia > RADIO_METROS:
        cursor.close()
        conn.close()
        return jsonify({"error": f"📍 Ubicación fuera del predio autorizado ({distancia:.1f}m)"}), 403

    # Verificar si ya se marcó asistencia hoy
    fecha_actual = ahora.date()
    cursor.execute("""
        SELECT id FROM asistencias_reuniones
        WHERE id_reunion = %s AND dni_chofer = %s AND fecha = %s
    """, (reunion_id, dni, fecha_actual))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({"error": "✅ Ya registraste tu asistencia"}), 409

    # Registrar asistencia
    cursor.execute("""
        INSERT INTO asistencias_reuniones (id_reunion, dni_chofer, fecha, hora_entrada, latitud, longitud, asistencia)
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

    # ✅ Convertir timedelta a time para el template
    if reunion and isinstance(reunion["hora"], timedelta):
        reunion["hora"] = (datetime.min + reunion["hora"]).time()

    if request.method == "POST":
        titulo = request.form["titulo"]
        frecuencia = request.form["frecuencia"]
        dia_semana = int(request.form["dia_semana"])
        hora = request.form["hora"]

        cursor.execute("""
            UPDATE reuniones 
            SET titulo = %s, frecuencia = %s, dia_semana = %s, hora = %s 
            WHERE id = %s
        """, (titulo, frecuencia, dia_semana, hora, id))
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



@app.route("/admin/asignaciones/<int:id_asignacion>/editar", methods=["GET", "POST"])
def asignacion_editar(id_asignacion):
    next_view = None
    with db_cursor() as (conn, cursor):
        # Obtener la asignación
        cursor.execute("""
            SELECT ar.id, ar.dni_chofer, ar.id_reunion, ar.obligatorio
            FROM asignaciones_reuniones ar
            WHERE ar.id = %s
        """, (id_asignacion,))
        asignacion = cursor.fetchone()

        if not asignacion:
            flash("❌ Asignación no encontrada", "danger")
            next_view = "asignaciones_global"
        else:
            if request.method == "POST":
                dni = request.form["dni"]
                reunion_id = request.form["reunion_id"]
                obligatorio = int("obligatorio" in request.form)

                cursor.execute("""
                    SELECT id FROM asignaciones_reuniones
                    WHERE dni_chofer = %s AND id_reunion = %s AND id != %s
                """, (dni, reunion_id, id_asignacion))
                duplicado = cursor.fetchone()

                if duplicado:
                    flash("⚠️ Ya existe otra asignación con ese chofer y reunión.", "warning")
                    next_view = "asignacion_editar"
                else:
                    cursor.execute("""
                        UPDATE asignaciones_reuniones
                        SET dni_chofer = %s, id_reunion = %s, obligatorio = %s
                        WHERE id = %s
                    """, (dni, reunion_id, obligatorio, id_asignacion))
                    flash("✅ Asignación actualizada correctamente", "success")
                    next_view = "asignaciones_global"

        # Solo para mostrar el formulario si no se hizo POST con redirect
        cursor.execute("SELECT dni, nombre, sector FROM choferes")
        choferes = cursor.fetchall()

        cursor.execute("SELECT id, titulo FROM reuniones WHERE activa = TRUE")
        reuniones = cursor.fetchall()

    if next_view == "asignacion_editar":
        return redirect(url_for("asignacion_editar", id_asignacion=id_asignacion))
    elif next_view:
        return redirect(url_for(next_view))

    return render_template("asignaciones_editar.html",
                           asignacion=asignacion,
                           choferes=choferes,
                           reuniones=reuniones)



@app.route("/admin/asignaciones/<int:id_asignacion>/eliminar", methods=["POST"])
def asignacion_eliminar(id_asignacion):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM asignaciones_reuniones WHERE id = %s", (id_asignacion,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("🗑️ Asignación eliminada correctamente", "success")
    return redirect(url_for("asignaciones_global"))    

@app.route('/api/reuniones/<dni>', methods=['GET'])
def reuniones_por_dni(dni):
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT r.id, r.titulo, r.fecha, r.hora, r.tipo, r.qr_url
            FROM reuniones r
            JOIN asistencias_reuniones a ON r.id = a.id_reunion
            WHERE a.dni_chofer = %s AND r.activa = 1
            ORDER BY r.fecha DESC;
        """
        cursor.execute(query, (dni,))
        reuniones = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(reuniones)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
#probamos reuniones

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
    