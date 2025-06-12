from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, flash
from flask_cors import CORS
from datetime import timedelta
import mysql.connector
from config import MYSQL_CONFIG
import os
from dotenv import load_dotenv
from io import BytesIO
from functools import wraps
from datetime import datetime, timedelta
from datetime import date
from notificaciones import enviar_push
import re
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



load_dotenv()

app = Flask(__name__)
CORS(app)

app.secret_key = 'clave-super-secreta'
app.permanent_session_lifetime = timedelta(minutes=30)

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

@app.route('/dashboard')
@login_required
def dashboard():
    sector_id = request.args.get('sector_id', type=int, default=1)
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')

    # Si no hay fechas, usar últimos 7 días
    hoy = datetime.today().date()
    if not fecha_inicio or not fecha_fin:
        fecha_fin = hoy
        fecha_inicio = hoy - timedelta(days=6)
    else:
        fecha_inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
        fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()

    sectores = [
        (1, "Entrega"),
        (2, "Almacén"),
        (3, "Administración"),
        (4, "Mantenimiento"),
    ]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, nombre FROM indicadores WHERE sector_id = %s AND activo = 1", (sector_id,))
    indicadores = cursor.fetchall()

    tarjetas = []
    graficos = []

    for indicador in indicadores:
        indicador_id = indicador['id']
        nombre = indicador['nombre']

        cursor.execute("""
            SELECT SUM(valor) AS total
            FROM kpis
            WHERE indicador_id = %s AND fecha = CURDATE()
        """, (indicador_id,))
        valor_hoy = cursor.fetchone()['total'] or 0
        tarjetas.append({'nombre': nombre, 'valor': int(valor_hoy)})

        cursor.execute("""
            SELECT fecha, SUM(valor) as total
            FROM kpis
            WHERE indicador_id = %s AND fecha BETWEEN %s AND %s
            GROUP BY fecha
            ORDER BY fecha
        """, (indicador_id, fecha_inicio, fecha_fin))
        rows = cursor.fetchall()

        fechas = [r['fecha'].strftime('%d/%m') for r in rows]
        valores = [int(r['total']) for r in rows]

        graficos.append({
            'nombre': nombre.capitalize(),
            'labels': fechas,
            'data': valores
        })

    cursor.close()
    conn.close()

    return render_template("dashboard.html",
        tarjetas=tarjetas,
        graficos=graficos,
        sectores=sectores,
        sector_id=sector_id,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin
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
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dni, nombre, sector FROM choferes")
    choferes = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('choferes.html', choferes=choferes)

@app.route('/admin/choferes/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_chofer():
    if request.method == 'POST':
        dni = request.form['dni']
        nombre = request.form['nombre']
        sector = request.form['sector']
        imagen = request.files['imagen']
        imagen_blob = imagen.read() if imagen else None

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM choferes WHERE dni = %s", (dni,))
        if cursor.fetchone():
            flash("❌ Ya existe un chofer con ese DNI", "danger")
            return redirect(url_for('nuevo_chofer'))

        cursor.execute("INSERT INTO choferes (dni, nombre, sector, imagen) VALUES (%s, %s, %s, %s)", (dni, nombre, sector, imagen_blob))
        conn.commit()
        cursor.close()
        conn.close()
        flash("✅ Chofer creado correctamente", "success")
        return redirect(url_for('listar_choferes'))

    return render_template('nuevo_chofer.html')

@app.route('/admin/choferes/editar/<dni>', methods=['GET', 'POST'])
@login_required
def editar_chofer(dni):
    conn = get_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        nombre = request.form['nombre']
        sector = request.form['sector']
        imagen = request.files['imagen']
        if imagen:
            imagen_blob = imagen.read()
            cursor.execute("UPDATE choferes SET nombre = %s, sector = %s, imagen = %s WHERE dni = %s", (nombre, sector, imagen_blob, dni))
        else:
            cursor.execute("UPDATE choferes SET nombre = %s, sector = %s WHERE dni = %s", (nombre, sector, dni))
        conn.commit()
        cursor.close()
        conn.close()
        flash("✅ Datos del chofer actualizados", "success")
        return redirect(url_for('listar_choferes'))

    cursor.execute("SELECT nombre, sector FROM choferes WHERE dni = %s", (dni,))
    chofer = cursor.fetchone()
    cursor.close()
    conn.close()

    if not chofer:
        flash("❌ Chofer no encontrado", "danger")
        return redirect(url_for('listar_choferes'))

    return render_template('editar_chofer.html', dni=dni, nombre=chofer[0], sector=chofer[1])

@app.route('/admin/choferes/eliminar/<dni>', methods=['POST'])
@login_required
def eliminar_chofer(dni):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM choferes WHERE dni = %s", (dni,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("🗑️ Chofer eliminado", "warning")
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
        return send_file(BytesIO(result[0]), mimetype='image/jpeg')
    else:
        return "", 204

@app.route('/api/login', methods=['POST'])
def login_chofer():
    data = request.get_json()
    dni = data.get('dni')
    if not dni:
        return jsonify({'success': False, 'message': 'DNI requerido'}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT nombre, sector FROM choferes WHERE dni = %s", (dni,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if result:
        return jsonify({'success': True, 'nombre': result[0], 'sector': result[1]})
    else:
        return jsonify({'success': False, 'message': 'Chofer no encontrado'}), 404

@app.route('/kpis/<dni>')
def kpis(dni):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sector FROM choferes WHERE dni = %s", (dni,))
    result = cursor.fetchone()
    if not result:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Chofer no encontrado'}), 404
    sector = result[0]

    cursor.execute("""
        SELECT fecha, indicador, valor
        FROM kpis
        WHERE dni = %s AND sector = %s
        ORDER BY fecha DESC
        LIMIT 20
    """, (dni, sector))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if not rows:
        return jsonify({'message': 'No se encontraron KPIs'}), 404

    fecha = rows[0][0]
    kpis_dict = {'fecha': fecha.strftime('%Y-%m-%d')}
    for _, indicador, valor in rows:
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
    cursor.close()
    conn.close()
    avisos = [{'id': r[0], 'fecha': r[1].strftime('%Y-%m-%d %H:%M'), 'mensaje': r[2]} for r in rows]
    return jsonify(avisos)

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
            conn = get_connection()
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

                    dni, fecha, indicador_id, sector_id, valor = partes

                    try:
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

                    # Obtener el nombre del indicador (si no existe, fallback al ID)
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
                    print(f"[Línea {i}] ⚠️ Error SQL: {e} - {decoded}")
                    lineas_invalidas += 1

            conn.commit()
            cursor.close()
            conn.close()

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
    
    
@app.route('/admin/indicadores', methods=['GET'])
@login_required
def admin_indicadores():
    sector_id = request.args.get('sector_id', type=int)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Cargar sectores para el filtro (usando tabla estática o hardcoded)
    sectores = [
        (1, "Entrega"),
        (2, "Almacén"),
        (3, "Administración"),
        (4, "Mantenimiento"),
    ]

    # Query indicadores con sector
    if sector_id:
        cursor.execute("""
            SELECT i.*, %s AS sector_nombre
            FROM indicadores i
            WHERE i.sector_id = %s
        """, (sectores[sector_id - 1][1], sector_id))
    else:
        cursor.execute("SELECT * FROM indicadores")

    indicadores = cursor.fetchall()

    # Agregar nombre del sector manualmente si no se filtró
    if not sector_id:
        for ind in indicadores:
            ind["sector_nombre"] = next((n for s, n in sectores if s == ind["sector_id"]), "Desconocido")

    cursor.close()
    conn.close()

    return render_template("admin_indicadores.html", indicadores=indicadores, sectores=sectores, sector_id=sector_id)
@app.route('/admin/indicadores/toggle/<int:id>', methods=['POST'])
@login_required
def toggle_indicador(id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT activo FROM indicadores WHERE id = %s", (id,))
    resultado = cursor.fetchone()

    if resultado:
        nuevo_estado = 0 if resultado[0] == 1 else 1
        cursor.execute("UPDATE indicadores SET activo = %s WHERE id = %s", (nuevo_estado, id))
        conn.commit()

    cursor.close()
    conn.close()
    return redirect(url_for('admin_indicadores'))

@app.route('/admin/indicadores/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_indicador():
    sectores = [
        (1, "Entrega"),
        (2, "Almacén"),
        (3, "Administración"),
        (4, "Mantenimiento"),
    ]

    if request.method == 'POST':
        nombre = request.form['nombre'].strip().upper()
        sector_id = request.form['sector_id']
        activo = int(request.form['activo'])

        conn = get_connection()
        cursor = conn.cursor()

        # Validar duplicados por nombre y sector
        cursor.execute("""
            SELECT id FROM indicadores
            WHERE LOWER(nombre) = %s AND sector_id = %s
        """, (nombre, sector_id))
        existente = cursor.fetchone()

        if existente:
            flash("❌ Ya existe un indicador con ese nombre en ese sector.", "danger")
        else:
            cursor.execute("""
                INSERT INTO indicadores (nombre, sector_id, activo)
                VALUES (%s, %s, %s)
            """, (nombre, sector_id, activo))
            conn.commit()
            flash("✅ Indicador creado correctamente.", "success")
            cursor.close()
            conn.close()
            return redirect(url_for('admin_indicadores'))

        cursor.close()
        conn.close()

    return render_template("nuevo_indicador.html", sectores=sectores)


@app.route('/admin/indicadores/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_indicador(id):
    sectores = [
        (1, "Entrega"),
        (2, "Almacén"),
        (3, "Administración"),
        (4, "Mantenimiento"),
    ]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        nombre = request.form['nombre'].strip().upper()
        sector_id = int(request.form['sector_id'])
        activo = int(request.form['activo'])

        # Verificar si existe otro indicador con ese nombre en ese sector
        cursor.execute("""
            SELECT id FROM indicadores
            WHERE LOWER(nombre) = %s AND sector_id = %s AND id != %s
        """, (nombre, sector_id, id))
        duplicado = cursor.fetchone()

        if duplicado:
            flash("❌ Ya existe un indicador con ese nombre en ese sector.", "danger")
        else:
            cursor.execute("""
                UPDATE indicadores
                SET nombre = %s, sector_id = %s, activo = %s
                WHERE id = %s
            """, (nombre, sector_id, activo, id))
            conn.commit()
            flash("✅ Indicador actualizado correctamente.", "success")
            return redirect(url_for('admin_indicadores'))

    # GET: cargar datos
    cursor.execute("SELECT * FROM indicadores WHERE id = %s", (id,))
    indicador = cursor.fetchone()

    if not indicador:
        flash("❌ Indicador no encontrado.", "danger")
        return redirect(url_for('admin_indicadores'))

    cursor.close()
    conn.close()
    return render_template("editar_indicador.html", indicador=indicador, sectores=sectores)


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
@login_required
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
            return jsonify({'tarjetas': []})  # parámetros incompletos

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, nombre, tipo_grafico, color_grafico, fill_grafico
            FROM indicadores
            WHERE sector_id = %s AND activo = 1
        """, (sector_id,))
        indicadores = cursor.fetchall()

        if not indicadores:
            return jsonify({'tarjetas': []})  # no hay indicadores activos

        tarjetas = []
        for ind in indicadores:
            cursor.execute("""
                SELECT ROUND(AVG(valor), 2) AS promedio
                FROM kpis
                WHERE indicador_id = %s AND sector_id = %s
                  AND fecha BETWEEN %s AND %s
            """, (ind['id'], sector_id, fecha_ini, fecha_fin))
            resultado = cursor.fetchone()
            tarjetas.append({
                'indicador': ind['nombre'],
                'valor': float(resultado['promedio'] or 0),
                'indicador_id': ind['id'],
                'tipo': ind['tipo_grafico'],
                'color': ind['color_grafico'],
                'fill': bool(ind['fill_grafico']),
            })

        cursor.close()
        conn.close()
        return jsonify({'tarjetas': tarjetas})

    except Exception as e:
        logger.error(f"Error en resumen_dashboard: {e}")
        return jsonify({'error': 'Error interno en resumen_dashboard'}), 500



# ────────────────────────────────────────────────────────────────
# 2. Serie histórica por indicador:
#    /api/serie_indicador?indicador_id=1&sector_id=2&from=2025-06-01&to=2025-06-10
# ────────────────────────────────────────────────────────────────
@app.route('/api/serie_indicador')
def api_serie_indicador():
    try:
        indicador_id = int(request.args.get('indicador_id'))
        sector_id    = int(request.args.get('sector_id'))
        fecha_ini    = request.args.get('from')
        fecha_fin    = request.args.get('to')

        if not (fecha_ini and fecha_fin):
            return jsonify({'labels': [], 'data': [], 'indicador': 'Sin datos'})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT nombre, tipo_grafico, color_grafico, fill_grafico
            FROM indicadores
            WHERE id = %s
        """, (indicador_id,))
        ind = cursor.fetchone()

        if not ind:
            return jsonify({'labels': [], 'data': [], 'indicador': 'Desconocido'})

        cursor.execute("""
            SELECT fecha, ROUND(AVG(valor), 2) AS promedio
              FROM kpis
             WHERE indicador_id = %s AND sector_id = %s
               AND fecha BETWEEN %s AND %s
          GROUP BY fecha
          ORDER BY fecha
        """, (indicador_id, sector_id, fecha_ini, fecha_fin))
        rows = cursor.fetchall()

        etiquetas = [r['fecha'].strftime('%d/%m') for r in rows]
        valores   = [float(r['promedio']) for r in rows]

        cursor.close()
        conn.close()

        return jsonify({
            'indicador': ind['nombre'],
            'labels': etiquetas,
            'data': valores,
            'tipo': ind['tipo_grafico'],
            'color': ind['color_grafico'],
            'fill': bool(ind['fill_grafico'])
        })

    except Exception as e:
        logger.error(f"Error en serie_indicador: {e}")
        return jsonify({'labels': [], 'data': [], 'indicador': 'Error'}), 500
    
    
@app.route('/api/historial_kpi_empleado')
def historial_kpi_empleado():
    try:
        dni = request.args.get('dni')
        if not dni:
            return jsonify({'error': 'DNI requerido'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT k.indicador_id, i.nombre, i.tipo_grafico, i.color_grafico, i.fill_grafico,
                   k.fecha, ROUND(AVG(k.valor), 2) AS valor
              FROM kpis k
              JOIN indicadores i ON k.indicador_id = i.id
             WHERE k.dni = %s
          GROUP BY k.indicador_id, k.fecha
          ORDER BY k.indicador_id, k.fecha
        """, (dni,))
        rows = cursor.fetchall()

        datos = {}
        for row in rows:
            ind_id = row['indicador_id']
            if ind_id not in datos:
                datos[ind_id] = {
                    'nombre': row['nombre'],
                    'tipo': row['tipo_grafico'],
                    'color': row['color_grafico'],
                    'fill': bool(row['fill_grafico']),
                    'labels': [],
                    'data': []
                }
            datos[ind_id]['labels'].append(row['fecha'].strftime('%d/%m'))
            datos[ind_id]['data'].append(float(row['valor']))

        return jsonify({'indicadores': list(datos.values())})

    except Exception as e:
        logger.error(f"Error en historial_kpi_empleado: {e}")
        return jsonify({'error': 'Error interno'}), 500
    
@app.route('/api/kpis_por_dni/<dni>')
def api_kpis_por_dni(dni):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Obtener sector del empleado
        cursor.execute("SELECT sector FROM choferes WHERE dni = %s", (dni,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Empleado no encontrado'}), 404

        sector_id = row['sector']

        # Obtener indicadores activos para ese sector
        cursor.execute("""
            SELECT id, nombre, tipo_grafico, color_grafico, fill_grafico
            FROM indicadores
            WHERE sector_id = %s AND activo = 1
        """, (sector_id,))
        indicadores = cursor.fetchall()

        tarjetas = []

        for ind in indicadores:
            cursor.execute("""
                SELECT ROUND(AVG(valor), 2) AS promedio
                FROM kpis
                WHERE indicador_id = %s AND dni = %s
            """, (ind['id'], dni))
            resultado = cursor.fetchone()

            tarjetas.append({
                'indicador_id': ind['id'],
                'indicador': ind['nombre'],
                'valor': float(resultado['promedio'] or 0),
                'tipo': ind['tipo_grafico'],
                'color': ind['color_grafico'],
                'fill': bool(ind['fill_grafico']),
            })

        cursor.close()
        conn.close()
        return jsonify({'tarjetas': tarjetas})

    except Exception as e:
        logger.error(f"Error en kpis_por_dni: {e}")
        return jsonify({'error': 'Error interno'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
