from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, flash
from flask_cors import CORS
from datetime import timedelta
import mysql.connector
from config import MYSQL_CONFIG
import os
from dotenv import load_dotenv
from io import BytesIO
from functools import wraps

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

    sectores = [
        (1, "Entrega"),
        (2, "Almacén"),
        (3, "Administración"),
        (4, "Mantenimiento"),
    ]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Traer indicadores activos del sector
    cursor.execute("""
        SELECT id, nombre 
        FROM indicadores 
        WHERE sector_id = %s AND activo = 1
    """, (sector_id,))
    indicadores = cursor.fetchall()

    tarjetas = []
    graficos = []

    for indicador in indicadores:
        indicador_id = indicador['id']
        nombre = indicador['nombre']

        # Valor de hoy
        cursor.execute("""
            SELECT SUM(valor) AS total
            FROM kpis
            WHERE indicador_id = %s AND fecha = CURDATE()
        """, (indicador_id,))
        valor_hoy = cursor.fetchone()['total'] or 0
        tarjetas.append({'nombre': nombre, 'valor': int(valor_hoy)})

        # Tendencia 7 días
        cursor.execute("""
            SELECT fecha, SUM(valor) AS total
            FROM kpis
            WHERE indicador_id = %s
            GROUP BY fecha
            ORDER BY fecha DESC
            LIMIT 7
        """, (indicador_id,))
        rows = cursor.fetchall()
        if rows:
            fechas = [r['fecha'].strftime('%d/%m') for r in reversed(rows)]
            valores = [int(r['total']) for r in reversed(rows)]
        else:
            fechas = []
            valores = []

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
        sector_id=sector_id
    )




@app.route('/panel', methods=['GET', 'POST'])
@login_required
def panel():
    mensaje_enviado = False

    if request.method == 'POST':
        dni = request.form['dni']
        mensaje = request.form['mensaje']

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO avisos (dni, mensaje) VALUES (%s, %s)", (dni, mensaje))
        conn.commit()
        cursor.close()
        conn.close()
        flash("✅ Aviso enviado correctamente", "success")
        mensaje_enviado = True

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dni, mensaje, fecha FROM avisos ORDER BY fecha DESC LIMIT 10")
    avisos = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('panel.html', avisos=avisos, mensaje_enviado=mensaje_enviado)

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
    cursor.execute("SELECT sector FROM choferes WHERE dni = %s", (dni,))
    result = cursor.fetchone()
    if not result:
        cursor.close()
        conn.close()
        return jsonify([])

    sector = result[0]
    cursor.execute("""
        SELECT fecha, indicador, valor
        FROM kpis
        WHERE dni = %s AND sector = %s
        ORDER BY fecha DESC, indicador
        LIMIT 100
    """, (dni, sector))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    historial = {}
    for fecha, indicador, valor in rows:
        fecha_str = fecha.strftime('%Y-%m-%d')
        if fecha_str not in historial:
            historial[fecha_str] = {}
        historial[fecha_str][indicador] = valor

    salida = []
    for fecha in sorted(historial.keys(), reverse=True):
        salida.append({'fecha': fecha, **historial[fecha]})

    return jsonify(salida)

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

                    dni, fecha, sector_id, indicador, valor = partes

                    try:
                        sector_id = int(sector_id)
                        valor = float(valor)
                    except ValueError as ve:
                        print(f"[Línea {i}] ❌ Error de conversión: {ve} - {decoded}")
                        lineas_invalidas += 1
                        continue

                    cursor.execute("""
                        INSERT INTO kpis (dni, fecha, sector_id, indicador, valor)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (dni, fecha, sector_id, indicador, valor))

                    registros_insertados += 1

                except Exception as e:
                    print(f"[Línea {i}] ⚠️ Error SQL: {e} - {decoded}")
                    lineas_invalidas += 1
                    continue

            conn.commit()
            cursor.close()
            conn.close()

            mensaje = f"✅ {registros_insertados} registros cargados correctamente."
            if lineas_invalidas:
                mensaje += f" ⚠️ {lineas_invalidas} líneas fueron ignoradas por formato incorrecto."
            flash(mensaje, "success")

        except Exception as e:
            flash(f"❌ Error general al procesar el archivo: {str(e)}", "danger")

    return render_template('subida_resultados.html')




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
   

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
