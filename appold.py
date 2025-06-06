
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file, flash, get_flashed_messages
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

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin/choferes')
@login_required
def listar_choferes():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dni, nombre FROM choferes")
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
        imagen = request.files['imagen']
        imagen_blob = imagen.read() if imagen else None

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM choferes WHERE dni = %s", (dni,))
        if cursor.fetchone():
            flash("❌ Ya existe un chofer con ese DNI", "danger")
            return redirect(url_for('nuevo_chofer'))

        cursor.execute("INSERT INTO choferes (dni, nombre, imagen) VALUES (%s, %s, %s)", (dni, nombre, imagen_blob))
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
        imagen = request.files['imagen']
        if imagen:
            imagen_blob = imagen.read()
            cursor.execute("UPDATE choferes SET nombre = %s, imagen = %s WHERE dni = %s", (nombre, imagen_blob, dni))
        else:
            cursor.execute("UPDATE choferes SET nombre = %s WHERE dni = %s", (nombre, dni))
        conn.commit()
        cursor.close()
        conn.close()
        flash("✅ Datos del chofer actualizados", "success")
        return redirect(url_for('listar_choferes'))

    cursor.execute("SELECT nombre FROM choferes WHERE dni = %s", (dni,))
    chofer = cursor.fetchone()
    cursor.close()
    conn.close()

    if not chofer:
        flash("❌ Chofer no encontrado", "danger")
        return redirect(url_for('listar_choferes'))

    return render_template('editar_chofer.html', dni=dni, nombre=chofer[0])

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

@app.route('/admin/kpis')
@login_required
def vista_kpis():
    return render_template('kpis.html')


@app.route('/api/login', methods=['POST'])
def login_chofer():
    data = request.get_json()
    dni = data.get('dni')
    if not dni:
        return jsonify({'success': False, 'message': 'DNI requerido'}), 400
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT nombre FROM choferes WHERE dni = %s", (dni,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    if result:
        return jsonify({'success': True, 'nombre': result[0]})
    else:
        return jsonify({'success': False, 'message': 'Chofer no encontrado'}), 404

@app.route('/kpis/<dni>')
def kpis(dni):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT fecha, entregas, rechazos, puntualidad, km, servicio
        FROM resultados_kpi
        WHERE dni = %s
        ORDER BY fecha DESC
        LIMIT 1
    """, (dni,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    if result:
        keys = ['fecha', 'entregas', 'rechazos', 'puntualidad', 'km', 'servicio']
        return jsonify(dict(zip(keys, result)))
    else:
        return jsonify({'message': 'No se encontraron KPIs'}), 404

@app.route('/kpis/historial/<dni>')
def historial_kpis(dni):
    page = int(request.args.get('page', 1))
    per_page = 10
    offset = (page - 1) * per_page
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT fecha, entregas, rechazos, puntualidad, km, servicio
        FROM resultados_kpi
        WHERE dni = %s
        ORDER BY fecha DESC
        LIMIT %s OFFSET %s
    """, (dni, per_page, offset))
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    kpis = [{
        'fecha': row[0].strftime('%Y-%m-%d'),
        'entregas': row[1],
        'rechazos': row[2],
        'puntualidad': row[3],
        'km': float(row[4]),
        'servicio': row[5]
    } for row in results]
    return jsonify(kpis)

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
        try:
            conn = get_connection()
            cursor = conn.cursor()

            for linea in archivo.stream.readlines():
                try:
                    decoded = linea.decode('utf-8').strip()
                    if not decoded or decoded.startswith('#'):
                        continue

                    partes = decoded.split(',')
                    if len(partes) != 7:
                        continue

                    dni = partes[0]
                    fecha = partes[1]
                    entregas = int(partes[2])
                    rechazos = int(partes[3])
                    puntualidad = float(partes[4])
                    km = float(partes[5])
                    servicio = partes[6]

                    cursor.execute("""
                        INSERT INTO resultados_kpi (dni, fecha, entregas, rechazos, puntualidad, km, servicio)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (dni, fecha, entregas, rechazos, puntualidad, km, servicio))

                    registros_insertados += 1

                except Exception as e:
                    continue  # Línea con error

            conn.commit()
            cursor.close()
            conn.close()
            flash(f"✅ {registros_insertados} registros cargados correctamente.", "success")

        except Exception as e:
            flash("❌ Error al procesar el archivo.", "danger")

    return render_template('subida_resultados.html')

@app.route('/')
def home():
    return redirect(url_for('login_admin'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
