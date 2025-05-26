from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from datetime import timedelta
import mysql.connector
from config import MYSQL_CONFIG

app = Flask(__name__)
CORS(app)

# Configuración de sesión
app.secret_key = 'clave-super-secreta'
app.permanent_session_lifetime = timedelta(minutes=30)

# Conexión directa a MySQL
def get_connection():
    return mysql.connector.connect(**MYSQL_CONFIG)

# 🧑‍💼 Login de administrador (panel web)
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
            return redirect(url_for('panel'))
        else:
            error = "Usuario o contraseña incorrectos"

    return render_template('login.html', error=error)

# 🔐 Logout del administrador
@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('login_admin'))

# 🧾 Panel administrativo de avisos
@app.route('/panel', methods=['GET', 'POST'])
def panel():
    if 'admin' not in session:
        return redirect(url_for('login_admin'))

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
        mensaje_enviado = True

    # Mostrar últimos avisos
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT dni, mensaje, fecha FROM avisos ORDER BY fecha DESC LIMIT 10")
    avisos = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('panel.html', avisos=avisos, mensaje_enviado=mensaje_enviado)

# 🚛 Login del chofer (usado por Flutter)
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

# 📊 KPIs diarios del chofer
@app.route('/kpis/<dni>', methods=['GET'])
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

# 🔔 Avisos para choferes
@app.route('/avisos/<dni>', methods=['GET'])
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

@app.route('/kpis/historial/<dni>', methods=['GET'])
def historial_kpis(dni):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT fecha, entregas, rechazos, puntualidad, km, servicio
        FROM resultados_kpi
        WHERE dni = %s
        ORDER BY fecha DESC
        LIMIT 30
    """, (dni,))
    results = cursor.fetchall()
    cursor.close()
    conn.close()

    kpis = [
        {
            'fecha': row[0].strftime('%Y-%m-%d'),
            'entregas': row[1],
            'rechazos': row[2],
            'puntualidad': row[3],
            'km': float(row[4]),
            'servicio': row[5]
        } for row in results
    ]

    return jsonify(kpis)


# ▶️ Ejecutar app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
