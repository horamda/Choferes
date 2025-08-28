import pandas as pd
import mysql.connector
import tkinter as tk
from tkinter import filedialog

# =========================
# Función para limpiar valores
# =========================
def limpiar_valor(valor):
    if pd.isna(valor):   # Si es NaN o NaT
        return None
    if isinstance(valor, float) and str(valor) == 'nan':
        return None
    return str(valor).strip() if valor is not None else None

# =========================
# Normalizar CUIT (solo números, clave única)
# =========================
def normalizar_cuit(cuit):
    if not cuit or pd.isna(cuit):
        return None
    return ''.join(filter(str.isdigit, str(cuit)))

# =========================
# Configuración de la BD
# =========================
conn = mysql.connector.connect(
    host="190.210.132.63",
    user="ht627842_root",
    password="Paisaje.2024*",
    database="ht627842_personal"
)
cursor = conn.cursor()

# =========================
# Selección de archivo Excel
# =========================
root = tk.Tk()
root.withdraw()
ruta_excel = filedialog.askopenfilename(
    title="Seleccionar archivo Excel",
    filetypes=[("Archivos Excel", "*.xlsx *.xls")]
)

if not ruta_excel:
    print("❌ No se seleccionó ningún archivo.")
    exit()

# =========================
# Leer Excel
# =========================
df = pd.read_excel(ruta_excel)
df.columns = df.columns.str.strip().str.lower()

# Renombramos columnas para que coincidan
mapeo = {
    "id": "id",
    "proveedor": "nombre",
    "cuit": "cuit",
    "tipo de servicio": "rubro",
    "localidad": "localidad",
    "provincia": "provincia",
    "dirección": "direccion",
    "direccion": "direccion",
    "teléfono": "telefono",
    "telefono": "telefono",
    "atencion por :": "atencion_por",
    "nivel servicio": "nivel_servicio"
}
df = df.rename(columns=mapeo)

# =========================
# Insertar proveedores
# =========================
for _, row in df.iterrows():
    try:
        nombre = limpiar_valor(row.get("nombre"))
        cuit = normalizar_cuit(row.get("cuit"))
        rubro = limpiar_valor(row.get("rubro"))
        localidad = limpiar_valor(row.get("localidad"))
        provincia = limpiar_valor(row.get("provincia"))
        direccion = limpiar_valor(row.get("direccion"))
        telefono = limpiar_valor(row.get("telefono"))
        atencion_por = limpiar_valor(row.get("atencion_por"))
        nivel_servicio = row.get("nivel_servicio") if not pd.isna(row.get("nivel_servicio")) else 0.00

        if not nombre:
            continue

        print(f"➡️ Procesando: {nombre} ({cuit})")

        cursor.execute("""
            INSERT INTO proveedores 
                (nombre, cuit, rubro, localidad, provincia, direccion, telefono, atencion_por, nivel_servicio)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                rubro = VALUES(rubro),
                localidad = VALUES(localidad),
                provincia = VALUES(provincia),
                direccion = VALUES(direccion),
                telefono = VALUES(telefono),
                atencion_por = VALUES(atencion_por),
                nivel_servicio = VALUES(nivel_servicio)
        """, (nombre, cuit, rubro, localidad, provincia, direccion, telefono, atencion_por, nivel_servicio))

    except Exception as e:
        print(f"⚠️ Error con {row.get('nombre')}: {e}")

# =========================
# Cerrar conexión
# =========================
conn.commit()
cursor.close()
conn.close()

print("✅ Proveedores importados/actualizados correctamente desde:", ruta_excel)
