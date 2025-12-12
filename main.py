import sys
import os
import hashlib
import json
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

from PySide6 import QtWidgets, QtGui, QtCore


LEDGER = "ledger.json"


# =====================================================
# UTILIDADES CRIPTOGRAFICAS Y DE LEDGER
# =====================================================

def generar_claves(usuario="estudiante"):
    """Genera par de claves RSA 3072 y las guarda en disco."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )
    public_key = private_key.public_key()

    with open(f"{usuario}_priv.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(b"clave-segura"),
            )
        )

    with open(f"{usuario}_pub.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def calcular_hash(path):
    """Calcula hash SHA 256 de un archivo."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            sha.update(bloque)
    return sha.hexdigest()


def firmar(hash_hex, priv_key_path):
    """Firma el hash con la llave privada RSA."""
    with open(priv_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=b"clave-segura"
        )

    signature = private_key.sign(
        hash_hex.encode("utf8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature.hex()


def verificar(hash_hex, firma_hex, pub_key_path):
    """Verifica la firma de un hash con la llave pública RSA."""
    with open(pub_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            bytes.fromhex(firma_hex),
            hash_hex.encode("utf8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def cargar_ledger():
    """
    Carga el ledger desde disco.
    Si el archivo no existe o su contenido no es compatible con el nuevo formato,
    crea un ledger vacio y lo devuelve.
    """
    estructura_requerida = {"archivo", "hash", "firma", "timestamp", "hash_prev"}

    if not os.path.exists(LEDGER):
        with open(LEDGER, "w", encoding="utf8") as f:
            json.dump([], f, indent=4)
        return []

    try:
        with open(LEDGER, "r", encoding="utf8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError("Ledger no es una lista")

        limpio = []
        for entrada in data:
            if isinstance(entrada, dict) and estructura_requerida.issubset(entrada.keys()):
                limpio.append(entrada)

        # Si ninguna entrada cumple la estructura, reseteamos
        if not limpio and data:
            raise ValueError("Formato antiguo incompatible")

        return limpio

    except Exception:
        # Reinicio seguro del ledger
        with open(LEDGER, "w", encoding="utf8") as f:
            json.dump([], f, indent=4)
        return []


def guardar_ledger(data):
    """Guarda el ledger en disco."""
    with open(LEDGER, "w", encoding="utf8") as f:
        json.dump(data, f, indent=4)


def crear_recibo(nombre_archivo, hash_actual, firma, hash_anterior):
    """Construye el bloque o recibo que se añade al ledger."""
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    return {
        "archivo": nombre_archivo,
        "hash": hash_actual,
        "firma": firma,
        "timestamp": ts,
        "hash_prev": hash_anterior,
    }


# =====================================================
# CALCULO MANUAL DE MERKLE ROOT Y VALIDACION DE CADENA
# =====================================================

def merkle_root(hashes):
    """
    Calcula la raiz de Merkle de una lista de hashes hexadecimales.
    Si la lista esta vacia devuelve None.
    """
    if not hashes:
        return None

    nivel = hashes[:]
    while len(nivel) > 1:
        siguiente = []
        for i in range(0, len(nivel), 2):
            izquierda = nivel[i]
            derecha = nivel[i + 1] if i + 1 < len(nivel) else izquierda
            combinado = (izquierda + derecha).encode("utf8")
            siguiente.append(hashlib.sha256(combinado).hexdigest())
        nivel = siguiente
    return nivel[0]


def verificar_cadena(ledger):
    """
    Verifica que cada bloque apunte correctamente al hash del anterior.
    Devuelve True si toda la cadena es consistente.
    """
    if not ledger:
        return True

    for i in range(1, len(ledger)):
        if ledger[i]["hash_prev"] != ledger[i - 1]["hash"]:
            return False
    return True


# =====================================================
# INTERFAZ MODERNA TIPO CYBERSECURITY UI
# =====================================================

class LockerUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Locker Digital Avanzado con Auditoria")
        self.resize(860, 580)

        self.setStyleSheet("""
        QMainWindow { background-color: #0f172a; }
        QLabel, QPushButton, QListWidget {
            color: #f9fafb;
            font-size: 15px;
            font-family: Segoe UI;
        }
        QPushButton {
            background-color: #1e40af;
            border-radius: 6px;
            padding: 8px 14px;
        }
        QPushButton:hover {
            background-color: #1d4ed8;
        }
        QListWidget {
            background-color: #020617;
            border: 1px solid #1f2937;
        }
        """)

        contenedor = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(16)

        titulo = QtWidgets.QLabel("Locker Digital con Hash, Firma Digital y Auditoria Encadenada")
        titulo.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        titulo.setStyleSheet("font-size: 22px; font-weight: bold; color: #60a5fa;")
        layout.addWidget(titulo)

        descripcion = QtWidgets.QLabel(
            "El sistema registra evidencias, calcula su hash SHA 256, firma digitalmente el registro con RSA 3072, "
            "las encadena en un ledger y permite auditar la integridad mediante una raiz de Merkle."
        )
        descripcion.setWordWrap(True)
        descripcion.setStyleSheet("font-size: 13px; color: #e5e7eb;")
        layout.addWidget(descripcion)

        self.boton_seleccionar = QtWidgets.QPushButton("Seleccionar archivo para registrar en el locker")
        self.boton_seleccionar.clicked.connect(self.seleccionar_archivo)
        layout.addWidget(self.boton_seleccionar)

        self.lista = QtWidgets.QListWidget()
        layout.addWidget(self.lista)

        botones_panel = QtWidgets.QHBoxLayout()
        self.boton_auditoria = QtWidgets.QPushButton("Abrir panel de auditoria")
        self.boton_auditoria.clicked.connect(self.abrir_auditoria)
        self.boton_actualizar = QtWidgets.QPushButton("Actualizar lista")
        self.boton_actualizar.clicked.connect(self.cargar_lista)

        botones_panel.addWidget(self.boton_auditoria)
        botones_panel.addWidget(self.boton_actualizar)
        layout.addLayout(botones_panel)

        contenedor.setLayout(layout)
        self.setCentralWidget(contenedor)

        self.cargar_lista()

    def cargar_lista(self):
        self.lista.clear()
        ledger = cargar_ledger()
        for r in ledger:
            self.lista.addItem(f"{r['archivo']}  |  {r['timestamp']}")

    def seleccionar_archivo(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo de evidencia",
            "",
            "Todos los archivos (*.*)"
        )
        if not path:
            return

        hash_actual = calcular_hash(path)

        if not os.path.exists("estudiante_priv.pem") or not os.path.exists("estudiante_pub.pem"):
            generar_claves("estudiante")

        firma = firmar(hash_actual, "estudiante_priv.pem")

        ledger = cargar_ledger()
        hash_prev = ledger[-1]["hash"] if ledger else None
        recibo = crear_recibo(os.path.basename(path), hash_actual, firma, hash_prev)
        ledger.append(recibo)
        guardar_ledger(ledger)

        self.cargar_lista()

        QtWidgets.QMessageBox.information(
            self,
            "Registro completado",
            "La evidencia se registro en el ledger con hash, firma digital y encadenamiento."
        )

    def abrir_auditoria(self):
        self.panel = AuditoriaUI()
        self.panel.show()


class AuditoriaUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Panel de Auditoria del Proyecto de Ciberseguridad")
        self.resize(820, 520)
        self.setStyleSheet("""
        QWidget { background-color: #020617; color: #f9fafb; }
        QListWidget {
            background-color: #020617;
            border: 1px solid #1f2937;
        }
        QPushButton {
            background-color: #15803d;
            border-radius: 6px;
            padding: 8px 12px;
        }
        QPushButton:hover {
            background-color: #16a34a;
        }
        """)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        titulo = QtWidgets.QLabel("Auditoria del Ledger y Raiz de Merkle")
        titulo.setStyleSheet("font-size: 20px; font-weight: bold; color: #34d399;")
        layout.addWidget(titulo)

        descripcion = QtWidgets.QLabel(
            "Esta vista permite revisar la secuencia de recibos generados, validar que el encadenamiento "
            "entre bloques no se haya roto y calcular la raiz de Merkle que resume criptograficamente "
            "las evidencias registradas."
        )
        descripcion.setWordWrap(True)
        descripcion.setStyleSheet("font-size: 13px; color: #e5e7eb;")
        layout.addWidget(descripcion)

        self.lista = QtWidgets.QListWidget()
        layout.addWidget(self.lista)

        btn_layout = QtWidgets.QHBoxLayout()
        self.boton_validar = QtWidgets.QPushButton("Validar cadena y calcular Merkle root")
        self.boton_validar.clicked.connect(self.validar)
        btn_layout.addWidget(self.boton_validar)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.cargar()

    def cargar(self):
        self.lista.clear()
        ledger = cargar_ledger()
        for r in ledger:
            self.lista.addItem(
                f"{r['archivo']} | hash: {r['hash'][:12]}... | ts: {r['timestamp']}"
            )

    def validar(self):
        ledger = cargar_ledger()
        if not ledger:
            QtWidgets.QMessageBox.information(
                self,
                "Sin datos",
                "El ledger no contiene registros de evidencias."
            )
            return

        cadena_ok = verificar_cadena(ledger)
        hashes = [r["hash"] for r in ledger]
        root = merkle_root(hashes)

        if cadena_ok:
            msg = (
                "La cadena de recibos es consistente y el encadenamiento hash_prev coincide en todos los bloques.\n\n"
                f"Raiz de Merkle calculada:\n{root}"
            )
            QtWidgets.QMessageBox.information(self, "Validacion correcta", msg)
        else:
            msg = (
                "Se detecto una inconsistencia en el encadenamiento de la cadena.\n"
                "Uno o mas bloques tienen un hash_prev que no coincide con el hash real del bloque anterior.\n\n"
                f"Raiz de Merkle calculada (sobre los hashes actuales):\n{root}"
            )
            QtWidgets.QMessageBox.critical(self, "Cadena alterada", msg)


# =====================================================
# EJECUCION DE LA APLICACION
# =====================================================

def main():
    app = QtWidgets.QApplication(sys.argv)
    ventana = LockerUI()
    ventana.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
