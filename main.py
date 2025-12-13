import sys
import os
import json
import hashlib
import datetime
from dotenv import load_dotenv

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

from supabase import create_client
from PySide6 import QtWidgets, QtCore


# =====================================================
# CONFIGURACIÓN SUPABASE
# =====================================================

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# =====================================================
# CRIPTOGRAFÍA
# =====================================================

def generar_claves(usuario="estudiante"):
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
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            sha.update(bloque)
    return sha.hexdigest()


def firmar(hash_hex, priv_key_path):
    with open(priv_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=b"clave-segura"
        )

    signature = private_key.sign(
        bytes.fromhex(hash_hex),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return signature.hex()


def verificar(hash_hex, firma_hex, pub_key_path):
    with open(pub_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            bytes.fromhex(firma_hex),
            bytes.fromhex(hash_hex),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# =====================================================
# BLOCKCHAIN / LEDGER
# =====================================================

def calcular_block_hash(recibo):
    data = json.dumps(
        {
            "archivo": recibo["archivo"],
            "hash": recibo["hash"],
            "firma": recibo["firma"],
            "timestamp": recibo["timestamp"],
            "hash_prev": recibo["hash_prev"],
        },
        sort_keys=True
    ).encode("utf8")

    return hashlib.sha256(data).hexdigest()


def obtener_ultimo_block_hash():
    res = supabase.table("ledger_entries") \
        .select("block_hash") \
        .order("created_at", desc=True) \
        .limit(1) \
        .execute()

    if res.data:
        return res.data[0]["block_hash"]
    return None


def cargar_ledger_db():
    res = supabase.table("ledger_entries") \
        .select("*") \
        .order("created_at") \
        .execute()
    return res.data


def verificar_cadena(ledger):
    for i in range(1, len(ledger)):
        if ledger[i]["hash_prev"] != ledger[i - 1]["block_hash"]:
            return False
    return True


def verificar_firmas(ledger):
    for r in ledger:
        if not verificar(r["hash"], r["firma"], "estudiante_pub.pem"):
            return False
    return True


def merkle_root(hashes):
    if not hashes:
        return None

    nivel = hashes[:]
    while len(nivel) > 1:
        siguiente = []
        for i in range(0, len(nivel), 2):
            izq = nivel[i]
            der = nivel[i + 1] if i + 1 < len(nivel) else izq
            combinado = (izq + der).encode("utf8")
            siguiente.append(hashlib.sha256(combinado).hexdigest())
        nivel = siguiente

    return nivel[0]


# =====================================================
# UI PRINCIPAL
# =====================================================

class LockerUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Locker Digital con Auditoría – Supabase")
        self.resize(860, 580)

        contenedor = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(contenedor)

        titulo = QtWidgets.QLabel("Locker Digital con Firma y Blockchain")
        titulo.setAlignment(QtCore.Qt.AlignCenter)
        titulo.setStyleSheet("font-size: 22px; font-weight: bold;")
        layout.addWidget(titulo)

        self.btn = QtWidgets.QPushButton("Registrar evidencia")
        self.btn.clicked.connect(self.seleccionar_archivo)
        layout.addWidget(self.btn)

        self.lista = QtWidgets.QListWidget()
        layout.addWidget(self.lista)

        self.btn_audit = QtWidgets.QPushButton("Panel de auditoría")
        self.btn_audit.clicked.connect(self.abrir_auditoria)
        layout.addWidget(self.btn_audit)

        self.setCentralWidget(contenedor)
        self.cargar_lista()

    def cargar_lista(self):
        self.lista.clear()
        res = supabase.table("ledger_entries") \
            .select("archivo, timestamp") \
            .order("created_at", desc=True) \
            .execute()

        for r in res.data:
            self.lista.addItem(f"{r['archivo']} | {r['timestamp']}")

    def seleccionar_archivo(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self)
        if not path:
            return

        if not os.path.exists("estudiante_priv.pem"):
            generar_claves("estudiante")

        hash_archivo = calcular_hash(path)
        firma = firmar(hash_archivo, "estudiante_priv.pem")
        hash_prev = obtener_ultimo_block_hash()

        recibo = {
            "archivo": os.path.basename(path),
            "hash": hash_archivo,
            "firma": firma,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "hash_prev": hash_prev
        }

        recibo["block_hash"] = calcular_block_hash(recibo)

        supabase.table("ledger_entries").insert(recibo).execute()
        self.cargar_lista()


    def abrir_auditoria(self):
        self.panel = AuditoriaUI()
        self.panel.show()


# =====================================================
# PANEL DE AUDITORÍA
# =====================================================

class AuditoriaUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Auditoría del Ledger")
        self.resize(820, 520)

        layout = QtWidgets.QVBoxLayout(self)

        self.lista = QtWidgets.QListWidget()
        layout.addWidget(self.lista)

        self.btn = QtWidgets.QPushButton("Validar cadena y Merkle")
        self.btn.clicked.connect(self.validar)
        layout.addWidget(self.btn)

        self.cargar()

    def cargar(self):
        self.lista.clear()
        ledger = cargar_ledger_db()
        for r in ledger:
            self.lista.addItem(f"{r['archivo']} | {r['hash'][:12]}...")

    def validar(self):
        ledger = cargar_ledger_db()

        cadena_ok = verificar_cadena(ledger)
        firmas_ok = verificar_firmas(ledger)
        root = merkle_root([r["block_hash"] for r in ledger])

        msg = (
            f"Cadena válida: {cadena_ok}\n"
            f"Firmas válidas: {firmas_ok}\n\n"
            f"Merkle Root:\n{root}"
        )

        QtWidgets.QMessageBox.information(self, "Resultado de auditoría", msg)


# =====================================================
# MAIN
# =====================================================

def main():
    app = QtWidgets.QApplication(sys.argv)
    win = LockerUI()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
