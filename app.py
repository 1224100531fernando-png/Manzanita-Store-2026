import json
import os
import secrets
import time
import uuid
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename


# ==========================================================
# 1. CONFIGURACIÓN GENERAL
# ==========================================================

app = Flask(__name__, template_folder="paginas")

app.secret_key = "manzanita-store-clave-desarrollo"

ARCHIVO_USUARIOS = os.path.join(
    app.root_path,
    "usuarios.json"
)

CARPETA_FOTOS = os.path.join(
    app.root_path,
    "static",
    "img",
    "perfiles"
)

os.makedirs(CARPETA_FOTOS, exist_ok=True)

ARCHIVO_PRODUCTOS = os.path.join(
    app.root_path,
    "productos.json"
)

CARPETA_PRODUCTOS = os.path.join(
    app.root_path,
    "static",
    "img",
    "productos"
)

os.makedirs(CARPETA_PRODUCTOS, exist_ok=True)

EXTENSIONES_PERMITIDAS = {"png", "jpg", "jpeg", "webp"}

ROLES_VALIDOS = [
    "Administrador",
    "Vendedor",
    "Técnico",
    "Cliente"
]

TIEMPO_CODIGO = 600
MAX_INTENTOS = 5


# ==========================================================
# 2. FUNCIONES DE USUARIOS
# ==========================================================

def cargar_usuarios():

    if not os.path.exists(ARCHIVO_USUARIOS):
        return []

    try:
        with open(
            ARCHIVO_USUARIOS,
            "r",
            encoding="utf-8"
        ) as archivo:

            datos = json.load(archivo)

            return datos if isinstance(datos, list) else []

    except (json.JSONDecodeError, OSError):
        return []


def guardar_usuarios(usuarios):

    with open(
        ARCHIVO_USUARIOS,
        "w",
        encoding="utf-8"
    ) as archivo:

        json.dump(
            usuarios,
            archivo,
            ensure_ascii=False,
            indent=4
        )

# ==========================================================
# FUNCIONES DE ALMACENAMIENTO DE PRODUCTOS
# ==========================================================

def cargar_productos():

    if not os.path.exists(ARCHIVO_PRODUCTOS):
        return []

    try:
        with open(
            ARCHIVO_PRODUCTOS,
            "r",
            encoding="utf-8"
        ) as archivo:

            datos = json.load(archivo)

            return datos if isinstance(datos, list) else []

    except (json.JSONDecodeError, OSError):
        return []


def guardar_productos(productos):

    with open(
        ARCHIVO_PRODUCTOS,
        "w",
        encoding="utf-8"
    ) as archivo:

        json.dump(
            productos,
            archivo,
            ensure_ascii=False,
            indent=4
        )

def obtener_cuenta_actual():

    usuario_actual = session.get("usuario")

    if not usuario_actual:
        return None

    usuarios = cargar_usuarios()

    return next(
        (
            cuenta for cuenta in usuarios
            if cuenta.get("usuario", "").casefold()
            == usuario_actual.casefold()
        ),
        None
    )


def extension_permitida(nombre):

    return (
        "." in nombre
        and nombre.rsplit(".", 1)[1].lower()
        in EXTENSIONES_PERMITIDAS
    )


def obtener_foto(cuenta):

    foto = cuenta.get("foto_perfil", "")

    if not foto:
        return None

    ruta = os.path.join(CARPETA_FOTOS, foto)

    if os.path.isfile(ruta):
        return foto

    return None


# ==========================================================
# 3. CONTROL DE ROLES
# ==========================================================

def obtener_rol():
    return session.get("rol", "")


def tiene_rol(*roles):
    return obtener_rol() in roles


def inicio_por_rol():

    rol = obtener_rol()

    if rol == "Administrador":
        return redirect(url_for("dashboard"))

    if rol == "Vendedor":
        return redirect(url_for("ventas"))

    if rol == "Técnico":
        return redirect(url_for("reparaciones"))
    
    if rol == "Cliente":
        return redirect(url_for("panel_cliente"))

    session.clear() 

    flash(
        "Tu cuenta todavía no tiene un rol asignado.",
        "error"
    )

    return redirect(url_for("login"))


def requiere_sesion(funcion):

    @wraps(funcion)
    def decorada(*args, **kwargs):

        if "usuario" not in session:

            flash(
                "Primero debes iniciar sesión.",
                "error"
            )

            return redirect(url_for("login"))

        return funcion(*args, **kwargs)

    return decorada


def requiere_rol(*roles):

    def decorador(funcion):

        @wraps(funcion)
        def decorada(*args, **kwargs):

            if "usuario" not in session:

                flash(
                    "Primero debes iniciar sesión.",
                    "error"
                )

                return redirect(url_for("login"))

            if not tiene_rol(*roles):

                flash(
                    "No tienes permisos para acceder a esta sección.",
                    "error"
                )

                return inicio_por_rol()

            return funcion(*args, **kwargs)

        return decorada

    return decorador


# ==========================================================
# 4. LIMPIAR DATOS DE RECUPERACIÓN
# ==========================================================

def limpiar_recuperacion():

    session.pop("recuperacion_usuario", None)
    session.pop("recuperacion_codigo_hash", None)
    session.pop("recuperacion_expira", None)
    session.pop("recuperacion_intentos", None)


# ==========================================================
# 5. PÁGINA PRINCIPAL
# ==========================================================

@app.route("/")
def inicio():

    return redirect(url_for("login"))

# ==========================================================
# 6. PANEL DEL CLIENTE
# ==========================================================

@app.route("/mi-cuenta")
@requiere_rol("Cliente")
def panel_cliente():

    cuenta = obtener_cuenta_actual()

    if not cuenta:
        session.clear()

        flash(
            "No se encontró tu cuenta. Inicia sesión nuevamente.",
            "error"
        )

        return redirect(url_for("login"))

    return render_template(
    "tienda/panel_cliente.html", productos_catalogo=[p for p in cargar_productos() if isinstance(p, dict)],
    cuenta=cuenta,
    nombre=session.get("nombre"),
    rol=obtener_rol(),
    foto_perfil=obtener_foto(cuenta)
    )

# ==========================================================
# 7. DASHBOARD DEL ADMINISTRADOR
# ==========================================================

@app.route("/dashboard")
@requiere_rol("Administrador")
def dashboard():

    usuarios_registrados = cargar_usuarios()
    cuenta = obtener_cuenta_actual()

    return render_template(
        "dashboard/dashboard.html",
        total_usuarios=len(usuarios_registrados),
        nombre=session.get("nombre"),
        rol=obtener_rol(),
        usuario_actual=cuenta,
        foto_perfil=obtener_foto(cuenta) if cuenta else None
    )


# ==========================================================
# 8. MI PERFIL
# ==========================================================

@app.route(
    "/perfil",
    methods=["GET", "POST"]
)
@requiere_sesion
def perfil():

    usuarios_registrados = cargar_usuarios()

    usuario_actual = session.get("usuario")

    cuenta = next(
        (
            u for u in usuarios_registrados
            if u.get("usuario", "").casefold()
            == usuario_actual.casefold()
        ),
        None
    )

    if not cuenta:

        session.clear()

        flash(
            "No se encontró tu cuenta.",
            "error"
        )

        return redirect(url_for("login"))

    if request.method == "POST":

        accion = request.form.get("accion", "actualizar")

        # ----------------------------------------------
        # ACTUALIZAR INFORMACIÓN PERSONAL
        # ----------------------------------------------

        if accion == "actualizar":

            nombre = request.form.get(
                "nombre",
                ""
            ).strip()

            apellidos = request.form.get(
                "apellidos",
                ""
            ).strip()

            correo = request.form.get(
                "correo",
                ""
            ).strip().lower()

            if not nombre or not apellidos or not correo:

                flash(
                    "Completa todos los campos.",
                    "error"
                )

                return redirect(url_for("perfil"))

            for otro_usuario in usuarios_registrados:

                if otro_usuario is cuenta:
                    continue

                if otro_usuario.get("correo", "").casefold() == correo.casefold():

                    flash(
                        "Ese correo ya está registrado por otro usuario.",
                        "error"
                    )

                    return redirect(url_for("perfil"))

            cuenta["nombre"] = nombre
            cuenta["apellidos"] = apellidos
            cuenta["correo"] = correo

            guardar_usuarios(usuarios_registrados)

            session["nombre"] = nombre

            flash(
                "Tu información se actualizó correctamente.",
                "success"
            )

            return redirect(url_for("perfil"))

        # ----------------------------------------------
        # CAMBIAR CONTRASEÑA
        # ----------------------------------------------

        elif accion == "contrasena":

            actual = request.form.get(
                "contrasena_actual",
                ""
            )

            nueva = request.form.get(
                "nueva_contrasena",
                ""
            )

            confirmar = request.form.get(
                "confirmar_contrasena",
                ""
            )

            if not check_password_hash(
                cuenta.get("password", ""),
                actual
            ):

                flash(
                    "La contraseña actual es incorrecta.",
                    "error"
                )

                return redirect(url_for("perfil"))

            if len(nueva) < 8:

                flash(
                    "La nueva contraseña debe tener al menos 8 caracteres.",
                    "error"
                )

                return redirect(url_for("perfil"))

            if nueva != confirmar:

                flash(
                    "Las nuevas contraseñas no coinciden.",
                    "error"
                )

                return redirect(url_for("perfil"))

            cuenta["password"] = generate_password_hash(nueva)

            guardar_usuarios(usuarios_registrados)

            flash(
                "Tu contraseña se cambió correctamente.",
                "success"
            )

            return redirect(url_for("perfil"))

        # ----------------------------------------------
        # ACTUALIZAR FOTOGRAFÍA
        # ----------------------------------------------

        elif accion == "foto":

            archivo = request.files.get("foto")

            if not archivo or not archivo.filename:

                flash(
                    "Selecciona una fotografía.",
                    "error"
                )

                return redirect(url_for("perfil"))

            if not extension_permitida(archivo.filename):

                flash(
                    "Formato no permitido. Usa JPG, JPEG, PNG o WEBP.",
                    "error"
                )

                return redirect(url_for("perfil"))

            extension = archivo.filename.rsplit(".", 1)[1].lower()

            nombre_archivo = (
                secrets.token_hex(16)
                + "."
                + extension
            )

            ruta_destino = os.path.join(
                CARPETA_FOTOS,
                nombre_archivo
            )

            try:

                archivo.save(ruta_destino)

                foto_anterior = cuenta.get("foto_perfil")

                cuenta["foto_perfil"] = nombre_archivo

                guardar_usuarios(usuarios_registrados)

                if foto_anterior:

                    ruta_anterior = os.path.join(
                        CARPETA_FOTOS,
                        foto_anterior
                    )

                    if os.path.isfile(ruta_anterior):
                        os.remove(ruta_anterior)

                flash(
                    "Tu fotografía de perfil se actualizó correctamente.",
                    "success"
                )

            except OSError:

                if os.path.isfile(ruta_destino):
                    os.remove(ruta_destino)

                flash(
                    "No se pudo guardar la fotografía.",
                    "error"
                )

            return redirect(url_for("perfil"))

    return render_template(
        "perfil/perfil.html",
        usuario=cuenta,
        foto_perfil=obtener_foto(cuenta),
        rol=obtener_rol()
    )


# ==========================================================
# 8. INICIAR SESIÓN
# ==========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        usuario = request.form.get(
            "usuario",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        usuarios_registrados = cargar_usuarios()

        cuenta = next(
            (
                u for u in usuarios_registrados
                if u.get("usuario", "").casefold()
                == usuario.casefold()
            ),
            None
        )

        if cuenta and check_password_hash(
            cuenta.get("password", ""),
            password
        ):

            if cuenta.get("activo", True) is False:

                flash(
                    "Tu cuenta está desactivada. Contacta al administrador.",
                    "error"
                )

                return redirect(url_for("login"))

        if cuenta and check_password_hash(
            cuenta.get("password", ""),
            password
        ):

            rol = cuenta.get("rol", "Sin asignar")

            if rol not in ROLES_VALIDOS:

                flash(
                    "Tu cuenta está pendiente de que el administrador asigne un rol.",
                    "error"
                )

                return redirect(url_for("login"))

            session.clear()

            session["usuario"] = cuenta["usuario"]
            session["nombre"] = cuenta.get("nombre", "Usuario")
            session["rol"] = rol

            flash(
                f"Bienvenido a Manzanita Store, {session['nombre']}.",
                "success"
            )

            return inicio_por_rol()

        flash(
            "Usuario o contraseña incorrectos.",
            "error"
        )

    return render_template(
        "autenticacion/login.html"
    )


# ==========================================================
# 9. REGISTRO DE CUENTAS
# ==========================================================

@app.route("/registro", methods=["GET", "POST"])
def registro():

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        apellidos = request.form.get("apellidos", "").strip()
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip().lower()

        password = request.form.get("password", "")
        confirmar_password = request.form.get(
            "confirmar_password",
            ""
        )

        if not all([
            nombre,
            apellidos,
            usuario,
            correo,
            password,
            confirmar_password
        ]):

            flash(
                "Todos los campos son obligatorios.",
                "error"
            )

            return render_template(
                "autenticacion/registro.html"
            )

        if len(password) < 8:

            flash(
                "La contraseña debe tener al menos 8 caracteres.",
                "error"
            )

            return render_template(
                "autenticacion/registro.html"
            )

        if password != confirmar_password:

            flash(
                "Las contraseñas no coinciden.",
                "error"
            )

            return render_template(
                "autenticacion/registro.html"
            )

        usuarios_registrados = cargar_usuarios()

        for cuenta in usuarios_registrados:

            if cuenta.get("usuario", "").casefold() == usuario.casefold():

                flash(
                    "Ese nombre de usuario ya está registrado.",
                    "error"
                )

                return render_template(
                    "autenticacion/registro.html"
                )

            if cuenta.get("correo", "").casefold() == correo.casefold():

                flash(
                    "Ese correo electrónico ya está registrado.",
                    "error"
                )

                return render_template(
                    "autenticacion/registro.html"
                )

        rol = (
            "Administrador"
            if len(usuarios_registrados) == 0
            else "Sin asignar"
        )

        nueva_cuenta = {
            "nombre": nombre,
            "apellidos": apellidos,
            "usuario": usuario,
            "correo": correo,
            "password": generate_password_hash(password),
            "rol": rol,
            "foto_perfil": ""
        }

        usuarios_registrados.append(nueva_cuenta)

        guardar_usuarios(usuarios_registrados)

        if rol == "Administrador":

            mensaje = (
                "Cuenta creada correctamente. "
                "Se ha asignado el rol de Administrador."
            )

        else:

            mensaje = (
                "Cuenta creada correctamente. "
                "El administrador deberá asignarte un rol."
            )

        flash(mensaje, "success")

        return redirect(url_for("login"))

    return render_template(
        "autenticacion/registro.html"
    )


# ==========================================================
# 10. REGISTRO PÚBLICO DE CLIENTES
# ==========================================================

@app.route("/registro-cliente", methods=["GET", "POST"])
def registro_cliente():

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        apellidos = request.form.get("apellidos", "").strip()
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip().lower()

        password = request.form.get("password", "")
        confirmar_password = request.form.get(
            "confirmar_password",
            ""
        )

        if not all([
            nombre,
            apellidos,
            usuario,
            correo,
            password,
            confirmar_password
        ]):

            flash(
                "Todos los campos son obligatorios.",
                "error"
            )

            return render_template(
                "tienda/registro_cliente.html"
            )

        if len(password) < 8:

            flash(
                "La contraseña debe tener al menos 8 caracteres.",
                "error"
            )

            return render_template(
                "tienda/registro_cliente.html"
            )

        if password != confirmar_password:

            flash(
                "Las contraseñas no coinciden.",
                "error"
            )

            return render_template(
                "tienda/registro_cliente.html"
            )

        usuarios_registrados = cargar_usuarios()

        for cuenta in usuarios_registrados:

            if cuenta.get("usuario", "").casefold() == usuario.casefold():

                flash(
                    "Ese nombre de usuario ya está registrado.",
                    "error"
                )

                return render_template(
                    "tienda/registro_cliente.html"
                )

            if cuenta.get("correo", "").casefold() == correo.casefold():

                flash(
                    "Ese correo electrónico ya está registrado.",
                    "error"
                )

                return render_template(
                    "tienda/registro_cliente.html"
                )

        nueva_cuenta = {
            "nombre": nombre,
            "apellidos": apellidos,
            "usuario": usuario,
            "correo": correo,
            "password": generate_password_hash(password),
            "rol": "Cliente",
            "foto_perfil": "",
            "activo": True
        }

        usuarios_registrados.append(nueva_cuenta)

        guardar_usuarios(usuarios_registrados)

        flash(
            "Tu cuenta de cliente se creó correctamente. Ya puedes iniciar sesión.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template(
        "tienda/registro_cliente.html"
    )


# ==========================================================
# 10. RECUPERAR CONTRASEÑA - GENERAR CÓDIGO
# ==========================================================

@app.route(
    "/recuperar-contrasena",
    methods=["GET", "POST"]
)
def recuperar_contrasena():

    if request.method == "POST":

        usuario = request.form.get(
            "usuario",
            ""
        ).strip()

        if not usuario:

            flash(
                "Escribe tu nombre de usuario.",
                "error"
            )

            return redirect(url_for("recuperar_contrasena"))

        usuarios_registrados = cargar_usuarios()

        cuenta = next(
            (
                u for u in usuarios_registrados
                if u.get("usuario", "").casefold()
                == usuario.casefold()
            ),
            None
        )

        if not cuenta:

            flash(
                "No se encontró una cuenta con ese nombre de usuario.",
                "error"
            )

            return redirect(url_for("recuperar_contrasena"))

        codigo = f"{secrets.randbelow(1000000):06d}"

        limpiar_recuperacion()

        session["recuperacion_usuario"] = cuenta["usuario"]

        session["recuperacion_codigo_hash"] = generate_password_hash(
            codigo
        )

        session["recuperacion_expira"] = time.time() + TIEMPO_CODIGO

        session["recuperacion_intentos"] = 0

        flash(
            f"Tu código de recuperación es: {codigo}. "
            "Tiene una vigencia de 10 minutos. "
            "No compartas este código.",
            "success"
        )

        return redirect(url_for("restablecer_contrasena"))

    return render_template(
        "autenticacion/recuperar_contraseña.html"
    )


# ==========================================================
# 11. RESTABLECER CONTRASEÑA
# ==========================================================

@app.route(
    "/restablecer-contrasena",
    methods=["GET", "POST"]
)
def restablecer_contrasena():

    usuario = session.get("recuperacion_usuario")
    codigo_hash = session.get("recuperacion_codigo_hash")
    expira = session.get("recuperacion_expira")

    if not usuario or not codigo_hash or not expira:

        limpiar_recuperacion()

        flash(
            "Primero debes solicitar un código de recuperación.",
            "error"
        )

        return redirect(url_for("recuperar_contrasena"))

    if time.time() > expira:

        limpiar_recuperacion()

        flash(
            "El código ha caducado. Solicita uno nuevo.",
            "error"
        )

        return redirect(url_for("recuperar_contrasena"))

    if request.method == "POST":

        codigo = request.form.get(
            "codigo",
            ""
        ).strip()

        nueva_password = request.form.get(
            "contrasena",
            ""
        )

        confirmar_password = request.form.get(
            "confirmar_contrasena",
            ""
        )

        intentos = session.get(
            "recuperacion_intentos",
            0
        )

        if intentos >= MAX_INTENTOS:

            limpiar_recuperacion()

            flash(
                "Superaste el límite de intentos. Solicita un nuevo código.",
                "error"
            )

            return redirect(url_for("recuperar_contrasena"))

        if not codigo or not check_password_hash(
            codigo_hash,
            codigo
        ):

            session["recuperacion_intentos"] = intentos + 1

            restantes = MAX_INTENTOS - (intentos + 1)

            if restantes <= 0:

                limpiar_recuperacion()

                flash(
                    "Superaste el límite de intentos. Solicita un nuevo código.",
                    "error"
                )

                return redirect(url_for("recuperar_contrasena"))

            flash(
                f"Código incorrecto. Te quedan {restantes} intentos.",
                "error"
            )

            return redirect(url_for("restablecer_contrasena"))

        if len(nueva_password) < 8:

            flash(
                "La contraseña debe tener al menos 8 caracteres.",
                "error"
            )

            return redirect(url_for("restablecer_contrasena"))

        if nueva_password != confirmar_password:

            flash(
                "Las contraseñas no coinciden.",
                "error"
            )

            return redirect(url_for("restablecer_contrasena"))

        usuarios_registrados = cargar_usuarios()

        cuenta = next(
            (
                u for u in usuarios_registrados
                if u.get("usuario", "").casefold()
                == usuario.casefold()
            ),
            None
        )

        if not cuenta:

            limpiar_recuperacion()

            flash(
                "No se pudo localizar la cuenta.",
                "error"
            )

            return redirect(url_for("login"))

        cuenta["password"] = generate_password_hash(
            nueva_password
        )

        guardar_usuarios(usuarios_registrados)

        limpiar_recuperacion()

        flash(
            "Tu contraseña se actualizó correctamente. Ya puedes iniciar sesión.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template(
        "autenticacion/restablecer_contraseña.html"
    )


# ==========================================================
# 12. FUNCIÓN PARA REGISTRAR PÁGINAS
# ==========================================================

def registrar_pagina(
    endpoint,
    ruta,
    plantilla,
    roles
):

    def vista(id=None):

        if "usuario" not in session:

            flash(
                "Primero debes iniciar sesión.",
                "error"
            )

            return redirect(url_for("login"))

        if not tiene_rol(*roles):

            flash(
                "No tienes permisos para acceder a esta sección.",
                "error"
            )

            return inicio_por_rol()

        if id is not None:

            return render_template(
                plantilla,
                id=id,
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        return render_template(
            plantilla,
            rol=obtener_rol(),
            nombre=session.get("nombre")
        )

    vista.__name__ = endpoint

    app.add_url_rule(
        ruta,
        endpoint=endpoint,
        view_func=vista,
        methods=["GET"]
    )


# ==========================================================
# 13. MÓDULO DE USUARIOS
# ==========================================================

@app.route("/usuarios")
@requiere_rol("Administrador")
def usuarios():

    usuarios_registrados = cargar_usuarios()

    lista_usuarios = []

    for indice, usuario in enumerate(
        usuarios_registrados,
        start=1
    ):

        lista_usuarios.append({

            "id": indice,

            "nombre": usuario.get("nombre", ""),

            "apellidos": usuario.get("apellidos", ""),

            "usuario": usuario.get("usuario", ""),

            "correo": usuario.get("correo", ""),

            "rol": usuario.get("rol", "Sin asignar")

        })

    return render_template(
        "usuarios/usuarios.html",
        usuarios=lista_usuarios,
        usuario_actual=session.get("usuario")
    )


@app.route(
    "/usuarios/rol/<int:id>",
    methods=["POST"]
)
@requiere_rol("Administrador")
def actualizar_rol_usuario(id):

    usuarios_registrados = cargar_usuarios()

    if id < 1 or id > len(usuarios_registrados):

        flash(
            "El usuario seleccionado no existe.",
            "error"
        )

        return redirect(url_for("usuarios"))

    cuenta = usuarios_registrados[id - 1]

    if cuenta.get("usuario") == session.get("usuario"):

        flash(
            "No puedes cambiar tu propio rol.",
            "error"
        )

        return redirect(url_for("usuarios"))

    nuevo_rol = request.form.get("rol", "")

    if nuevo_rol not in ROLES_VALIDOS:

        flash(
            "El rol seleccionado no es válido.",
            "error"
        )

        return redirect(url_for("usuarios"))

    cuenta["rol"] = nuevo_rol

    guardar_usuarios(usuarios_registrados)

    flash(
        f"El rol de {cuenta.get('usuario')} se actualizó correctamente.",
        "success"
    )

    return redirect(url_for("usuarios"))


# ==========================================================
# 14. REGISTRAR USUARIOS DESDE EL PANEL ADMINISTRADOR
# ==========================================================

@app.route("/usuarios/registrar", methods=["GET", "POST"])
@requiere_rol("Administrador")
def nuevo_usuario():

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        apellidos = request.form.get("apellidos", "").strip()
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")
        confirmar_password = request.form.get("confirmar_password", "")
        rol = request.form.get("rol", "")

        if not all([
            nombre, apellidos, usuario, correo,
            password, confirmar_password, rol
        ]):
            flash("Todos los campos son obligatorios.", "error")
            return render_template(
                "usuarios/registrar_usuario.html",
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        if len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.", "error")
            return render_template(
                "usuarios/registrar_usuario.html",
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        if password != confirmar_password:
            flash("Las contraseñas no coinciden.", "error")
            return render_template(
                "usuarios/registrar_usuario.html",
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        if rol not in ROLES_VALIDOS:
            flash("El rol seleccionado no es válido.", "error")
            return render_template(
                "usuarios/registrar_usuario.html",
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        usuarios_registrados = cargar_usuarios()

        for cuenta in usuarios_registrados:

            if cuenta.get("usuario", "").casefold() == usuario.casefold():
                flash("Ese nombre de usuario ya está registrado.", "error")
                return render_template(
                    "usuarios/registrar_usuario.html",
                    rol=obtener_rol(),
                    nombre=session.get("nombre")
                )

            if cuenta.get("correo", "").casefold() == correo.casefold():
                flash("Ese correo electrónico ya está registrado.", "error")
                return render_template(
                    "usuarios/registrar_usuario.html",
                    rol=obtener_rol(),
                    nombre=session.get("nombre")
                )

        nueva_cuenta = {
            "nombre": nombre,
            "apellidos": apellidos,
            "usuario": usuario,
            "correo": correo,
            "password": generate_password_hash(password),
            "rol": rol,
            "foto_perfil": "",
            "activo": True
        }

        usuarios_registrados.append(nueva_cuenta)
        guardar_usuarios(usuarios_registrados)

        flash("Usuario registrado correctamente.", "success")
        return redirect(url_for("usuarios"))

    return render_template(
        "usuarios/registrar_usuario.html",
        rol=obtener_rol(),
        nombre=session.get("nombre")
    )


# ==========================================================
# 15. EDITAR USUARIOS
# ==========================================================

@app.route("/usuarios/editar/<int:id>", methods=["GET", "POST"])
@requiere_rol("Administrador")
def editar_usuario(id):

    usuarios_registrados = cargar_usuarios()

    if id < 1 or id > len(usuarios_registrados):
        flash("El usuario seleccionado no existe.", "error")
        return redirect(url_for("usuarios"))

    cuenta = usuarios_registrados[id - 1]

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        apellidos = request.form.get("apellidos", "").strip()
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        nuevo_password = request.form.get("password", "")
        nuevo_rol = request.form.get("rol", "")

        if not all([nombre, apellidos, usuario, correo]):
            flash("Completa todos los campos obligatorios.", "error")
            return render_template(
                "usuarios/editar_usuario.html",
                usuario=cuenta,
                id=id,
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        for indice, otra_cuenta in enumerate(usuarios_registrados):

            if indice == id - 1:
                continue

            if otra_cuenta.get("usuario", "").casefold() == usuario.casefold():
                flash("Ese nombre de usuario ya está registrado.", "error")
                return render_template(
                    "usuarios/editar_usuario.html",
                    usuario=cuenta,
                    id=id,
                    rol=obtener_rol(),
                    nombre=session.get("nombre")
                )

            if otra_cuenta.get("correo", "").casefold() == correo.casefold():
                flash("Ese correo electrónico ya está registrado.", "error")
                return render_template(
                    "usuarios/editar_usuario.html",
                    usuario=cuenta,
                    id=id,
                    rol=obtener_rol(),
                    nombre=session.get("nombre")
                )

        es_cuenta_actual = (
            cuenta.get("usuario", "").casefold()
            == session.get("usuario", "").casefold()
        )

        if es_cuenta_actual:
            nuevo_rol = cuenta.get("rol", "Administrador")

        elif nuevo_rol not in ROLES_VALIDOS:
            flash("El rol seleccionado no es válido.", "error")
            return render_template(
                "usuarios/editar_usuario.html",
                usuario=cuenta,
                id=id,
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        if (
            cuenta.get("rol") == "Administrador"
            and nuevo_rol != "Administrador"
            and cuenta.get("activo", True)
        ):

            administradores_activos = sum(
                1 for u in usuarios_registrados
                if u.get("rol") == "Administrador"
                and u.get("activo", True)
            )

            if administradores_activos <= 1:
                flash(
                    "No puedes quitar el rol al último administrador activo.",
                    "error"
                )
                return redirect(url_for("usuarios"))

        if nuevo_password and len(nuevo_password) < 8:
            flash("La nueva contraseña debe tener al menos 8 caracteres.", "error")
            return render_template(
                "usuarios/editar_usuario.html",
                usuario=cuenta,
                id=id,
                rol=obtener_rol(),
                nombre=session.get("nombre")
            )

        cuenta["nombre"] = nombre
        cuenta["apellidos"] = apellidos
        cuenta["usuario"] = usuario
        cuenta["correo"] = correo
        cuenta["rol"] = nuevo_rol

        if nuevo_password:
            cuenta["password"] = generate_password_hash(nuevo_password)

        guardar_usuarios(usuarios_registrados)

        if es_cuenta_actual:
            session["usuario"] = usuario
            session["nombre"] = nombre
            session["rol"] = nuevo_rol

        flash("Los datos del usuario se actualizaron correctamente.", "success")
        return redirect(url_for("usuarios"))

    return render_template(
        "usuarios/editar_usuario.html",
        usuario=cuenta,
        id=id,
        rol=obtener_rol(),
        nombre=session.get("nombre")
    )


# ==========================================================
# 16. ACTIVAR Y DESACTIVAR CUENTAS
# ==========================================================

@app.route("/usuarios/estado/<int:id>", methods=["POST"])
@requiere_rol("Administrador")
def cambiar_estado_usuario(id):

    usuarios_registrados = cargar_usuarios()

    if id < 1 or id > len(usuarios_registrados):
        flash("El usuario seleccionado no existe.", "error")
        return redirect(url_for("usuarios"))

    cuenta = usuarios_registrados[id - 1]

    if cuenta.get("usuario", "").casefold() == session.get("usuario", "").casefold():
        flash("No puedes desactivar o modificar el estado de tu propia cuenta.", "error")
        return redirect(url_for("editar_usuario", id=id))

    nuevo_estado = request.form.get("activo", "")

    if nuevo_estado not in ("true", "false"):
        flash("La solicitud de estado no es válida.", "error")
        return redirect(url_for("editar_usuario", id=id))

    activar = nuevo_estado == "true"

    if not activar and cuenta.get("rol") == "Administrador":
        administradores_activos = sum(
            1 for u in usuarios_registrados
            if u.get("rol") == "Administrador"
            and u.get("activo", True)
        )

        if administradores_activos <= 1:
            flash("No puedes desactivar al último administrador activo.", "error")
            return redirect(url_for("editar_usuario", id=id))

    cuenta["activo"] = activar
    guardar_usuarios(usuarios_registrados)

    if activar:
        flash("La cuenta se reactivó correctamente.", "success")
    else:
        flash("La cuenta se puso en pausa correctamente.", "success")

    return redirect(url_for("editar_usuario", id=id))


# ==========================================================
# 17. ELIMINAR CUENTAS PERMANENTEMENTE
# ==========================================================

@app.route("/usuarios/eliminar/<int:id>", methods=["POST"])
@requiere_rol("Administrador")
def eliminar_usuario(id):

    usuarios_registrados = cargar_usuarios()

    if id < 1 or id > len(usuarios_registrados):
        flash("El usuario seleccionado no existe.", "error")
        return redirect(url_for("usuarios"))

    cuenta = usuarios_registrados[id - 1]

    if cuenta.get("usuario", "").casefold() == session.get("usuario", "").casefold():
        flash("No puedes eliminar tu propia cuenta.", "error")
        return redirect(url_for("usuarios"))

    if (
        cuenta.get("rol") == "Administrador"
        and cuenta.get("activo", True)
    ):

        administradores_activos = sum(
            1 for u in usuarios_registrados
            if u.get("rol") == "Administrador"
            and u.get("activo", True)
        )

        if administradores_activos <= 1:
            flash("No puedes eliminar al último administrador activo.", "error")
            return redirect(url_for("usuarios"))

    usuarios_registrados.pop(id - 1)
    guardar_usuarios(usuarios_registrados)

    flash("La cuenta se eliminó permanentemente.", "success")
    return redirect(url_for("usuarios"))


registrar_pagina(
    "permisos",
    "/usuarios/permisos",
    "usuarios/permisos.html",
    ("Administrador",)
)


# ==========================================================
# 14. MÓDULO DE CLIENTES
# ==========================================================

registrar_pagina(
    "clientes",
    "/clientes",
    "clientes/clientes.html",
    ("Administrador", "Vendedor", "Técnico")
)

registrar_pagina(
    "registrar_cliente",
    "/clientes/registrar",
    "clientes/registrar_cliente.html",
    ("Administrador", "Vendedor")
)

registrar_pagina(
    "detalle_cliente",
    "/clientes/detalle/<int:id>",
    "clientes/detalle_cliente.html",
    ("Administrador", "Vendedor", "Técnico")
)

registrar_pagina(
    "editar_cliente",
    "/clientes/editar/<int:id>",
    "clientes/editar_cliente.html",
    ("Administrador", "Vendedor")
)


# ==========================================================
# 15. MÓDULO DE REPARACIONES
# ==========================================================

registrar_pagina(
    "reparaciones",
    "/reparaciones",
    "reparaciones/reparaciones.html",
    ("Administrador", "Técnico")
)

registrar_pagina(
    "registrar_reparacion",
    "/reparaciones/registrar",
    "reparaciones/registrar_reparacion.html",
    ("Administrador", "Técnico")
)

registrar_pagina(
    "detalle_reparacion",
    "/reparaciones/detalle/<int:id>",
    "reparaciones/detalle_reparacion.html",
    ("Administrador", "Técnico")
)

registrar_pagina(
    "editar_reparacion",
    "/reparaciones/editar/<int:id>",
    "reparaciones/editar_reparacion.html",
    ("Administrador", "Técnico")
)

registrar_pagina(
    "seguimiento_reparacion",
    "/reparaciones/seguimiento/<int:id>",
    "reparaciones/seguimiento_reparacion.html",
    ("Administrador", "Técnico")
)


# ==========================================================
# 16. MÓDULO DE TICKETS
# ==========================================================

registrar_pagina(
    "tickets",
    "/tickets",
    "tickets/tickets.html",
    ("Administrador", "Técnico")
)

registrar_pagina(
    "crear_ticket",
    "/tickets/crear",
    "tickets/crear_ticket.html",
    ("Administrador", "Técnico")
)

registrar_pagina(
    "detalle_ticket",
    "/tickets/detalle/<int:id>",
    "tickets/detalle_ticket.html",
    ("Administrador", "Técnico")
)

registrar_pagina(
    "editar_ticket",
    "/tickets/editar/<int:id>",
    "tickets/editar_ticket.html",
    ("Administrador", "Técnico")
)


# ==========================================================
# 17. MÓDULO DE INVENTARIO
# ==========================================================

registrar_pagina(
    "inventario",
    "/inventario",
    "inventario/inventario.html",
    ("Administrador", "Vendedor")
)


@app.route("/inventario/registrar", methods=["GET", "POST"])
@requiere_rol("Administrador")
def registrar_producto():

    if request.method == "POST":

        codigo = request.form.get("codigo", "").strip()
        nombre = request.form.get("nombre", "").strip()
        categoria = request.form.get("categoria", "").strip()
        marca = request.form.get("marca", "").strip()
        proveedor = request.form.get("proveedor", "").strip()
        descripcion = request.form.get("descripcion", "").strip()

        categorias_validas = [
            "iPhone",
            "Mac",
            "Accesorios",
            "Refacciones"
        ]

        if not all([codigo, nombre, categoria, marca]):
            flash("Completa todos los campos obligatorios.", "error")
            return redirect(url_for("registrar_producto"))

        if (
            len(codigo) > 30
            or not all(c.isalnum() or c in "_-" for c in codigo)
        ):
            flash("El código del producto no es válido.", "error")
            return redirect(url_for("registrar_producto"))

        if categoria not in categorias_validas:
            flash("Selecciona una categoría válida.", "error")
            return redirect(url_for("registrar_producto"))

        productos = cargar_productos()

        if any(
            p.get("codigo", "").casefold() == codigo.casefold()
            for p in productos
        ):
            flash("Ya existe un producto con ese código.", "error")
            return redirect(url_for("registrar_producto"))

        try:
            costo = float(request.form.get("costo", ""))
            precio = float(request.form.get("precio", ""))
            stock = int(request.form.get("stock", ""))
            minimo = int(request.form.get("minimo", ""))

            if (
                costo < 0 or precio < 0
                or costo > 999999999 or precio > 999999999
                or stock < 0 or minimo < 0
                or stock > 999999 or minimo > 999999
                or precio < costo
            ):
                raise ValueError

        except (ValueError, TypeError):
            flash("Revisa los costos, precios y existencias.", "error")
            return redirect(url_for("registrar_producto"))

        imagen = request.files.get("imagen")
        nombre_imagen = ""

        if imagen and imagen.filename:

            if not extension_permitida(imagen.filename):
                flash("La imagen debe ser PNG, JPG, JPEG o WEBP.", "error")
                return redirect(url_for("registrar_producto"))

            extension = imagen.filename.rsplit(".", 1)[1].lower()
            nombre_imagen = f"{uuid.uuid4().hex}.{extension}"

            imagen.save(
                os.path.join(CARPETA_PRODUCTOS, nombre_imagen)
            )

        producto = {
            "id": uuid.uuid4().hex,
            "codigo": codigo,
            "nombre": nombre,
            "categoria": categoria,
            "marca": marca,
            "costo": costo,
            "precio": precio,
            "stock": stock,
            "minimo": minimo,
            "proveedor": proveedor,
            "descripcion": descripcion,
            "imagen": nombre_imagen,
            "activo": True
        }

        productos.append(producto)
        guardar_productos(productos)

        flash("Producto registrado correctamente.", "success")
        return redirect(url_for("inventario"))

    return render_template(
        "inventario/registrar_producto.html",
        rol=obtener_rol(),
        nombre=session.get("nombre")
    )

registrar_pagina(
    "editar_producto",
    "/inventario/editar/<int:id>",
    "inventario/editar_producto.html",
    ("Administrador",)
)


# ==========================================================
# 18. MÓDULO DE VENTAS
# ==========================================================

registrar_pagina(
    "ventas",
    "/ventas",
    "ventas/ventas.html",
    ("Administrador", "Vendedor")
)

registrar_pagina(
    "nueva_venta",
    "/ventas/nueva",
    "ventas/nueva_venta.html",
    ("Administrador", "Vendedor")
)

registrar_pagina(
    "detalle_venta",
    "/ventas/detalle/<int:id>",
    "ventas/detalle_venta.html",
    ("Administrador", "Vendedor")
)


# ==========================================================
# 19. MÓDULO DE REPORTES
# ==========================================================

registrar_pagina(
    "reportes",
    "/reportes",
    "reportes/reportes.html",
    ("Administrador",)
)

registrar_pagina(
    "reporte_inventario",
    "/reportes/inventario",
    "reportes/reporte_inventario.html",
    ("Administrador",)
)

registrar_pagina(
    "reporte_ventas",
    "/reportes/ventas",
    "reportes/reporte_ventas.html",
    ("Administrador",)
)


# ==========================================================
# 20. CERRAR SESIÓN
# ==========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "Has cerrado sesión correctamente.",
        "success"
    )

    return redirect(url_for("login"))


# ==========================================================
# 21. EJECUTAR APLICACIÓN
# ==========================================================



@app.context_processor
def inyectar_productos_inventario():
    # Se inyectan datos solo en la vista autorizada de Inventario.
    if request.endpoint == "inventario" and "usuario" in session:
        return {"inventario_productos": cargar_productos()}
    return {}

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
