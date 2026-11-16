
import json
import os
import secrets
import time

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


# ==========================================================
# 1. CONFIGURACIÓN GENERAL
# ==========================================================

app = Flask(__name__, template_folder="paginas")

app.secret_key = "manzanita-store-clave-desarrollo"

ARCHIVO_USUARIOS = os.path.join(
    app.root_path,
    "usuarios.json"
)

ROLES_VALIDOS = [
    "Administrador",
    "Vendedor",
    "Técnico"
]

TIEMPO_CODIGO = 600  # 10 minutos
MAX_INTENTOS = 5


# ==========================================================
# 2. ADMINISTRACIÓN DE USUARIOS
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
# 6. DASHBOARD DEL ADMINISTRADOR
# ==========================================================

@app.route("/dashboard")
@requiere_rol("Administrador")
def dashboard():

    usuarios_registrados = cargar_usuarios()

    return render_template(
        "dashboard/dashboard.html",
        total_usuarios=len(usuarios_registrados),
        nombre=session.get("nombre"),
        rol=obtener_rol()
    )


# ==========================================================
# 7. INICIAR SESIÓN
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
# 8. REGISTRO DE CUENTAS
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
            "rol": rol
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
# 9. RECUPERAR CONTRASEÑA - GENERAR CÓDIGO
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

        # Generar código aleatorio de seis dígitos.

        codigo = f"{secrets.randbelow(1000000):06d}"

        # Guardar el hash del código en la sesión.

        limpiar_recuperacion()

        session["recuperacion_usuario"] = cuenta["usuario"]

        session["recuperacion_codigo_hash"] = generate_password_hash(
            codigo
        )

        session["recuperacion_expira"] = time.time() + TIEMPO_CODIGO

        session["recuperacion_intentos"] = 0

        # Mostrar el código solamente para pruebas locales.

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
# 10. RESTABLECER CONTRASEÑA
# ==========================================================

@app.route(
    "/restablecer-contrasena",
    methods=["GET", "POST"]
)
def restablecer_contrasena():

    usuario = session.get("recuperacion_usuario")
    codigo_hash = session.get("recuperacion_codigo_hash")
    expira = session.get("recuperacion_expira")

    # Verificar que exista una recuperación activa.

    if not usuario or not codigo_hash or not expira:

        limpiar_recuperacion()

        flash(
            "Primero debes solicitar un código de recuperación.",
            "error"
        )

        return redirect(url_for("recuperar_contrasena"))

    # Verificar vencimiento.

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

        # Control de intentos.

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

        # Validar código.

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

        # Validar nueva contraseña.

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

        # Buscar nuevamente al usuario.

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

        # Actualizar contraseña con hash.

        cuenta["password"] = generate_password_hash(
            nueva_password
        )

        guardar_usuarios(usuarios_registrados)

        # Eliminar código para impedir reutilización.

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
# 11. FUNCIÓN PARA REGISTRAR PÁGINAS
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
# 12. MÓDULO DE USUARIOS
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


registrar_pagina(
    "nuevo_usuario",
    "/usuarios/registrar",
    "usuarios/registrar_usuario.html",
    ("Administrador",)
)

registrar_pagina(
    "registrar_usuario",
    "/usuarios/registrar",
    "usuarios/registrar_usuario.html",
    ("Administrador",)
)

registrar_pagina(
    "editar_usuario",
    "/usuarios/editar/<int:id>",
    "usuarios/editar_usuario.html",
    ("Administrador",)
)

registrar_pagina(
    "permisos",
    "/usuarios/permisos",
    "usuarios/permisos.html",
    ("Administrador",)
)


# ==========================================================
# 13. MÓDULO DE CLIENTES
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
# 14. MÓDULO DE REPARACIONES
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
# 15. MÓDULO DE TICKETS
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
# 16. MÓDULO DE INVENTARIO
# ==========================================================

registrar_pagina(
    "inventario",
    "/inventario",
    "inventario/inventario.html",
    ("Administrador", "Vendedor")
)

registrar_pagina(
    "registrar_producto",
    "/inventario/registrar",
    "inventario/registrar_producto.html",
    ("Administrador",)
)

registrar_pagina(
    "editar_producto",
    "/inventario/editar/<int:id>",
    "inventario/editar_producto.html",
    ("Administrador",)
)


# ==========================================================
# 17. MÓDULO DE VENTAS
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
# 18. MÓDULO DE REPORTES
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
# 19. CERRAR SESIÓN
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
# 20. EJECUTAR APLICACIÓN
# ==========================================================

if __name__ == "__main__":

    app.run(debug=True)
