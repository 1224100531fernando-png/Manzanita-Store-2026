
import json
import os

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
# 4. PÁGINA PRINCIPAL
# ==========================================================

@app.route("/")
def inicio():

    return redirect(url_for("login"))


# ==========================================================
# 5. DASHBOARD DEL ADMINISTRADOR
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
# 6. INICIAR SESIÓN
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

            session["nombre"] = cuenta.get(
                "nombre",
                "Usuario"
            )

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
# 7. REGISTRO DE CUENTAS
# ==========================================================

@app.route("/registro", methods=["GET", "POST"])
def registro():

    if request.method == "POST":

        nombre = request.form.get(
            "nombre",
            ""
        ).strip()

        apellidos = request.form.get(
            "apellidos",
            ""
        ).strip()

        usuario = request.form.get(
            "usuario",
            ""
        ).strip()

        correo = request.form.get(
            "correo",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

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

            if cuenta.get(
                "usuario",
                ""
            ).casefold() == usuario.casefold():

                flash(
                    "Ese nombre de usuario ya está registrado.",
                    "error"
                )

                return render_template(
                    "autenticacion/registro.html"
                )

            if cuenta.get(
                "correo",
                ""
            ).casefold() == correo.casefold():

                flash(
                    "Ese correo electrónico ya está registrado.",
                    "error"
                )

                return render_template(
                    "autenticacion/registro.html"
                )

        # La primera cuenta será Administrador.
        # Las demás necesitarán asignación de rol.

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
# 8. FUNCIÓN PARA REGISTRAR PÁGINAS
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
# 9. MÓDULO DE USUARIOS
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

            "nombre": usuario.get(
                "nombre",
                ""
            ),

            "apellidos": usuario.get(
                "apellidos",
                ""
            ),

            "usuario": usuario.get(
                "usuario",
                ""
            ),

            "correo": usuario.get(
                "correo",
                ""
            ),

            "rol": usuario.get(
                "rol",
                "Sin asignar"
            )

        })

    return render_template(
        "usuarios/usuarios.html",
        usuarios=lista_usuarios,
        usuario_actual=session.get("usuario")
    )


# Asignar o cambiar el rol de un usuario.

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

    nuevo_rol = request.form.get(
        "rol",
        ""
    )

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
# 10. MÓDULO DE CLIENTES
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
# 11. MÓDULO DE REPARACIONES
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
# 12. MÓDULO DE TICKETS
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
# 13. MÓDULO DE INVENTARIO
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
# 14. MÓDULO DE VENTAS
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
# 15. MÓDULO DE REPORTES
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
# 16. CERRAR SESIÓN
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
# 17. EJECUTAR APLICACIÓN
# ==========================================================

if __name__ == "__main__":

    app.run(debug=True)
