
from flask import Flask, render_template, redirect, url_for

app = Flask(__name__, template_folder="paginas")
app.secret_key = "manzanita-store-desarrollo"

@app.route("/")
def inicio():
    return redirect(url_for("login"))

@app.route("/login")
def login():
    return render_template("autenticacion/login.html")

@app.route("/registro")
def registro():
    return render_template("autenticacion/registro.html")


if __name__ == "__main__":
    app.run(debug=True)
