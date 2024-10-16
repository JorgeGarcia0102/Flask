from app import app
from flask import render_template, request, flash, redirect, url_for, session
from app.config import connectionBD
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
import re
from controllers.Funciones_usuario import *
from werkzeug.utils import secure_filename
import os


@app.route('/perfil', methods=['GET'])
def perfil():
    if 'id_usuario' in session:
        dataPerfil = info_perfil_session()
        return render_template('usuarios/perfil.html', info_perfil=dataPerfil[0])
    return redirect(url_for('login'))

@app.route('/perfil', methods=['POST'])
def update_perfil():
    if 'id_usuario' in session:
        resultadoUpdatePerfil = procesar_update_perfil(request.form)
        if resultadoUpdatePerfil == 1:
            flash('Perfil actualizado correctamente', 'success')
            return redirect(url_for('perfil'))
        elif resultadoUpdatePerfil == 2:
            flash('Las contraseñas no coinciden, por favor verifique', 'error')
        elif resultadoUpdatePerfil == 3:
            flash('Por favor ingrese su correo y contraseña actual', 'error')
        else:
            flash('Error al actualizar perfil', 'error')
        return redirect(url_for('perfil'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET'])
def register():
    return render_template('usuarios/register.html')

@app.route('/register', methods=['POST'])
def register_post():
    usuario = request.form.get('usuario')
    email = request.form.get('email')
    password = request.form.get('password')

    if recibeInsertRegisterUser(usuario, email, password):
        flash('Usuario registrado correctamente', 'success')
        return redirect(url_for('login'))
    else:
        flash('Error en el registro de usuarios', 'error')
        return redirect(url_for('register'))

@app.route('/login', methods=['GET'])
def login():
    return render_template('usuarios/login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        with connectionBD() as conexion_MySQLdb:
            with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                querySQL = """SELECT id_usuario, usuario, email, password FROM usuarios WHERE email = %s"""
                cursor.execute(querySQL, (email,))
                account = cursor.fetchone()

                if account:
                    if check_password_hash(account['password'], password):
                        session['id_usuario'] = account['id_usuario']
                        session['usuario'] = account['usuario']
                        session['email'] = account['email']
                        flash('Inicio de sesión exitoso', 'success')
                        return redirect(url_for('perfil'))
                    else:
                        flash('Contraseña incorrecta', 'error')
                else:
                    flash('Cuenta no encontrada', 'error')
    except Exception as e:
        flash(f"Error al iniciar sesión: {e}", 'error')

    return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
def logout():
    if 'id_usuario' in session:
        session.clear()
        flash('Has cerrado sesión correctamente', 'success')
    return redirect(url_for('login'))