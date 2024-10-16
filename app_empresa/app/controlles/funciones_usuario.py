# Importando paquetes desde flask
from flask import session, flash

# Importando conexión a BD
from config import connectionBD

# Para validar contraseña
from werkzeug.security import check_password_hash

import re
# Para encriptar contraseña generate_password_hash
from werkzeug.security import generate_password_hash

def recibeInsertRegisterUser(usuario, email, password):
    respuestaValidar = validarDataRegisterLogin(
        usuario, email, password)

    if (respuestaValidar):
        nueva_password = generate_password_hash(password, method='scrypt')
        try:
            with connectionBD() as conexion_MySQLdb:
                with conexion_MySQLdb.cursor(dictionary=True) as mycursor:
                    sql = "INSERT INTO usuarios(usuario, password, email) VALUES (%s, %s, %s)"
                    valores = (usuario, nueva_password, email)
                    mycursor.execute(sql, valores)
                    conexion_MySQLdb.commit()
                    resultado_insert = mycursor.rowcount
                    return resultado_insert
        except Exception as e:
            print(f"Error en el Insert usuarios: {e}")
            return []
    else:
        return False

# Validando la data del registros para el login
def validarDataRegisterLogin(usuario, email, password):
    try:
        with connectionBD() as conexion_MySQLdb:
            with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                querySQL = "SELECT * FROM usuarios WHERE email = %s"
                cursor.execute(querySQL, (email,))
                userBD = cursor.fetchone() # Obtener la primera fila de resultados

                if userBD is not None:
                    flash('El registro no fue procesado ya existe la cuenta', 'error')
                    return False
                elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    flash('El Correo es inválido', 'error')
                    return False
                elif not usuario or not email or not password:
                    flash('Por favor llene los campos del formulario.', 'error')
                    return False
                else:
                    # La cuenta no existe y los datos del formulario son válidos, puedo realizar el Insert
                    return True
    except Exception as e:
        print(f"Error en validarDataRegisterLogin : {e}")
        return []

def info_perfil_session():
    try:
        with connectionBD() as conexion_MySQLdb:
            with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                querySQL = "SELECT usuario, email FROM usuarios WHERE id_usuario = %s"
                cursor.execute(querySQL, (session['id_usuario'],))
                info_perfil = cursor.fetchall()
                return info_perfil
    except Exception as e:
        print(f"Error en info_perfil_session : {e}")
        return []

def procesar_update_perfil(data_form):
    # Extraer datos del diccionario data_form
    id_usuario = session['id_usuario']
    usuario = data_form['usuario']
    email = data_form['email']
    pass_actual = data_form['pass_actual']
    new_password = data_form['new_password']
    repetir_password = data_form['repetir_password']

    if not pass_actual or not email:
        return 3

    with connectionBD() as conexion_MySQLdb:
        with conexion_MySQLdb.cursor(dictionary=True) as cursor:
            querySQL = """SELECT * FROM usuarios WHERE email = %s LIMIT 1"""
            cursor.execute(querySQL, (email,))
            account = cursor.fetchone()

            if account:
                if check_password_hash(account['password'], pass_actual):
                    # Verificar si new_password y repetir_password estan vacias
                    if not new_password or not repetir_password:
                        return updatePefilSinPass(id_usuario, usuario)
                    else:
                        if new_password != repetir_password:
                            return 2
                        else:
                            try:
                                nueva_password = generate_password_hash(
                                    new_password, method='scrypt')
                                with connectionBD() as conexion_MySQLdb:
                                    with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                                        querySQL = """
                                        UPDATE usuarios
                                        SET
                                        usuario = %s,
                                        password = %s
                                        WHERE id_usuario = %s
                                        """
                                        params = (usuario, nueva_password, id_usuario)
                                        cursor.execute(querySQL, params)
                                        conexion_MySQLdb.commit()
                                        return cursor.rowcount or []
                            except Exception as e:
                                print(f"Ocurrió en procesar_update_perfil: {e}")
                                return []
                else:
                    return 0
            return 0

def updatePefilSinPass(id_usuario, usuario):
    try:
        with connectionBD() as conexion_MySQLdb:
            with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                querySQL = """
                UPDATE usuarios
                SET
                usuario = %s
                WHERE id_usuario = %s
                """
                params = (usuario, id_usuario)
                cursor.execute(querySQL, params)
                conexion_MySQLdb.commit()
                return cursor.rowcount
    except Exception as e:
        print(f"Ocurrió un error en la funcion updatePefilSinPass: {e}")
        return []

def dataLoginSession():
    inforLogin = {
        "id_usuario": session['id_usuario'],
        "usuario": session['usuario'],
        "email": session['email']
    }
    return inforLogin