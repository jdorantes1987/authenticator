import logging
import logging.config

import bcrypt


class AuthManager:
    logging.config.fileConfig("logging.ini")
    MAX_INTENTOS = 5

    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger(__class__.__name__)

    def _get_user(self, username):
        try:
            cur = self.db.get_cursor()
            cur.execute(
                "SELECT username, password, name, intentos_fallidos, bloqueado FROM users WHERE username = %s",
                (username,),
            )
            return cur.fetchone()
        except Exception as e:
            self.logger.error(f"Error al obtener usuario '{username}': {e}")
            return None

    def autenticar(self, username, password) -> tuple[bool, str]:
        self.db.connection.connect()
        user = self._get_user(username)
        if not user:
            return False, "Usuario no encontrado"

        idlogin, hash_pass, intentos, bloqueado = (
            user["username"],
            user["password"],
            user["intentos_fallidos"],
            user["bloqueado"],
        )
        self.db.autocommit(True)

        if bloqueado:
            msg = f"Usuario '{username}' bloqueado por demasiados intentos fallidos"
            self.logger.warning(msg)
            return False, msg

        if bcrypt.checkpw(password.encode(), hash_pass.encode()):
            self._reset_intentos(idlogin)
            self.logger.info(f"Usuario '{username}' autenticado exitosamente")
            self.db.autocommit(False)
            self.db.close_connection()
            return True, "Autenticación exitosa"
        else:
            self._incrementar_intentos(idlogin, intentos)
            if intentos + 1 >= self.MAX_INTENTOS:
                self._bloquear_usuario(idlogin)
                return False, "Usuario bloqueado por demasiados intentos fallidos"
            self.logger.warning(f"Contraseña incorrecta para '{username}'.")
            self.db.autocommit(False)
            self.db.close_connection()
            return (
                False,
                f"Contraseña incorrecta. Intentos restantes: {self.MAX_INTENTOS - (intentos + 1)}",
            )

    def _reset_intentos(self, username):
        try:
            cur = self.db.get_cursor()
            cur.execute(
                "UPDATE users SET intentos_fallidos = 0 WHERE username = %s",
                (username,),
            )
        except Exception as e:
            self.logger.error(f"Error al resetear intentos para '{username}': {e}")

    def _incrementar_intentos(self, username, intentos):
        try:
            cur = self.db.get_cursor()
            cur.execute(
                "UPDATE users SET intentos_fallidos = %s WHERE username = %s",
                (intentos + 1, username),
            )
        except Exception as e:
            self.logger.error(f"Error al incrementar intentos para '{username}': {e}")

    def _bloquear_usuario(self, username):
        try:
            cur = self.db.get_cursor()
            cur.execute(
                "UPDATE users SET bloqueado = 1 WHERE username = %s", (username,)
            )
        except Exception as e:
            self.logger.error(f"Error al bloquear usuario '{username}': {e}")

    def registrar_usuario(self, iduser, nombre, password) -> tuple[bool, str]:
        try:
            self.db.connection.connect()
            hash_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            self.db.autocommit(True)
            cur = self.db.get_cursor()
            cur.execute(
                "INSERT INTO users (username, name, password) VALUES (%s, %s, %s)",
                (iduser, nombre, hash_pass),
            )
            self.db.autocommit(False)
            self.logger.info(f"Usuario '{iduser}' registrado exitosamente.")
            return True, "Registro exitoso"
        except Exception as e:
            self.logger.error(f"Error al registrar usuario '{iduser}': {e}")
            return False, "Error en el registro"
        finally:
            self.db.close_connection()

    def modificar_clave(self, username, nueva_password) -> tuple[bool, str]:
        """
        Modifica la contraseña de un usuario.
        """
        self.db.connection.connect()
        user = self._get_user(username)
        if not user:
            return False, "Usuario no encontrado"

        bloqueado = user["bloqueado"]

        if bloqueado:
            msg = (
                f"Usuario '{username}' bloqueado. No se puede modificar la contraseña."
            )
            self.logger.warning(msg)
            return False, msg
        try:
            hash_pass = bcrypt.hashpw(
                nueva_password.encode(), bcrypt.gensalt()
            ).decode()
            self.db.autocommit(True)
            cur = self.db.get_cursor()
            cur.execute(
                "UPDATE users SET password = %s WHERE username = %s",
                (hash_pass, username),
            )
            self.db.autocommit(False)
            self.logger.info(f"Contraseña modificada para '{username}'.")
            return True, "Contraseña actualizada correctamente."
        except Exception as e:
            msg = f"Error al modificar la contraseña para '{username}': {e}"
            self.logger.error(msg)
            return False, msg
        finally:
            self.db.close_connection()

    def user_existe(self, username) -> bool:
        """
        Verifica si un usuario existe.
        """
        self.db.connection.connect()
        user = self._get_user(username)
        self.db.close_connection()
        return user is not None


if __name__ == "__main__":
    import os
    import sys

    from dotenv import load_dotenv

    sys.path.append("..\\conexiones")
    from conn.database_connector import DatabaseConnector
    from conn.mysql_connector import MySQLConnector

    load_dotenv(override=True)

    mysql_connector = MySQLConnector(
        host=os.environ["DB_HOST"],
        database=os.environ["DB_NAME"],
        user=os.environ["DB_USER_ADMIN"],
        password=os.environ["DB_PASSWORD"],
    )
    mysql_connector.connect()
    db = DatabaseConnector(mysql_connector)
    auth = AuthManager(db)

    # print("=== Prueba de registro de usuario ===")
    # iduser = input("Usuario: ")
    # nombre = input("Nombre: ")
    # password = input("Contraseña: ")
    # auth.registrar_usuario(iduser, nombre, password)
    # print("Usuario registrado.\n")

    print("=== Prueba de autenticación ===")
    iduser_login = input("Usuario para login: ")
    password_login = input("Contraseña: ")
    ok, msg = auth.autenticar(iduser_login, password_login)
    print(msg)

    # print("=== Prueba de modificación de contraseña ===")
    # iduser_mod = input("Usuario para modificar contraseña: ")
    # nueva_password = input("Nueva contraseña: ")
    # ok, msg = auth.modificar_clave(iduser_mod, nueva_password)
    # print(msg)

    # print("=== Prueba de existencia de usuario ===")
    # iduser_check = input("Usuario a verificar: ")
    # existe = auth.user_existe(iduser_check)
    # print(f"El usuario '{iduser_check}' {'existe' if existe else 'no existe'}.")
