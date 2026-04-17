import logging
import logging.config

import bcrypt


class AuthManager:
    logging.config.fileConfig("logging.ini")
    MAX_INTENTOS = 5

    def __init__(self, db, ActiveDirectory=None):
        self.db = db
        self.AD = ActiveDirectory
        self.logger = logging.getLogger(__class__.__name__)

    def _get_user(self, username):
        try:
            cur = self.db.get_cursor()
            sql, params = (
                "SELECT id, username, password, name, intentos_fallidos, bloqueado, cod_client_asociation FROM users WHERE username = {}",
                [username],
            )
            cur = self.db.execute(sql, params)
            row = cur.fetchone()
            # intentar normalizar a dict usando description / helpers
            dict_rows = self.db.rows_to_dict(cur, row)
            return dict_rows
        except Exception as e:
            self.logger.error(f"Error al obtener usuario '{username}': {e}")
            return None

    def autenticar(self, username, password) -> tuple[bool, str]:
        user = self._get_user(username)
        if not user:
            return False, "Usuario no encontrado"

        idlogin, hash_pass, intentos, bloqueado = (
            user["username"],
            user["password"],
            user["intentos_fallidos"],
            user["bloqueado"],
        )

        if bloqueado:
            msg = f"Usuario '{username}' bloqueado por demasiados intentos fallidos"
            self.logger.warning(msg)
            return False, msg

        # Intentar autenticación via Active Directory si está configurado
        if self.AD:
            if self.AD.authenticate(username, password):
                self._reset_intentos(idlogin)
                self.logger.info(
                    f"Usuario '{username}' autenticado exitosamente via Active Directory"
                )
                return True, "Autenticación exitosa via Active Directory"
            else:
                self._incrementar_intentos(idlogin, intentos)
                if intentos + 1 >= self.MAX_INTENTOS:
                    self._bloquear_usuario(idlogin)
                    return False, "Usuario bloqueado por demasiados intentos fallidos"
                self.logger.warning(
                    f"Autenticación fallida via Active Directory para '{username}'."
                )
                return (
                    False,
                    f"Autenticación fallida via Active Directory. Intentos restantes: {self.MAX_INTENTOS - (intentos + 1)}",
                )

        # Autenticación local
        if bcrypt.checkpw(password.encode(), hash_pass.encode()):
            self._reset_intentos(idlogin)
            self.logger.info(f"Usuario '{username}' autenticado exitosamente")
            return True, "Autenticación exitosa"
        else:
            self._incrementar_intentos(idlogin, intentos)
            if intentos + 1 >= self.MAX_INTENTOS:
                self._bloquear_usuario(idlogin)
                return False, "Usuario bloqueado por demasiados intentos fallidos"
            self.logger.warning(f"Contraseña incorrecta para '{username}'.")
            return (
                False,
                f"Contraseña incorrecta. Intentos restantes: {self.MAX_INTENTOS - (intentos + 1)}",
            )

    def _reset_intentos(self, username):
        try:
            sql, params = (
                "UPDATE users SET intentos_fallidos = 0 WHERE username = {}",
                [username],
            )
            self.db.execute(sql, params)
            self.db.commit()
        except Exception as e:
            self.logger.error(f"Error al resetear intentos para '{username}': {e}")
            self.db.rollback()

    def _incrementar_intentos(self, username, intentos):
        try:
            sql, params = (
                "UPDATE users SET intentos_fallidos = {} WHERE username = {}",
                [intentos + 1, username],
            )
            self.db.execute(sql, params)
            self.db.commit()
        except Exception as e:
            self.logger.error(f"Error al incrementar intentos para '{username}': {e}")
            self.db.rollback()

    def _bloquear_usuario(self, username):
        try:
            sql, params = (
                "UPDATE users SET bloqueado = 1 WHERE username = {}",
                [username],
            )
            self.db.execute(sql, params)
            self.db.commit()
        except Exception as e:
            self.logger.error(f"Error al bloquear usuario '{username}': {e}")
            self.db.rollback()

    def registrar_usuario(self, iduser, nombre, password) -> tuple[bool, str]:
        try:
            hash_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            sql, params = (
                "INSERT INTO users (username, name, password) VALUES ({}, {}, {})",
                [iduser, nombre, hash_pass],
            )
            self.db.execute(sql, params)
            self.db.commit()
            self.logger.info(f"Usuario '{iduser}' registrado exitosamente.")
            return True, "Registro exitoso"
        except Exception as e:
            self.logger.error(f"Error al registrar usuario '{iduser}': {e}")
            self.db.rollback()
            return False, "Error en el registro"

    def modificar_clave(self, username, nueva_password) -> tuple[bool, str]:
        """
        Modifica la contraseña de un usuario.
        """
        user = self._get_user(username)
        if not user:
            return False, "Usuario no encontrado"

        # soportar dict o secuencia normalizada
        bloqueado = (
            user.get("bloqueado", 0)
            if hasattr(user, "get")
            else (user[4] if len(user) > 4 else 0)
        )

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
            sql, params = (
                "UPDATE users SET password = {} WHERE username = {}",
                [hash_pass, username],
            )
            self.db.execute(sql, params)
            self.db.commit()
            self.logger.info(f"Contraseña modificada para '{username}'.")
            return True, "Contraseña actualizada correctamente."
        except Exception as e:
            msg = f"Error al modificar la contraseña para '{username}': {e}"
            self.logger.error(msg)
            self.db.rollback()
            return False, msg

    def user_existe(self, username) -> bool:
        """
        Verifica si un usuario existe.
        """
        user = self._get_user(username)
        return user is not None

    def get_data_user(self, username):
        """
        Obtiene la información completa del usuario.
        """
        return self._get_user(username)

    def get_data_users(self):
        """
        Obtiene la información de todos los usuarios.
        """
        try:
            sql = "SELECT id, username, name, password, intentos_fallidos, bloqueado FROM users"
            cur = self.db.execute(sql, [])
            users_data = cur.fetchall()
            dict_rows = self.db.rows_to_dict(cur, users_data)

            # Normalizar dict_rows a lista de dicts (segura para iterar)
            if dict_rows is None:
                return []
            elif isinstance(dict_rows, dict):
                return [dict_rows]
            elif isinstance(dict_rows, list):
                # filtrar sólo dicts por seguridad
                return [r for r in dict_rows if isinstance(r, dict)]
            else:
                return []
        except Exception as e:
            self.logger.error(f"Error al obtener datos de usuarios: {e}")
            return []


if __name__ == "__main__":
    import os
    import sys

    from dotenv import load_dotenv

    sys.path.append("../conexiones")

    from conn.database_connector import DatabaseConnector
    from conn.mysql_connector import MySQLConnector

    env_path = os.path.join("../conexiones", ".env")
    load_dotenv(
        dotenv_path=env_path,
        override=True,
    )  # Recarga las variables de entorno desde el archivo

    # Para SQL Server
    db_credentials = {
        "host": os.getenv("HOST_PRODUCCION_AAPN"),
        "database": os.getenv("DB_NAME_AAPN"),
        "user": os.getenv("DB_USER_AAPN"),
        "password": os.getenv("DB_PASSWORD_AAPN"),
        "port": 3308,
    }

    mysql_connector = MySQLConnector(**db_credentials)
    mysql_connector.connect()
    db = DatabaseConnector(mysql_connector)
    db.autocommit(False)
    oAuth = AuthManager(db)
    dict_users = oAuth.get_data_users()
    lista = [user["username"] for user in dict_users if isinstance(user, dict)]
    print(lista)

    # print("=== Prueba de registro de usuario ===")
    # iduser = input("Usuario: ")
    # nombre = input("Nombre: ")
    # password = input("Contraseña: ")
    # auth.registrar_usuario(iduser, nombre, password)
    # print("Usuario registrado.\n")

    # print("=== Prueba de autenticación ===")
    # iduser_login = input("Usuario para login: ")
    # password_login = input("Contraseña: ")

    # print("=== Prueba de modificación de contraseña ===")
    # iduser_mod = input("Usuario para modificar contraseña: ")
    # nueva_password = input("Nueva contraseña: ")
    # ok, msg = auth.modificar_clave(iduser_mod, nueva_password)
    # print(msg)

    # print("=== Prueba de existencia de usuario ===")
    # iduser_check = input("Usuario a verificar: ")
    # existe = auth.user_existe(iduser_check)
    # print(f"El usuario '{iduser_check}' {'existe' if existe else 'no existe'}.")
    db.autocommit(True)
    db.close_connection()
