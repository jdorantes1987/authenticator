import logging
from typing import Optional

from process_permission import ProcessPermission
from role_manager import User
from user_role import UserRole


class RoleManagerDB:
    """
    Gestiona la carga de usuarios, roles y permisos desde una base de datos MySQL.
    """

    def __init__(self, db):
        self.db = db
        self.logger = logging.getLogger(__class__.__name__)

    def load_user_by_username(self, username: str) -> Optional[User]:
        """
        Carga un usuario y todos sus roles y permisos asociados desde la BD.
        Retorna un objeto User completamente populado o None si no se encuentra.
        """

        try:
            # 1. Buscar al usuario
            sql, params = (
                "SELECT id, username FROM users WHERE username = {}",
                [username],
            )
            cur = self.db.execute(sql, params)
            user_data = cur.fetchone()
            # intentar normalizar a dict usando description / helpers
            dict_rows = self.db.rows_to_dict(cur, user_data)

            # asegurar que dict_row es un dict antes de indexar por claves
            if not isinstance(dict_rows, dict):
                self.logger.debug(
                    "User row no es dict (valor=%r), se aborta", dict_rows
                )
                return None

            user = User(username=dict_rows["username"])

            # 2. Cargar los roles del usuario y sus permisos
            sql_query = """
                SELECT
                    r.role_name,
                    p.process_name,
                    rp.can_read,
                    rp.can_create,
                    rp.can_update,
                    rp.can_delete
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                LEFT JOIN role_permissions rp ON r.id = rp.role_id
                LEFT JOIN processes p ON rp.process_id = p.id
                WHERE ur.username = {}
            """
            sql, params = (sql_query, [dict_rows["username"]])
            cur = self.db.execute(sql, params)
            permissions_data = cur.fetchall()
            dict_rows = self.db.rows_to_dict(cur, permissions_data)

            # Normalizar dict_rows a lista de dicts (segura para iterar)
            if dict_rows is None:
                dict_rows = []
            elif isinstance(dict_rows, dict):
                dict_rows = [dict_rows]
            elif isinstance(dict_rows, list):
                # filtrar sólo dicts por seguridad
                dict_rows = [r for r in dict_rows if isinstance(r, dict)]
            else:
                dict_rows = []

            # 3. Reconstruir los objetos Role y Permission
            roles_map = {}
            for row in dict_rows:
                role_name = row["role_name"]
                if role_name not in roles_map:
                    roles_map[role_name] = UserRole(name=role_name)

                # Si el rol tiene permisos definidos para algún proceso
                if row["process_name"]:
                    permission = ProcessPermission(
                        read=bool(row["can_read"]),
                        create=bool(row["can_create"]),
                        update=bool(row["can_update"]),
                        delete=bool(row["can_delete"]),
                    )
                    roles_map[role_name].add_permission(row["process_name"], permission)

            # 4. Asignar los roles reconstruidos al usuario
            for role in roles_map.values():
                user.assign_role(role)

            return user
        except Exception as e:
            self.logger.error(f"Error al cargar usuario '{username}': {e}")
            return None


# Ejemplo de uso
if __name__ == "__main__":

    import os
    import sys

    from dotenv import load_dotenv

    sys.path.append("..\\conexiones")
    from conn.database_connector import DatabaseConnector
    from conn.sql_server_connector import SQLServerConnector

    env_path = os.path.join("../conexiones", ".env")
    load_dotenv(
        dotenv_path=env_path,
        override=True,
    )  # Recarga las variables de entorno desde el archivo

    # Configurar logging básico si el usuario no proporciona configuración
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    # Para SQL Server
    sqlserver_connector = SQLServerConnector(
        host=os.environ["HOST_PRODUCCION_PROFIT"],
        database=os.environ["DB_NAME_DERECHA_PROFIT"],
        user=os.environ["DB_USER_PROFIT"],
        password=os.environ["DB_PASSWORD_PROFIT"],
    )
    sqlserver_connector.connect()
    db = DatabaseConnector(sqlserver_connector)
    role_manager = RoleManagerDB(db)
    user = role_manager.load_user_by_username("jdorantes")
    if user:
        print(f"--- Verificando permisos para {user.username} ---")
        print(
            f"¿Puede leer en Creyentes? {'✅' if user.has_permission('Creyentes', 'read') else '❌'}"
        )
        print(
            f"¿Puede crear en Creyentes? {'✅' if user.has_permission('Creyentes', 'create') else '❌'}"
        )
        print(
            f"¿Puede actualizar en Creyentes? {'✅' if user.has_permission('Creyentes', 'update') else '❌'}"
        )
        print(
            f"¿Puede eliminar en Creyentes? {'✅' if user.has_permission('Creyentes', 'delete') else '❌'}"
        )

    else:
        print("Usuario no encontrado.")

    db.close_connection()
