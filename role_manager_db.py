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
            self.db.connection.connect()
            cursor = self.db.get_cursor()

            # 1. Buscar al usuario
            cursor.execute(
                "SELECT id, username FROM users WHERE username = %s", (username,)
            )

            user_data = cursor.fetchone()

            if not user_data:
                return None

            user = User(username=user_data["username"])

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
                WHERE ur.username = %s
            """
            cursor.execute(sql_query, (user_data["username"],))
            permissions_data = cursor.fetchall()
            self.db.close_connection()

            # 3. Reconstruir los objetos Role y Permission
            roles_map = {}
            for row in permissions_data:
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
    from conn.mysql_connector import MySQLConnector

    load_dotenv(override=True)

    # Configurar logging básico si el usuario no proporciona configuración
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    mysql_connector = MySQLConnector(
        host=os.environ["DB_HOST"],
        database=os.environ["DB_NAME"],
        user=os.environ["DB_USER_ADMIN"],
        password=os.environ["DB_PASSWORD"],
    )
    mysql_connector.connect()
    db = DatabaseConnector(mysql_connector)
    role_manager = RoleManagerDB(db)
    user = role_manager.load_user_by_username("admin")
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
