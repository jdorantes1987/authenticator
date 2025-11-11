from typing import Set

from protocol_permission import Role


class User:
    """
    Clase que representa a un usuario del sistema.
    """

    def __init__(self, username: str):
        self.username = username
        self.roles: Set[Role] = set()

    def assign_role(self, role: Role):
        """Asigna un rol al usuario."""
        self.roles.add(role)

    def has_permission(self, process_name: str, action: str) -> bool:
        """
        Verifica si el usuario tiene un permiso específico a través de
        cualquiera de sus roles.
        """
        return any(role.has_permission_for(process_name, action) for role in self.roles)

    def __repr__(self) -> str:
        return f"<User username='{self.username}'>"
