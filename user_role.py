from typing import Dict
from protocol_permission import Permission


class UserRole:
    """
    Implementación concreta de un rol de usuario que agrupa
    permisos por proceso.
    """

    def __init__(self, name: str):
        self._name = name
        self._process_permissions: Dict[str, Permission] = {}

    @property
    def name(self) -> str:
        return self._name

    def add_permission(self, process_name: str, permission: Permission):
        """Asigna un conjunto de permisos a un proceso específico para este rol."""
        self._process_permissions[process_name.lower()] = permission

    def has_permission_for(self, process_name: str, action: str) -> bool:
        """Verifica si el rol tiene un permiso de acción para un proceso."""
        process_name = process_name.lower()
        permission = self._process_permissions.get(process_name)
        if not permission:
            return False

        action_map = {
            "read": permission.can_read,
            "create": permission.can_create,
            "update": permission.can_update,
            "delete": permission.can_delete,
        }

        check_action = action_map.get(action.lower())
        return check_action() if check_action else False

    def __repr__(self) -> str:
        return f"<UserRole name='{self.name}'>"
