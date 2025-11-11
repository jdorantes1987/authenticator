class ProcessPermission:
    """
    Implementación concreta de los permisos para un proceso del sistema.
    """

    def __init__(
        self,
        read: bool = False,
        create: bool = False,
        update: bool = False,
        delete: bool = False,
    ):
        self._permissions = {
            "read": read,
            "create": create,
            "update": update,
            "delete": delete,
        }

    def can_read(self) -> bool:
        return self._permissions.get("read", False)

    def can_create(self) -> bool:
        return self._permissions.get("create", False)

    def can_update(self) -> bool:
        return self._permissions.get("update", False)

    def can_delete(self) -> bool:
        return self._permissions.get("delete", False)

    def __repr__(self) -> str:
        return f"<ProcessPermission read={self.can_read()}, create={self.can_create()}, update={self.can_update()}, delete={self.can_delete()}>"
