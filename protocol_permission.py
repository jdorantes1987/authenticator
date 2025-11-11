from typing import Protocol


class Permission(Protocol):
    """
    Protocolo que define las acciones permitidas sobre un recurso.
    """

    def can_read(self) -> bool:
        pass

    def can_create(self) -> bool:
        pass

    def can_update(self) -> bool:
        pass

    def can_delete(self) -> bool:
        pass


class Role(Protocol):
    @property
    def name(self) -> str:
        pass

    # Verifica si el rol tiene un permiso específico para un proceso dado
    def has_permission_for(self, process_name: str, action: str) -> bool:
        pass
