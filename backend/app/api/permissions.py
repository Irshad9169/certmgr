"""Granular RBAC: permission codes + role→permission matrix.

Permissions are string codes like "certificate:issue". Roles map to sets of
permissions. The matrix is seeded into the roles table at startup/migration.
"""

from __future__ import annotations

from app.models.enums import RoleName

# ── Permission codes ────────────────────────────────────────────────────────
P_ = {
    "cert": {
        "view": "certificate:view",
        "issue": "certificate:issue",
        "renew": "certificate:renew",
        "revoke": "certificate:revoke",
        "import": "certificate:import",
        "export": "certificate:export",
        "download_key": "certificate:download_key",
        "deploy": "certificate:deploy",
        "edit": "certificate:edit",
        "delete": "certificate:delete",
        "bulk": "certificate:bulk",
    },
    "server": {
        "view": "server:view",
        "manage": "server:manage",
        "command": "server:command",
        "deploy": "server:deploy",
    },
    "hook": {
        "view": "hook:view",
        "manage": "hook:manage",
    },
    "notification": {
        "view": "notification:view",
        "manage": "notification:manage",
    },
    "audit": {
        "view": "audit:view",
    },
    "admin": {
        "users": "admin:users",
        "settings": "admin:settings",
        "providers": "admin:providers",
        "maintenance": "admin:maintenance",
        "reports": "admin:reports",
        "webhooks": "admin:webhooks",
    },
    "discovery": {
        "run": "discovery:run",
        "view": "discovery:view",
    },
    "health": {
        "view": "health:view",
        "run": "health:run",
    },
    "ai": {
        "use": "ai:use",
    },
}

# Flattened sets per role
_ROLE_PERMISSIONS: dict[RoleName, set[str]] = {
    RoleName.ADMIN: {
        *P_["cert"].values(), *P_["server"].values(), *P_["hook"].values(),
        *P_["notification"].values(), *P_["audit"].values(), *P_["admin"].values(),
        *P_["discovery"].values(), *P_["health"].values(), *P_["ai"].values(),
    },
    RoleName.CERT_MANAGER: {
        P_["cert"]["view"], P_["cert"]["issue"], P_["cert"]["renew"], P_["cert"]["revoke"],
        P_["cert"]["import"], P_["cert"]["export"], P_["cert"]["download_key"],
        P_["cert"]["deploy"], P_["cert"]["edit"], P_["cert"]["bulk"],
        P_["server"]["view"], P_["server"]["deploy"],
        P_["hook"]["view"], P_["notification"]["view"],
        P_["discovery"]["run"], P_["discovery"]["view"], P_["health"]["view"],
    },
    RoleName.OPERATOR: {
        P_["cert"]["view"], P_["cert"]["issue"], P_["cert"]["renew"], P_["cert"]["import"],
        P_["cert"]["export"], P_["cert"]["deploy"],
        P_["server"]["view"], P_["server"]["deploy"],
        P_["hook"]["view"], P_["notification"]["view"],
        P_["discovery"]["view"], P_["health"]["view"],
    },
    RoleName.READ_ONLY: {
        P_["cert"]["view"], P_["server"]["view"], P_["hook"]["view"],
        P_["notification"]["view"], P_["audit"]["view"], P_["discovery"]["view"],
        P_["health"]["view"],
    },
}

ROLE_PERMISSIONS: dict[str, set[str]] = {r.value: set(p) for r, p in _ROLE_PERMISSIONS.items()}


def role_permissions(role_name: str) -> list[str]:
    return sorted(ROLE_PERMISSIONS.get(role_name, []))


def has_permission(role_name: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role_name, set())


def all_permissions() -> dict[str, str]:
    flat: dict[str, str] = {}
    for group in P_.values():
        flat.update(group)
    return flat


def seed_default_roles(db) -> None:
    """Idempotently create the four built-in roles."""
    from app.models.user import Role

    descriptions = {
        RoleName.ADMIN: "Full platform administration",
        RoleName.CERT_MANAGER: "Full certificate lifecycle management",
        RoleName.OPERATOR: "Day-to-day certificate operations",
        RoleName.READ_ONLY: "Read-only visibility",
    }
    for role in RoleName:
        existing = db.query(Role).filter(Role.name == role.value).first()
        if existing:
            existing.permissions = role_permissions(role.value)
            continue
        db.add(Role(
            name=role.value,
            description=descriptions[role],
            permissions=role_permissions(role.value),
        ))
