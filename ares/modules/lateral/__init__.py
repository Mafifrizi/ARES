"""
ARES — lateral movement modules

All lateral movement classes. Import from here:

    from ares.modules.lateral.modules import RDPLateral, PsExecLateral
    from ares.modules.lateral.dcom    import DCOMLateral
    from ares.modules.lateral.smb_relay import SMBRelayAuditModule
"""
from __future__ import annotations

try:
    from ares.modules.lateral.modules import (  # noqa: F401
        BaseLateralModule,
        LateralResult,
        LateralTechnique,
        RDPLateral,
        PsExecLateral,
        WMIExecLateral,
        SSHPivot,
        WinRMLateral,
    )
except ImportError:
    pass

try:
    from ares.modules.lateral.dcom      import DCOMLateral          # noqa: F401
    from ares.modules.lateral.smb_relay import SMBRelayAuditModule  # noqa: F401
    from ares.modules.lateral.mssql     import MSSQLModule          # noqa: F401
except ImportError:
    pass

__all__ = [
    "BaseLateralModule", "LateralResult", "LateralTechnique",
    "RDPLateral", "PsExecLateral", "WMIExecLateral",
    "SSHPivot", "WinRMLateral",
    "DCOMLateral", "SMBRelayAuditModule", "MSSQLModule",
]
