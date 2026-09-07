"""ARES Sovereign Purple-Team Prompts for MCP.

Pre-engineered tactical workflows appearing in Claude Desktop, Cursor, and IDE prompt pickers:
- security_audit_debrief
- lateral_movement_analysis
- remediation_action_plan
"""
from __future__ import annotations

from ares.mcp.protocol import GetPromptResult, Prompt, PromptArgument, PromptMessage, TextContent


class McpPromptRegistry:
    """Registry for standard Purple-Team prompts."""

    def __init__(self) -> None:
        self._prompts: dict[str, Prompt] = {}
        self._register_default_prompts()

    def _register_default_prompts(self) -> None:
        self._prompts["security_audit_debrief"] = Prompt(
            name="security_audit_debrief",
            description="Format campaign security findings into an authoritative executive debrief with CVSS metrics.",
            arguments=[
                PromptArgument(name="campaign_id", description="Campaign identifier to analyze", required=True),
                PromptArgument(name="focus", description="Specific focus area (e.g. Active Directory, Web, Network)", required=False),
            ],
        )
        self._prompts["lateral_movement_analysis"] = Prompt(
            name="lateral_movement_analysis",
            description="Inspect the attack graph to find shortest path to Domain Admins and identify choke points.",
            arguments=[
                PromptArgument(name="campaign_id", description="Campaign identifier to analyze", required=True),
            ],
        )
        self._prompts["remediation_action_plan"] = Prompt(
            name="remediation_action_plan",
            description="Synthesize an actionable sysadmin remediation roadmap ordered by risk severity.",
            arguments=[
                PromptArgument(name="campaign_id", description="Campaign identifier", required=True),
            ],
        )

    def list_prompts(self) -> list[Prompt]:
        return list(self._prompts.values())

    async def get_prompt(self, name: str, arguments: dict[str, str] | None = None) -> GetPromptResult:
        args = arguments or {}
        cid = args.get("campaign_id", "active_campaign")

        if name == "security_audit_debrief":
            prompt_text = (
                f"You are the Lead Purple Team Analyst reviewing campaign '{cid}'.\n\n"
                "Instructions:\n"
                "1. Call `ares_list_findings(campaign_id='{cid}', min_severity='high')` to gather critical risks.\n"
                "2. Synthesize an Executive Debrief covering:\n"
                "   - Critical Risk Summary\n"
                "   - Exploitable Attack Vectors (CVSS >= 7.0)\n"
                "   - Immediate Containment Priorities\n"
                "3. Ensure zero confidential credentials or raw hashes appear in your briefing."
            )
            return GetPromptResult(
                description="Executive Security Audit Debrief",
                messages=[PromptMessage(role="user", content=TextContent(text=prompt_text))],
            )

        if name == "lateral_movement_analysis":
            prompt_text = (
                f"You are analyzing lateral movement risk for campaign '{cid}'.\n\n"
                "Instructions:\n"
                "1. Call `ares_query_attack_graph(campaign_id='{cid}')` to retrieve attack graph paths.\n"
                "2. Identify the single most critical choke point where severing network trust or credentials "
                "blocks the adversary from reaching Domain Admins.\n"
                "3. Recommend network segmentation or tiering architecture improvements."
            )
            return GetPromptResult(
                description="Lateral Movement & Graph Analysis",
                messages=[PromptMessage(role="user", content=TextContent(text=prompt_text))],
            )

        if name == "remediation_action_plan":
            prompt_text = (
                f"You are generating a prioritized remediation roadmap for campaign '{cid}'.\n\n"
                "Instructions:\n"
                "1. Call `ares_list_findings` to enumerate all unmitigated issues.\n"
                "2. For each finding, call `ares_get_remediation_guidance` to extract verified tactical actions.\n"
                "3. Output a 3-phase remediation matrix (Immediate 24h, Short-term 7d, Strategic 30d)."
            )
            return GetPromptResult(
                description="Prioritized Remediation Roadmap",
                messages=[PromptMessage(role="user", content=TextContent(text=prompt_text))],
            )

        raise ValueError(f"Unknown prompt: '{name}'")
