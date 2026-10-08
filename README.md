# Atlas EASM desktop application

Launch the local PySide6 interface with `python main.py` after installing
`requirements.txt`. Enter or import targets, watch analysis progress, inspect
evidence and prior runs, then export results when needed. See
[desktop installation and workflow](#atlas-easm-desktop-application) below.

The command-line tools described in the following sections remain available
for scripted and legacy workflows.

This project implements the requested four-stage defensive EASM workflow:

```text
01_generate_input.py
        |
        v
targets.xlsx / targets.json
        |
        v
02_off_asn_discovery.py
        |
        v
off_asn_candidates.xlsx / off_asn_candidates.json
        |
        v
03_connector.py
        |
        v
04_ip_verification.py
        |
        v
verified_ip_ranges.xlsx / verified_ip_ranges.json
```

## What the system does

The system discovers public IPs related to target domains, determines their current origin ASN, removes IPs originated by known target ASNs, and then independently evaluates whether remaining IPs are actually associated with the target organization.

A cloud-provider result is never treated as proof of customer ownership.

The final attribution distinguishes network registration from operational/customer control and records the evidence used.


## One-command workflow — recommended

You do **not** need to run the four programs manually.

Put your input file in the same folder and name it:

```text
targets.xlsx
```

Then run:

```powershell
python run_all.py
```

That's it.

The runner will:

1. Run the discovery program.
2. Create `off_asn_candidates.xlsx` and `off_asn_candidates.json`.
3. Automatically open `off_asn_candidates.xlsx` in Excel on Windows.
4. Start the verification program immediately afterward.
5. You can inspect the first/discovery Excel output while verification is still running.
6. When verification finishes, it creates `verified_ip_ranges.xlsx` and `verified_ip_ranges.json`.

You can also specify another input file:

```powershell
python run_all.py --input my_targets.xlsx
```

Useful options:

```powershell
python run_all.py --input targets.xlsx --workers 10
python run_all.py --input targets.xlsx --no-open-excel
python run_all.py --input targets.xlsx --overwrite
```

### What you see while it runs

```text
[1/2] DISCOVERY STARTED
    ...
[HANDOFF] Discovery finished successfully.
[HANDOFF] Excel: off_asn_candidates.xlsx
[HANDOFF] JSON : off_asn_candidates.json
[VIEW] Opened discovery workbook in Excel

[2/2] VERIFICATION STARTED
[2/2] You can now inspect the discovery Excel workbook while verification is running.
    Verified 10/120
    Verified 20/120
    ...
```

So the intended user workflow is simply:

```text
Put targets.xlsx in folder
        ↓
python run_all.py
        ↓
Discovery Excel opens
        ↓
You inspect it
        ↓
Verification runs automatically
        ↓
Final verified_ip_ranges.xlsx
```

## Installation

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Python 3.11+ is supported, including 3.12 and 3.13.

## Configuration

Edit `config.json`:

```json
{
  "shodan_api_key": "YOUR_KEY"
}
```

Or create `.env` from `.env.example`:

```text
SHODAN_API_KEY=YOUR_KEY
```

The environment variable takes precedence in the discovery/verification calls when present.

Never commit secrets to source control.

## Step 1: Generate input

Interactive:

```powershell
python 01_generate_input.py
```

From an existing CSV/XLSX/JSON:

```powershell
python 01_generate_input.py --input my_targets.xlsx --output targets.xlsx --json-output targets.json
```

Input columns:

```text
Parent_Organization
Target_Entity
Target_Domain
Known_Target_ASNs
Known_Registrant_Names
```

Multiple values use `;`.

Example:

```text
Qualys | Qualys, Inc. | qualys.com | AS27385 | QUALYS, INC.;QUALYS INC
```

The generator validates domains, ASNs, duplicate rows, whitespace and normalization.

## Step 2: Run discovery only

```powershell
python 02_off_asn_discovery.py --input targets.xlsx
```

Or:

```powershell
python 02_off_asn_discovery.py --input targets.json --output off_asn_candidates.xlsx
```

Discovery sources include:

- DNS A/AAAA and CNAME
- Certificate Transparency via crt.sh
- Reverse DNS
- RDAP
- RIPEstat network/ASN information for current origin ASN
- Shodan when configured
- TLS certificate inspection
- Lightweight same-domain public-page inspection for IP/CIDR references

The discovery engine only creates candidates. It does not make the final ownership decision.

## Step 3: Run the complete workflow

Recommended:

```powershell
python 03_connector.py --input targets.xlsx
```

The connector:

1. Validates the target input.
2. Runs discovery.
3. Validates candidate JSON.
4. Refuses to invoke verification for malformed or empty candidate JSON.
5. Runs the verification engine.
6. Reports the final files.

## Step 4: Run verification independently

```powershell
python 04_ip_verification.py --input off_asn_candidates.json
```

This is useful when the discovery JSON has already been generated and you want to re-run attribution.

## Output

The final workbook contains:

- `Verified IPs`
- `Evidence`
- `Summary`
- `Candidates`

The `Verified IPs` sheet includes:

```text
IP Range
IP
Parent Organization
Target Entity
Target Domain
Relationship
Owned/Leased/Hosted
Registered Organization
Origin ASN
Origin Organization
Hosting Provider
Confidence Score
Confidence
Evidence Count
Discovery Sources
Verification Sources
DNS Evidence
TLS Evidence
Certificate Evidence
RDAP Evidence
BGP Evidence
Shodan Evidence
Historical DNS Evidence
Official Source Evidence
Proof Summary
First Seen
Last Seen
Verification Timestamp
```

## Attribution methodology

### Important distinctions

- Origin ASN is the ASN currently observed as the origin in RIPEstat.
- RDAP organization is the registered network organization.
- Hosting provider is treated as infrastructure context.
- DNS-to-target-host evidence indicates current application/infrastructure association.
- TLS SAN/CN evidence is strong corroboration.
- CT evidence is historical/discovery evidence and is not ownership proof by itself.
- Shodan is supporting evidence.
- Official/public target-domain evidence is treated as strong evidence when the page explicitly contains the relevant IP/range.
- A cloud provider's ownership of an address does not prove the target organization owns or operates the service.

### Confidence

Default thresholds:

```text
90-100  CONFIRMED
75-89   HIGH
50-74   MEDIUM
30-49   LOW
0-29    UNVERIFIED
```

A score alone cannot force `CONFIRMED`. The verification engine requires a strong direct relationship, such as official documentation or current target DNS plus a matching target TLS certificate, or multiple independent strong signals.

## IP range safety

The system intentionally does not expand a single observed IP into an entire cloud CIDR.

For an observed IPv4 address, the default `IP Range` is its host route (`/32`); IPv6 uses `/128`.

The RDAP registered network is retained separately as `Registered Organization`/candidate metadata. A whole target-associated CIDR should only be added when evidence explicitly supports the range.

This avoids the common EASM error of attributing an entire AWS/Azure/GCP/CDN block to one customer.

## Caching

`easm_cache.db` is created as a migration-safe SQLite cache. The current implementation keeps the cache foundation available for future provider-specific caching and does not depend on a fixed historical schema.

## Rate limits and safety

The implementation uses timeouts, retries, exponential backoff, request delays and bounded workers.

It performs passive/lightweight DNS, RDAP, CT and TLS checks. It does not perform arbitrary port scanning or aggressive enumeration.

Respect the terms, rate limits and acceptable-use policies of every provider.

## Logs

```text
logs/discovery.log
logs/verification.log
logs/connector.log
```

API keys are not intentionally logged.

## File safety

Existing outputs are not silently overwritten. Timestamped filenames are generated unless `--overwrite` is explicitly supplied.

Example:

```text
verified_ip_ranges_20261005_110000.xlsx
```

## Limitations

1. Internet infrastructure changes quickly; evidence is time-dependent.
2. RIPEstat and RDAP can differ in semantics and update timing.
3. CT proves certificate/name history, not customer ownership.
4. Reverse DNS is operator-controlled and may be generic.
5. Shared CDNs and SaaS platforms require special caution.
6. Historical DNS is represented as `Not Available` unless a configured provider is added; the system does not fabricate historical associations.
7. Official-source inspection is intentionally limited to public material directly reachable from the target domain; it is not a general web search engine.
8. Absence of evidence does not prove that an IP is unrelated.
9. `Owned`, `Leased/Hosted`, and `Operated` are attribution conclusions based on evidence, not legal title determinations.

## Example end-to-end

```powershell
python 01_generate_input.py --input seed_targets.xlsx --output targets.xlsx --json-output targets.json
python 03_connector.py --input targets.xlsx
```

The primary final artifact is:

```text
verified_ip_ranges.xlsx
```

The JSON equivalent is:

```text
verified_ip_ranges.json
```

## Defensive-use note

Use this system only for organizations and infrastructure you are authorized to assess. The objective is external attack-surface inventory and defensible attribution, not intrusive scanning.


## Accuracy and performance improvements

This version is intentionally high-precision for EASM attribution:

- IPv6 is excluded; only public IPv4 candidates are processed.
- Certificate Transparency is context only and is not counted as proof that a certificate was served by the candidate IP.
- Current DNS must be correlated with live TLS before TLS becomes strong direct evidence.
- Cloud/shared hosting is treated as infrastructure context rather than organization ownership.
- Multiple unrelated domains/hostnames on the same IP create a shared-infrastructure penalty.
- Evidence is grouped into independent families so DNS/CT/TLS observations do not inflate confidence as if they were fully independent proofs.
- Historical DNS can be enabled with the optional Censys Platform API credentials. Censys Active DNS provides current and historical DNS relationships; availability/history depends on the account tier.
- The final `EASM Assets` worksheet contains only `CONFIRMED_OWNED`, `CONFIRMED_LEASED`, or `CONFIRMED_OPERATED` results. Lower-confidence candidates remain in `Verified IPs` for review.
- The system remains conservative: a cloud-provider registration is not treated as target ownership.

### Optional Censys configuration

Set `CENSYS_API_TOKEN` and `CENSYS_ORG_ID` in `.env`, or put them in `config.json`. `CENSYS_HISTORY_DAYS` defaults to 31. If credentials are absent, the system continues without historical DNS and explicitly reports it as unavailable.

---

## Atlas EASM desktop application

The primary interface is now a local PySide6 desktop application. The existing command-line scripts remain available for compatibility. The desktop app calls their discovery and verification functions directly; it does not start a web server or shell subprocess for analysis.

### Install and launch on Windows

Install Python 3.12 or newer, then in this repository:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

On Linux/macOS, activate `.venv/bin/activate` and use `python main.py`. A graphical desktop session is required. No administrator rights are needed for normal use.

### Workflow

Open **New Analysis**. Enter a parent organization, target entity, domain, known ASN and optional registrant names, or import an `.xlsx` target file. Multiple values use semicolons. Both paths use the same target validator and canonical ASN normalizer. Each Excel import asks whether to replace the active workspace, append to it, or cancel; replacement is the default. **Clear Workspace** removes only the current targets and temporary view, leaving saved analyses intact. Review the targets and click **Run analysis**. Each parent organization receives its own Qt worker and saved run.

**Running Jobs** shows each organization's status, elapsed time, discovered hostnames, candidates, and verified IPs. Pause, resume, or cancel one job independently. These controls take effect at the next target or candidate boundary; an in-flight network request may finish first. Completed jobs move into **Analysis History**. The **Assets** page begins with a summary and key findings, followed by tabs for EASM Assets, Candidates, Shared Infrastructure, Rejected results, and Evidence. Click an IP to open an inspector beside the table for proof, network details, evidence, and timeline. Search and sort the table or use the separate **Evidence** page. Select a candidate and choose **Reverify selected IP** for fresh evidence in a new run. **Analysis History** reopens prior runs, compares two selected runs, or loads their targets for a retry. **Organizations** groups saved results by parent organization. Excel and JSON are created only by **Export**. The sidebar can collapse, and Settings supports Light, Dark, and System appearance.

A known target ASN is excluded before IP verification and remains visible as `KNOWN_ASN_EXCLUDED`. Only `CONFIRMED_OWNED`, `CONFIRMED_LEASED` and `CONFIRMED_OPERATED` enter EASM Assets. The existing conservative attribution engine determines scores and relationships; the UI displays its results.

Discovery uses current DNS, certificate transparency and public target pages. With optional provider credentials, it also accepts bounded Shodan hostname-search matches and Censys domain-history IPs as **candidates**. These extra sources may find more off-ASN IPs, but a past observation or Shodan match is not proof of present ownership. The engine rechecks origin ASN, current DNS, TLS, RDAP and other independent signals before inclusion. If an unrelated cloud provider owns the registered range while current target DNS and a matching live TLS certificate both exist, that expected hosting registration no longer subtracts from the score. A candidate can still remain unverified when evidence is weak.

Shodan verification already uses its exact-IP endpoint, `GET /shodan/host/{ip}`, for each off-ASN candidate when `SHODAN_API_KEY` is configured. Shodan `ip:` and `net:` are **search filters**; searching a whole network would pull in unrelated customer infrastructure and does not verify target control. The new hostname search uses a single bounded page per target domain and only retains public IPv4 results with an in-scope hostname. Availability depends on the Shodan API plan and credits. Enter the key through **Settings** or a local environment variable. A local `config.json` key also works, but that file is tracked; do not commit a real key to source control.

### Data, credentials and diagnostics

Analysis history is stored in SQLite at `%LOCALAPPDATA%\AtlasEASM\atlas.db` on Windows or `~/.local/share/AtlasEASM/atlas.db` on Unix. Set `EASM_DATA_DIR` to choose another location. A SQLite cache beside the database retains successful public RIPEstat responses for 15 minutes and RDAP/CT responses for one hour. Reverification bypasses that cache. Optional provider credentials use environment variables or **Settings**: `SHODAN_API_KEY`, `CENSYS_API_TOKEN`, `CENSYS_ORG_ID`. Settings writes a local `.env` beside the database; existing values are masked, and environment values take precedence. Protect your local user account and application data directory; credentials are not written to result rows. Without optional credentials, the core pipeline still runs and historical DNS can be unavailable. Network providers, DNS and TLS require outbound access. Per-IP verification errors remain visible in Results as `ERROR`; a failed run is recorded in History.

### Tests and Windows packaging

```powershell
python -m pip install pytest
python -m pytest -q tests
```

Run `build.bat` on Windows to build `dist\AtlasEASM.exe` with PyInstaller. Packaging requires a Windows machine; the Linux cloud environment can validate imports and the Qt launch path but cannot validate a Windows executable.
