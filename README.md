# EASM Off-ASN Discovery and Verification System

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
