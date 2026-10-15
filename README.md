# Supply Chain Risk Commander

A component exposure assessment tool. Import an SPDX 2.x or CycloneDX JSON SBOM, inspect GitHub contributor and governance observations, model controls, and export an auditable risk sidecar. Runs without tokens, network, or an LLM in the clearly labeled synthetic scenario.

## Quick start

Python 3.11–3.13 recommended. From this project directory:

```sh
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501. Optional: set `GITHUB_TOKEN` or enter a token in the sidebar. Public endpoints work without credentials within GitHub limits. No database or paid service is required. Data stays in Streamlit session memory; export before ending a session. Install requires internet; the offline demo does not after installation.

```sh
python -m pytest -q
```

## Two-minute demonstration

- **0:00–0:20** Start in Offline scenario. State plainly: all observations are synthetic; project links are inventory mappings, not supporting findings. Show six components and the mission/exposure matrix.
- **0:20–0:45** Select Requests, raise mission criticality and reach. Explain horizontal impact versus vertical observed contributor/governance exposure. Completeness measures coverage, not certainty.
- **0:45–1:10** Select independent human review and primary-branch safeguards. Show the diamond moving down while impact stays fixed. These are modeled assumptions; no repository was changed.
- **1:10–1:30** Open the Evidence tab and Method tab. Show weighted drivers, unknown handling, policy sources, and the unverified identity/attestation guardrail.
- **1:30–1:50** Optionally switch to Live GitHub, fetch one component, and show timestamped API URLs. If the network fails, unknown stays unknown. Do not depend on live access for judging.
- **1:50–2:00** Export JSON and the concise report. Point to the enterprise adoption policy below.

## Evidence and model

Mission impact = 100 × sum of three analyst inputs / 15. Inputs each range 1–5. Defaults are illustrative, not mission facts. Exposure = 100 × weighted sum of known factors / known weights. Weights: concentration 30; archived 15; direct-commit safeguard gap 30; review gap 25. Missing factors are excluded and visibly reduce completeness. All-unknown components are unscored and omitted from the chart, available via the selector.

GitHub evidence is repository-level and current at retrieval, not release-specific. Contributor concentration uses the largest commit count divided by counts in the first 100 contributor records, includes bots, and may be truncated/cached. It is not privilege concentration, identity verification, or maliciousness. An archive flag measures lifecycle context, not a vulnerability. A protected branch flag alone does not establish direct-commit prevention, so live branch exposure stays unknown. Review settings are partial evidence and may be bypassed. Mapping a package to a repository is unverified SBOM input. No vulnerability scanning, malware detection, or provenance verification is claimed.

Residual exposure applies illustrative factor discounts: review 65%; direct-commit prevention 75%; documented privileged-member responsibilities 20% to the concentration driver. The last is a continuity-planning assumption and does not change actual commit concentration. These are not calibrated estimates or compliance results. Effects do not stack within a factor or increase completeness. Quadrants use a visual 50-point divider with no validated acceptance threshold. Compare components with different coverage cautiously.

Optional Scorecard data is contextual only and excluded from scoring; unknown or failed checks do not imply a finding. deps.dev and LLM integration are intentionally omitted to keep the demo reliable.

## Enterprise adoption policy (proposed, requires organization approval)

1. Assign each component a mission owner. Validate package-to-repository mapping against publisher records and release provenance. Preserve the original SBOM hash with each assessment.
2. Record retrieval time and source endpoints. Review partial, stale, conflicting, or missing observations before a deployment decision. Never auto-approve a component on a low exposure index; the index is not an acceptance threshold.
3. Request evidence of primary-branch direct-commit prevention (OSPS-AC-03.01), independent non-author human review (OSPS-QA-07.01), and privileged-member roles (OSPS-GV-01.01/02). A selected simulation control is a plan, not proof. Store implementation evidence and an accountable reviewer separately.
4. Contributor assessment concerns observable activity, review boundaries, and privileges. U.S. Person status remains unverified until an authorized process obtains and validates explicit attestation under applicable organizational policy. Names, language, location, ethnicity and profile proxies must never determine status or malicious intent. Keep attestation records in an authorized system, outside this public-evidence sidecar.
5. Require mission-owner disposition for high-impact components with missing evidence: verify safeguards, isolate usage, plan replacement, or document a time-bounded exception and owner. Reassess after material contributor, governance, release or mission changes.
6. Extend collection with verified Sigstore attestations, SLSA provenance and GUAC relationships when production adoption justifies it. They are integration opportunities, not implemented capabilities.

## Sources and compatibility

- [OSPS Baseline v2026.08.28](https://baseline.openssf.org/versions/2026-08-28): selected guidance; this app is not a baseline compliance scanner.
- [GitHub repository/contributors REST API](https://docs.github.com/en/rest/repos/repos): pinned supported API version 2022-11-28; GET requests only, 10-second timeout each; protection may require additional privileges. API status codes preserved, tokens omitted. No requests to SBOM-supplied hosts.
- [Streamlit Plotly selection](https://docs.streamlit.io/develop/api-reference/charts/st.plotly_chart): scatter selection with `on_select="rerun"`, plus an accessible component selector.
- [OpenSSF Scorecard API](https://api.securityscorecards.dev): optional snapshot with its own date and coverage.

Pinned runtime dependencies in requirements.txt. Tests cover both parsers, nested/duplicate inventory, invalid input, mapping boundaries, deterministic scoring, unknown handling, mitigations, JSON/report export, and mocked GitHub failures/partial responses. The app supports SPDX 2.x package inventories, not SPDX 3 graphs. It normalizes CycloneDX nested components; it does not validate the entire SBOM schema or resolve dependency reachability. Mission reach is an analyst input. Inventory limit: 1,000 components; JSON upload limit: 10 MB. Local trusted use is the MVP deployment model.
