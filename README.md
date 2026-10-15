# HEPHAESTUS

HEPHAESTUS helps you review the open-source components in a software bill of materials (SBOM), examine public repository and contributor sources, and compare proposed safeguards against the consequences of a component failing in your operation.

It supports SPDX 2.x JSON, SPDX 3 JSON-LD graphs, and CycloneDX JSON inventories. It runs locally and includes a fictional offline scenario for learning. It does not detect malicious contributors or calculate a probability of compromise.

## Quick start

Use Python 3.11–3.13. Open a terminal in the downloaded project folder. On Ubuntu/Debian, first install virtual-environment support:

```sh
sudo apt update
sudo apt install python3-venv
```

On macOS, install Python with its `venv` module if needed. Then, on either system:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m streamlit run app.py
```

Open http://localhost:8501 on the computer running the app. To stop it, press Ctrl+C in that terminal. To start it again, run the last command from the same folder.

If pip reports **externally managed environment**, use the `.venv/bin/python -m pip` command above. Avoid `sudo pip` and `--break-system-packages`. If `ensurepip` is missing, install `python3-venv` or the matching version package, such as `python3.12-venv`. Create a new environment on each device; do not copy `.venv` between computers.

## Your first assessment

1. **Choose an inventory.** Start with a bundled sample or upload a JSON SBOM. Nested CycloneDX components are included. SPDX 3 graphs include Software Package nodes; files, agents, and relationships are not counted as components. Compact terms, expanded Core/Software IRIs, inline namespace prefixes, and locally linked external references are supported. Remote contexts and graph nodes are never fetched; unresolved or conflicting repository mappings stay unknown. This is an inventory reader, not a full RDF reasoner or SPDX schema validator. Files are limited to 10 MB and inventories to 1,000 components.
2. **Verify mappings.** Open Inventory & repository mapping. Confirm that each package points to its actual upstream GitHub repository. A URL supplied in an SBOM is not independent evidence of that relationship. Unmapped packages remain available but cannot be researched automatically.
3. **Choose evidence.** Offline scenario uses fictional observations for bundled samples. Uploaded inventories start unknown. Live GitHub collects current public repository observations. The optional GitHub token can increase API allowance and may permit more branch-setting evidence. Public endpoints can work without it.
4. **Review and run research.** Select up to five repositories and 1–3 contributors each. Run research explicitly. GitHub observations are collected for scoring; if a Tavily key is supplied, two public-source searches run per contributor, at most 30 per run. Fewer contributors may be available. Deep extraction is off. Cached scopes are reused; Retry failed research reruns only partial or failed scopes. Retrying may consume additional searches. Research can take several minutes; progress is shown and requests have timeouts.
5. **Inspect and set consequences.** Select a component using the selector or matrix. In Live GitHub, Fetch evidence also collects governance observations for just that component. Set operational criticality, deployment reach, and recovery difficulty using their information icons for 1–5 scale definitions.
6. **Review sources and proposed controls.** Examine Evidence and Method before interpreting the matrix. Controls are what-if assumptions, not upstream changes or implementation evidence.
7. **Finish assessment.** Review the all-component summary, then download a PDF report and JSON sidecar. Unknown observations do not prevent reporting. The original SBOM is unchanged.

Use Tutorial under More Information for guidance beside the working controls. Next advances the highlighted box; Exit tutorial asks for confirmation. Tutorial navigation does not run research. README opens this guide; Back to assessment restores the assessment. The Show/Hide sidebar button remains available at the top left.

## Connections and privacy

The sidebar accepts a GitHub token, Tavily API key, and optional Tavily project ID. You can instead set `GITHUB_TOKEN`, `TAVILY_API_KEY`, and `TAVILY_PROJECT_ID` in the environment before starting the app. Do not commit secrets into source files.

Credentials stay in session or the process environment and are excluded from exports. Clicking Run research sends public contributor names/handles and repository identifiers to Tavily. It does not send your full SBOM or mission inputs. GitHub requests use mapped repository identifiers and public contributor accounts. No requests are made merely because a file was uploaded.

Assessments and research results stay in session memory, not a database. Export before ending the session. Changing the inventory or evidence mode starts a new assessment context. No Tavily key is needed for GitHub collection or offline use. Without network access, live observations remain unknown; the offline sample remains usable after dependencies are installed.

## How the assessment works

These are explainable decision-support indices, not validated predictions. The model weights and control discounts are design assumptions, not a scientific estimate of attack likelihood.

### Sources used

- **SBOM input:** component name, version, identifiers, and repository references. Package-to-repository mappings are unverified. Dependency reachability is not resolved; deployment reach is your input.
- **GitHub REST:** repository archive state, default branch context, available review settings, and the first page of up to 100 contributor records. Contributor concentration is the largest recorded commit share in that returned sample. Records may be cached or truncated, include bots, and describe history rather than present maintainer privileges. A protected flag alone does not prove prevention of direct commits; that scored safeguard stays unknown in live collection. Review settings may have bypasses and do not establish every independent-review requirement.
- **Tavily contributor research:** the approved Contributor Lens modules build two queries from the public GitHub identity and repository, then filter results with heuristic identity matching. Weak matches are discarded; retained sources are labeled heuristic exact or probable and require human confirmation. A search relevance value is not identity certainty. No retained matches is not a negative finding. Failed searches are visibly incomplete. LinkedIn is excluded, deep extraction is disabled, and no generated answer or LLM is required. These results supply context only: they do not change exposure or evidence completeness. Named non-bot research contributors differ from the broader scoring sample.
- **Optional OpenSSF Scorecard:** a separate repository snapshot for context. Its checks are not included in this model's scores.
- **OSPS Baseline v2026.08.28:** guidance for proposed safeguards, not a claim of compliance. The app links selected controls to independent human review, primary-branch protection, and documented privileged-member roles.

All live observations describe the repository at retrieval, not necessarily the exact package release in the SBOM. Verify source identity, package mapping, and release provenance before relying on findings.

### Formulas and scales

**Mission impact** = 100 × (operational criticality + deployment reach + recovery difficulty) / 15. Each input ranges 1–5, so impact ranges 20–100. Default 3 values are starting assumptions to review, not mission facts.

**Observed exposure** = 100 × sum(weight × observed factor) / sum(known weights). Factors range 0–1. Weights: contributor concentration 30, archived repository 15, direct-commit safeguard gap 30, and review-setting gap 25. Archived is 1 when archived and 0 otherwise. Safeguard gaps are 1 for an observed gap, 0 for an observed safeguard. Unknown factors are excluded, never treated as zero. With no observations, exposure is Unknown.

**Evidence completeness** = sum of the known factor weights, expressed as a percentage. It measures model coverage, not truth or statistical confidence. A low observed score with missing evidence cannot establish low overall exposure.

**Modeled residual** applies illustrative discounts to selected drivers using the same denominator: independent review 65%, prevention of direct commits 75%, and documented privileged-member responsibilities 20% on the concentration driver. Documenting roles does not change actual commit concentration; its discount is an uncalibrated continuity-planning assumption. Effects do not stack within a driver or increase completeness. Selecting a control does not implement it, verify it, or prove compliance.

In the matrix, circles are baseline and diamonds are modeled residual. Point size reflects completeness. Components with no scored observations are omitted from the chart but remain selectable. The 50-point quadrant dividers are visual guides, not validated acceptance thresholds. Compare components with attention to differences in evidence coverage.

### What the results cannot establish

The app does not infer malicious intent, nationality, citizenship, immigration status, or U.S. Person status. Names, location, language, ethnicity, company, or public-profile absence must not be used as proxies. Status remains unverified until an authorized process validates explicit attestation. Maintain those records in an authorized system outside this public-evidence report.

No vulnerability scan, malware detection, release-provenance verification, or baseline compliance audit is claimed. Before accepting a component, verify missing evidence and obtain mission-owner review. Record an owner and expiry for any exception. Reassess after material release, governance, or operational changes.

## Downloading the assessment

Finish assessment opens the report view even when evidence is incomplete. The **PDF report** includes every component, mission inputs, drivers, source links, research status, limitations, and proposed controls. The **JSON sidecar** preserves structured evidence, source timestamps and queries, component/repository associations, the SBOM SHA-256, model version, and pinned research revision. Credentials are excluded. Clearly labeled synthetic values are not findings about the linked projects.

## Updating an installed copy

Stop the app with Ctrl+C. If you cloned the GitHub repository, run these commands from the checkout:

```sh
git pull --ff-only
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m streamlit run app.py
```

If Git reports local changes or diverged history, stop and preserve your changes with a commit or a backup before resolving the conflict. Do not use a hard reset or delete changes to force the update. Export any session assessment before restarting.

If you installed from a ZIP, download the latest source into a **new folder**, create a fresh `.venv`, install requirements, and start the app from that new folder. Keep the previous folder until the update works. Do not overwrite a running installation or copy its `.venv`. Re-enter session credentials or keep using your environment variables.

## References and validation

- [SPDX 3.0.1 JSON-LD serialization](https://spdx.github.io/spdx-spec/v3.0.1/serializations/)
- [GitHub REST repository API](https://docs.github.com/en/rest/repos/repos)
- [Tavily Search API](https://docs.tavily.com/documentation/api-reference/endpoint/search)
- [Contributor research source](https://github.com/rockangator/tavily-contributor-research-demo) at revision `3b0b945370f6cf9be8aab0d6982c692d15d2e53b`; attribution and approved reuse are documented in THIRD_PARTY.md.
- [OpenSSF OSPS Baseline v2026.08.28](https://baseline.openssf.org/versions/2026-08-28)
- [Python virtual-environment guidance](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)

Run automated checks with `.venv/bin/python -m pytest -q`. Tests use local fixtures/fakes and do not consume Tavily credits. Pinned dependencies are in requirements.txt. Local trusted use is the supported deployment model.
