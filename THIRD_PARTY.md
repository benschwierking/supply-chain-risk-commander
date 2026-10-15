# Contributor research attribution

The contributor_lens modules originate from:
https://github.com/rockangator/tavily-contributor-research-demo
Revision: 3b0b945370f6cf9be8aab0d6982c692d15d2e53b

The user explicitly confirmed permission to incorporate this code into HEPHAESTUS on October 15, 2026. Upstream does not declare a license; this acknowledgement does not grant downstream recipients additional rights or assign a new license to upstream code.

Local adaptation: Tavily search failures preserve successful results, use sanitized messages, and report partial status. The HEPHAESTUS research adapter uses bounded requests, excludes internal priority/identity-confidence scores and demographics from user-facing assessments, and does not invoke upstream report persistence. Upstream modules retain their original scoring implementation for traceability; HEPHAESTUS does not call that scoring pipeline.
