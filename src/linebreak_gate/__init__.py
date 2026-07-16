"""linebreak-gate — LineBreak's security gate, shared by the desktop app and CI.

The canonical home of the scanner core that previously lived inside the desktop
backend (``apps/desktop/backend/app``):

* :mod:`linebreak_gate.security_scan` — dependency CVE scanning (osv-scanner
  preferred, npm-audit fallback), pure parsing, fail-closed semantics.
* :mod:`linebreak_gate.code_scan` — AI SAST over first-party source with
  adversarial verification (injectable ``discover``/``verify``).
* :mod:`linebreak_gate.security_artifact` — the versioned, git-native security
  artifact (findings + approval trail) both surfaces read and write.
* :mod:`linebreak_gate.entitlements` — the provider-agnostic entitlements
  contract (Decision/Verdict/protocol) and the permissive ``open`` provider.

The desktop backend imports these via thin shims (``app/security_scan.py`` et
al. replace themselves with these modules), so there is exactly ONE
implementation — no fork of scanner logic between the in-app gate and the CI
gate. The CI-facing pieces (``gate_config``, ``verdict``, ``cli``) live only
here and are consumed via the ``linebreak-gate`` console script.
"""

__version__ = "1.8.0"
