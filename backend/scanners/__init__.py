from .gitleaks import Gitleaks
from .njsscan import Njsscan
from .osv_scanner import OsvScanner
from .retirejs import RetireJs
from .semgrep import Semgrep

# Pipeline order (§3): secrets -> dependencies -> static analysis. Trivy is dropped for Render (§22).
# Classes, not instances: each scan gets fresh ones, so per-run state (like `checked`) never leaks between scans.
ALL = [Gitleaks, OsvScanner, RetireJs, Semgrep, Njsscan]
