from .bandit import Bandit
from .custom_rules import VibeRules
from .gitleaks import Gitleaks
from .lockfile_lint import LockfileLint
from .njsscan import Njsscan
from .osv_scanner import OsvScanner
from .retirejs import RetireJs
from .semgrep import Semgrep
from .trufflehog import TruffleHog
from .zizmor import Zizmor

# Pipeline order (§3): secrets -> dependencies -> static analysis -> our own rules. Trivy is dropped for Render (§22).
# Classes, not instances: each scan gets fresh ones, so per-run state (like `checked`) never leaks between scans.
ALL = [Gitleaks, TruffleHog, OsvScanner, LockfileLint, RetireJs, Semgrep, Bandit, Njsscan, Zizmor, VibeRules]
