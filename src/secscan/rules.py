"""Built-in secret and API-path rules ported from the SecScan SAST engine."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_BASE_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 14,
    "MEDIUM": 7,
    "LOW": 3,
    "INFO": 1,
}

FILE_CRITICALITY_MULTIPLIERS = {
    "CRITICAL": 2.0,
    "HIGH": 1.5,
    "MEDIUM": 1.0,
    "LOW": 0.5,
}


@dataclass(frozen=True)
class Rule:
    """One detection rule. ``pattern`` is a JavaScript-style regular expression."""

    id: str
    name: str
    pattern: str
    severity: str
    category: str
    description: str
    remediation: str = ""
    flags: str = "g"
    min_entropy: float | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        severity = self.severity.upper()
        if severity not in SEVERITY_RANK:
            raise ValueError(f"invalid severity {self.severity!r} on rule {self.id}")
        if severity != self.severity:
            object.__setattr__(self, "severity", severity)


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        id="sec-aws-akid",
        name="AWS Access Key ID",
        pattern=r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
        severity="CRITICAL",
        category="CLOUD_CREDENTIAL",
        description="AWS public access key hardcoded in source.",
        remediation="Use IAM roles, environment variables, or AWS Secrets Manager.",
        min_entropy=3.5,
    ),
    Rule(
        id="sec-aws-secret",
        name="AWS Secret Access Key",
        pattern=r"""(?:aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]""",
        flags="gi",
        severity="CRITICAL",
        category="CLOUD_CREDENTIAL",
        description="AWS authentication secret exposed in source.",
        remediation="Rotate the key in the AWS console and switch to temporary credentials.",
        min_entropy=4.2,
    ),
    Rule(
        id="sec-google-api",
        name="Google Cloud / Gemini API Key",
        pattern=r"\bAIza[-0-9A-Za-z_]{35}\b",
        severity="HIGH",
        category="API_KEY",
        description="Google Cloud or Gemini API key exposed in source.",
        remediation="Restrict the key in Google Cloud Console or move the call to the server.",
        min_entropy=4.0,
    ),
    Rule(
        id="sec-github-pat",
        name="GitHub Personal Access Token",
        pattern=r"\b(?:ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b",
        severity="CRITICAL",
        category="AUTH_TOKEN",
        description="GitHub personal access token exposed in the repository.",
        remediation="Revoke the token and store the value as a CI secret.",
        min_entropy=4.1,
    ),
    Rule(
        id="sec-stripe-secret",
        name="Stripe Secret API Key",
        pattern=r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b",
        severity="CRITICAL",
        category="API_KEY",
        description="Stripe secret or restricted key exposed.",
        remediation="Rotate the key in the Stripe dashboard. Do not ship secret keys to the frontend.",
        min_entropy=4.0,
    ),
    Rule(
        id="sec-jwt-token",
        name="JSON Web Token (JWT)",
        pattern=r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b",
        severity="HIGH",
        category="AUTH_TOKEN",
        description="Static JWT embedded in source.",
        remediation="Replace static tokens with an authentication flow.",
        min_entropy=4.3,
    ),
    Rule(
        id="sec-slack-webhook",
        name="Slack Incoming Webhook / Bot Token",
        pattern=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        severity="HIGH",
        category="AUTH_TOKEN",
        description="Slack webhook URL or bot token hardcoded.",
        remediation="Move the URL or token to an environment variable.",
        min_entropy=3.8,
    ),
    Rule(
        id="sec-private-key",
        name="RSA / OpenSSH Private Key",
        pattern=r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----[\s\S]*?-----END (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----",
        severity="CRITICAL",
        category="PRIVATE_KEY",
        description="Private cryptographic key embedded in the file.",
        remediation="Remove the key from version control and load it from a vault or agent.",
    ),
    Rule(
        id="sec-db-uri",
        name="Database Connection URI with Credentials",
        pattern=r"""(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s:"']+:[^\s:"']+@[^\s:"']+""",
        flags="gi",
        severity="CRITICAL",
        category="DATABASE_URI",
        description="Connection string with username and password in clear text.",
        remediation="Move credentials to an environment variable.",
    ),
    Rule(
        id="sec-hardcoded-pass",
        name="Hardcoded Password Assignment",
        pattern=r"""(?:password|passwd|pwd|db_pass|secret_key|client_secret)\s*[:=]\s*['"][^'"]{8,64}['"]""",
        flags="gi",
        severity="HIGH",
        category="PASSWORD",
        description="Hardcoded password or secret key assignment.",
        remediation="Inject the value at runtime from an environment variable.",
        min_entropy=3.2,
    ),
    Rule(
        id="sec-openai-key",
        name="OpenAI API Secret Key",
        pattern=r"\bsk-(?:proj-|live-)?[-_a-zA-Z0-9]{32,80}\b",
        severity="CRITICAL",
        category="API_KEY",
        description="OpenAI API secret key found in source.",
        remediation="Revoke the key and keep it only on the server.",
        min_entropy=4.1,
    ),
    Rule(
        id="sec-sendgrid-key",
        name="SendGrid API Key",
        pattern=r"\bSG\.[-0-9A-Za-z_]{22}\.[-0-9A-Za-z_]{43}\b",
        severity="HIGH",
        category="API_KEY",
        description="SendGrid email API key exposed.",
        remediation="Rotate the key and keep the value in the backend environment.",
        min_entropy=4.0,
    ),
    Rule(
        id="sec-sensitive-api-path",
        name="Sensitive or Admin API Route",
        pattern=r"""['"](?:/api/v[0-9]+)?/(?:admin|internal|superadmin|debug|actuator|metrics|management|auth/token|users/export|billing/charge)[^\s'"]*['"]""",
        flags="gi",
        severity="MEDIUM",
        category="API_PATH",
        description="Administrative or sensitive API route mapped in source.",
        remediation="Require authorization on the route and do not ship it in public bundles without access control.",
    ),
    Rule(
        id="sec-api-endpoint",
        name="Hardcoded API Path / Endpoint",
        pattern=r"""['"](?:https?://[-.a-zA-Z0-9]+)?/(?:api|v1|v2|graphql|rest|webhook)/[-./_a-zA-Z0-9]+['"]""",
        flags="gi",
        severity="LOW",
        category="API_PATH",
        description="Hardcoded API endpoint or path.",
        remediation="Use a configurable base URL per environment.",
    ),
)
