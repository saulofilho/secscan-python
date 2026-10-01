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
        description="Chave de acesso pública da AWS encontrada hardcoded no código.",
        remediation="Utilize AWS IAM Roles, variáveis de ambiente ou AWS Secrets Manager.",
        min_entropy=3.5,
    ),
    Rule(
        id="sec-aws-secret",
        name="AWS Secret Access Key",
        pattern=r"""(?:aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]""",
        flags="gi",
        severity="CRITICAL",
        category="CLOUD_CREDENTIAL",
        description="Segredo de autenticação da AWS exposto diretamente.",
        remediation="Rotacione a chave no console da AWS e migre para credenciais temporárias.",
        min_entropy=4.2,
    ),
    Rule(
        id="sec-google-api",
        name="Google Cloud / Gemini API Key",
        pattern=r"\bAIza[-0-9A-Za-z_]{35}\b",
        severity="HIGH",
        category="API_KEY",
        description="Chave de API do Google Cloud ou Gemini exposta no código.",
        remediation="Restrinja a chave no Google Cloud Console ou mova a chamada para o servidor.",
        min_entropy=4.0,
    ),
    Rule(
        id="sec-github-pat",
        name="GitHub Personal Access Token",
        pattern=r"\b(?:ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b",
        severity="CRITICAL",
        category="AUTH_TOKEN",
        description="Token de acesso pessoal do GitHub exposto no repositório.",
        remediation="Revogue o token e armazene o valor como secret do CI.",
        min_entropy=4.1,
    ),
    Rule(
        id="sec-stripe-secret",
        name="Stripe Secret API Key",
        pattern=r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b",
        severity="CRITICAL",
        category="API_KEY",
        description="Chave secreta ou restrita do Stripe exposta.",
        remediation="Rotacione a chave no painel do Stripe. Não envie chaves secretas ao frontend.",
        min_entropy=4.0,
    ),
    Rule(
        id="sec-jwt-token",
        name="JSON Web Token (JWT)",
        pattern=r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b",
        severity="HIGH",
        category="AUTH_TOKEN",
        description="Token JWT estático embutido no código-fonte.",
        remediation="Substitua tokens estáticos por um fluxo de autenticação.",
        min_entropy=4.3,
    ),
    Rule(
        id="sec-slack-webhook",
        name="Slack Incoming Webhook / Bot Token",
        pattern=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        severity="HIGH",
        category="AUTH_TOKEN",
        description="URL de webhook do Slack ou token de bot hardcoded.",
        remediation="Mova a URL ou o token para uma variável de ambiente.",
        min_entropy=3.8,
    ),
    Rule(
        id="sec-private-key",
        name="RSA / OpenSSH Private Key",
        pattern=r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----[\s\S]*?-----END (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----",
        severity="CRITICAL",
        category="PRIVATE_KEY",
        description="Chave criptográfica privada encontrada embutida no arquivo.",
        remediation="Remova a chave do controle de versão e carregue-a por um cofre ou agent.",
    ),
    Rule(
        id="sec-db-uri",
        name="Database Connection URI with Credentials",
        pattern=r"""(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s:"']+:[^\s:"']+@[^\s:"']+""",
        flags="gi",
        severity="CRITICAL",
        category="DATABASE_URI",
        description="String de conexão com usuário e senha em texto claro.",
        remediation="Extraia as credenciais para uma variável de ambiente.",
    ),
    Rule(
        id="sec-hardcoded-pass",
        name="Hardcoded Password Assignment",
        pattern=r"""(?:password|passwd|pwd|db_pass|secret_key|client_secret)\s*[:=]\s*['"][^'"]{8,64}['"]""",
        flags="gi",
        severity="HIGH",
        category="PASSWORD",
        description="Atribuição de senha ou chave secreta fixa no código.",
        remediation="Injete o valor em tempo de execução por variável de ambiente.",
        min_entropy=3.2,
    ),
    Rule(
        id="sec-openai-key",
        name="OpenAI API Secret Key",
        pattern=r"\bsk-(?:proj-|live-)?[-_a-zA-Z0-9]{32,80}\b",
        severity="CRITICAL",
        category="API_KEY",
        description="Chave secreta de API da OpenAI encontrada no código.",
        remediation="Revogue a chave e mantenha-a apenas no servidor.",
        min_entropy=4.1,
    ),
    Rule(
        id="sec-sendgrid-key",
        name="SendGrid API Key",
        pattern=r"\bSG\.[-0-9A-Za-z_]{22}\.[-0-9A-Za-z_]{43}\b",
        severity="HIGH",
        category="API_KEY",
        description="Chave de envio de e-mails do SendGrid exposta.",
        remediation="Rotacione a chave e mova o valor para o ambiente do backend.",
        min_entropy=4.0,
    ),
    Rule(
        id="sec-sensitive-api-path",
        name="Sensitive or Admin API Route",
        pattern=r"""['"](?:/api/v[0-9]+)?/(?:admin|internal|superadmin|debug|actuator|metrics|management|auth/token|users/export|billing/charge)[^\s'"]*['"]""",
        flags="gi",
        severity="MEDIUM",
        category="API_PATH",
        description="Rota de API administrativa ou sensível mapeada no código.",
        remediation="Exija autorização na rota e evite publicá-la em bundles sem controle de acesso.",
    ),
    Rule(
        id="sec-api-endpoint",
        name="Hardcoded API Path / Endpoint",
        pattern=r"""['"](?:https?://[-.a-zA-Z0-9]+)?/(?:api|v1|v2|graphql|rest|webhook)/[-./_a-zA-Z0-9]+['"]""",
        flags="gi",
        severity="LOW",
        category="API_PATH",
        description="Endpoint ou caminho de API fixo no código.",
        remediation="Use uma URL base configurável por ambiente.",
    ),
)
