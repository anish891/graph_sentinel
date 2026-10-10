"""Application configuration.

All settings come from environment variables (optionally a local `.env`). Secrets are
held in `SecretStr` so they are never rendered by `repr()`, logs, or API responses.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


class ConfigIssue(BaseModel):
    """A configuration problem, described without revealing any secret value."""

    setting: str
    severity: Literal["error", "warning", "info"]
    message: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(REPO_ROOT / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- application -----------------------------------------------------
    app_env: Literal["development", "test", "demo", "production"] = "development"
    demo_mode: bool = True
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:8080"]
    )

    # ---- auth --------------------------------------------------------------
    auth_mode: Literal["demo", "oidc"] = "demo"
    auth_secret_key: SecretStr | None = None
    session_ttl_minutes: int = Field(default=480, ge=5, le=24 * 60)
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_roles_claim: str = "roles"
    default_tenant: str = Field(default="acme", pattern=r"^[a-z0-9][a-z0-9-]{1,31}$")
    # Multi-tenant operation is NOT implemented beyond a tenant property filter;
    # production refuses to start with this enabled.
    multi_tenant: bool = False

    # ---- FalkorDB ------------------------------------------------------------
    falkordb_host: str = "localhost"
    falkordb_port: int = 6379
    falkordb_username: str | None = None
    falkordb_password: SecretStr | None = None
    falkordb_graph_name: str = Field(default="graphsentinel", pattern=r"^[A-Za-z0-9_\-]{1,64}$")
    falkordb_query_timeout_ms: int = Field(default=5000, ge=100, le=30000)
    falkordb_max_connections: int = Field(default=32, ge=2, le=256)

    # ---- relational metadata ---------------------------------------------------
    sqlite_path: str = "./data/runtime/graphsentinel.db"
    synthetic_data_dir: str = str(REPO_ROOT / "data" / "synthetic")

    # ---- LLM -------------------------------------------------------------------
    # auto = Azure if fully configured, else Groq if configured, else mock (demo/test only)
    llm_provider: Literal["auto", "azure", "groq", "mock"] = "auto"
    azure_openai_api_key: SecretStr | None = None
    azure_openai_endpoint: str | None = None
    azure_openai_api_version: str = "v1"
    azure_openai_deployment: str | None = None
    azure_openai_api_mode: Literal["auto", "responses", "chat"] = "auto"
    groq_api_key: SecretStr | None = None
    # qwen/qwen3.8-27b completed full investigations in live testing; openai/gpt-oss-* on Groq repeatedly
    # failed the final step by calling a non-existent "commentary" tool (harmony-format channel leak).
    groq_model: str = "qwen/qwen3.8-27b"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    # Free-tier per-minute token limits are small; Groq rejects oversized requests (HTTP 413).
    groq_tool_output_max_chars: int = Field(default=1500, ge=300, le=20000)
    # Groq counts requested output tokens against the per-minute budget; tool-call turns are short.
    groq_max_output_tokens: int = Field(default=1000, ge=200, le=8000)
    # Sent only to reasoning models that accept it (openai/gpt-oss-*); fewer reasoning tokens per turn.
    groq_reasoning_effort: Literal["low", "medium", "high"] = "low"
    llm_timeout_seconds: float = Field(default=45, gt=0, le=300)
    llm_max_retries: int = Field(default=3, ge=0, le=8)
    llm_max_output_tokens: int = Field(default=1500, ge=100, le=16000)
    # Rate limits (HTTP 429) get their own retry budget and wait for the server-provided reset time.
    llm_rate_limit_max_retries: int = Field(default=10, ge=0, le=30)
    llm_rate_limit_max_wait_seconds: float = Field(default=65, gt=0, le=300)

    # ---- agent limits --------------------------------------------------------------
    agent_max_steps: int = Field(default=12, ge=1, le=50)
    agent_max_tool_calls: int = Field(default=12, ge=1, le=50)
    agent_max_traversal_depth: int = Field(default=5, ge=1, le=6)
    agent_tool_timeout_seconds: float = Field(default=10, gt=0, le=60)
    # Generous enough for rate-limited free-tier LLMs (a 10-step investigation ≈ 3-6 minutes on Groq free tier).
    agent_investigation_timeout_seconds: float = Field(default=480, gt=0, le=1800)
    agent_token_budget: int = Field(default=80000, ge=1000)
    agent_max_concurrent_investigations: int = Field(default=4, ge=1, le=64)
    agent_require_approval: bool = True

    # ---- actions ---------------------------------------------------------------------
    action_approval_ttl_hours: int = Field(default=24, ge=1, le=24 * 14)
    # Real executors are not implemented. This flag exists so that the setting is
    # explicit; any value other than True fails validation.
    simulation_only: bool = True

    # ---- risk -----------------------------------------------------------------------
    risk_weights_file: str | None = None

    # ---- HTTP hardening ----------------------------------------------------------------
    rate_limit_per_minute: int = Field(default=240, ge=10)
    max_request_bytes: int = Field(default=65536, ge=1024, le=10 * 1024 * 1024)

    # ---- observability -------------------------------------------------------------------
    otel_exporter_otlp_endpoint: str | None = None

    # ---- MCP ----------------------------------------------------------------------------
    mcp_principal_role: Literal["viewer", "investigator"] = "viewer"
    mcp_enable_write_tools: bool = False

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [o.strip() for o in value.split(",") if o.strip()]
        return value

    @field_validator(
        "azure_openai_endpoint",
        "azure_openai_deployment",
        "oidc_issuer",
        "oidc_audience",
        "oidc_jwks_url",
        "falkordb_username",
        "otel_exporter_otlp_endpoint",
        "risk_weights_file",
        mode="before",
    )
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("azure_openai_api_key", "groq_api_key", "falkordb_password", "auth_secret_key", mode="before")
    @classmethod
    def _blank_secret_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode="after")
    def _hard_rules(self) -> Settings:
        if not self.simulation_only:
            raise ValueError("SIMULATION_ONLY=false is not supported: no real response executors are implemented.")
        if self.app_env == "production":
            problems = []
            if self.demo_mode:
                problems.append("DEMO_MODE must be false in production")
            if self.auth_mode != "oidc":
                problems.append("AUTH_MODE must be 'oidc' in production (demo auth is not real auth)")
            if self.multi_tenant:
                problems.append("MULTI_TENANT is not supported in production (tenant isolation incomplete)")
            if self.llm_provider == "mock":
                problems.append("LLM_PROVIDER=mock is not allowed in production")
            if "*" in self.cors_origins:
                problems.append("CORS_ORIGINS must not contain '*' in production")
            if problems:
                raise ValueError("Invalid production configuration: " + "; ".join(problems))
        return self

    # ---- derived ---------------------------------------------------------------------------
    @property
    def azure_configured(self) -> bool:
        return bool(self.azure_openai_api_key and self.azure_openai_endpoint and self.azure_openai_deployment)

    @property
    def groq_configured(self) -> bool:
        return self.groq_api_key is not None

    @property
    def effective_llm_provider(self) -> Literal["azure", "groq", "mock", "unavailable"]:
        if self.llm_provider == "mock":
            return "mock" if self.demo_mode or self.app_env == "test" else "unavailable"
        if self.llm_provider == "azure":
            return "azure" if self.azure_configured else "unavailable"
        if self.llm_provider == "groq":
            return "groq" if self.groq_configured else "unavailable"
        if self.azure_configured:
            return "azure"
        if self.groq_configured:
            return "groq"
        return "mock" if self.demo_mode or self.app_env == "test" else "unavailable"

    def config_issues(self) -> list[ConfigIssue]:
        """Human-readable configuration diagnostics. Never includes secret values."""
        issues: list[ConfigIssue] = []
        if self.auth_mode == "demo":
            issues.append(
                ConfigIssue(
                    setting="AUTH_MODE",
                    severity="warning",
                    message="Demo authentication is active. It is NOT production authentication.",
                )
            )
            if self.auth_secret_key is None:
                issues.append(
                    ConfigIssue(
                        setting="AUTH_SECRET_KEY",
                        severity="warning",
                        message="Not set; an ephemeral key is generated at startup (sessions reset on restart).",
                    )
                )
        if self.auth_mode == "oidc" and not (self.oidc_issuer and self.oidc_audience and self.oidc_jwks_url):
            issues.append(
                ConfigIssue(
                    setting="OIDC_*",
                    severity="error",
                    message="OIDC_ISSUER, OIDC_AUDIENCE and OIDC_JWKS_URL are required.",
                )
            )
        if self.falkordb_password is None:
            issues.append(
                ConfigIssue(setting="FALKORDB_PASSWORD", severity="warning", message="No FalkorDB password configured.")
            )
        missing = [
            name
            for name, val in (
                ("AZURE_OPENAI_API_KEY", self.azure_openai_api_key),
                ("AZURE_OPENAI_ENDPOINT", self.azure_openai_endpoint),
                ("AZURE_OPENAI_DEPLOYMENT", self.azure_openai_deployment),
            )
            if not val
        ]
        # Warn only when Azure is requested or partially configured (some values set, some missing).
        if missing and (self.llm_provider == "azure" or len(missing) < 3):
            sev: Literal["error", "info", "warning"] = "error" if self.llm_provider == "azure" else "warning"
            issues.append(
                ConfigIssue(
                    setting="AZURE_OPENAI_*",
                    severity=sev,
                    message=f"Azure OpenAI not fully configured (missing: {', '.join(missing)}); it is not used.",
                )
            )
        if self.azure_openai_endpoint and not self.azure_openai_endpoint.startswith("https://"):
            issues.append(
                ConfigIssue(
                    setting="AZURE_OPENAI_ENDPOINT", severity="error", message="Endpoint must start with https://"
                )
            )
        if self.llm_provider == "groq" and not self.groq_configured:
            issues.append(
                ConfigIssue(
                    setting="GROQ_API_KEY", severity="error", message="LLM_PROVIDER=groq but GROQ_API_KEY is not set."
                )
            )
        if self.groq_base_url and not self.groq_base_url.startswith("https://"):
            issues.append(ConfigIssue(setting="GROQ_BASE_URL", severity="error", message="Must start with https://"))
        if self.effective_llm_provider == "mock":
            issues.append(
                ConfigIssue(
                    setting="LLM_PROVIDER",
                    severity="info",
                    message="No LLM configured (Azure OpenAI or GROQ_API_KEY); "
                    "the offline deterministic mock planner is used.",
                )
            )
        if self.effective_llm_provider == "unavailable":
            issues.append(
                ConfigIssue(
                    setting="LLM_PROVIDER",
                    severity="error",
                    message="No usable LLM provider; investigations cannot start.",
                )
            )
        return issues


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
