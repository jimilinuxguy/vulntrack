from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./vulntrack.db"
    oidc_issuer: str = ""
    oidc_audience: str = "vulntrack"
    oidc_jwks_url: str = ""
    dev_auth: bool = False
    cloud_foundry: bool = False
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    model_config = SettingsConfigDict(env_prefix="VULNTRACK_", env_file=".env", extra="ignore")

settings = Settings()
