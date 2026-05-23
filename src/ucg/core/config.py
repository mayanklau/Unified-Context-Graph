from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    env: str = "local"
    default_tenant_id: str = "default"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_prefix="UCG_", env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
