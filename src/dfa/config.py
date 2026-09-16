"""Configuration loading.

Precedence (highest first):
  1. environment variables prefixed with ``DFA_`` (or a ``.env`` file)
  2. ``config/*.yaml``
  3. defaults below
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"


class GeneratorConfig(BaseModel):
    backend: Literal["ollama", "openai_compatible"] = "ollama"
    model: str = "hf.co/JonathanColetti/Qwen3.8-27B-Uncensored-GGUF:Q8_0"
    base_url: str = "http://localhost:11434"
    num_ctx: int = 32768
    temperature: float = 0.1
    keep_alive: str = "30m"
    think: bool = False  # Qwen3 thinking mode; off = faster, deterministic short outputs


class EmbeddingConfig(BaseModel):
    model: str = "Qwen/Qwen3-Embedding-0.6B"
    device: str = "cuda"
    batch_size: int = 32
    max_length: int = 1024
    dtype: Literal["float16", "bfloat16", "float32"] = "float16"


class RerankerConfig(BaseModel):
    model: str = "Qwen/Qwen3-Reranker-0.6B"
    device: str = "cuda"
    batch_size: int = 16
    max_length: int = 2048
    dtype: Literal["float16", "bfloat16", "float32"] = "float16"


class VectorStoreConfig(BaseModel):
    backend: Literal["qdrant"] = "qdrant"
    path: str | None = "data/qdrant"
    url: str | None = None


class ChunkingConfig(BaseModel):
    window_events: int = 20
    window_seconds: int = 120
    external_chunk_tokens: int = 512
    external_overlap_tokens: int = 64


class RetrievalParams(BaseModel):
    bm25_k: int = 50
    dense_k: int = 50
    rrf_k: int = 60
    rerank_keep_evidence: int = 10
    rerank_keep_external: int = 5
    timeline_neighbours: int = 5
    dedup_per_shape: int = 3  # max near-identical event lines (numbers masked) kept before reranking; 0 = off
    sparse: bool = True  # BM25 prefetch (False = dense only; for baselines)
    rerank: bool = True  # cross-encoder reranking (False = keep the RRF order; for baselines)
    hops: int = 1  # extra retrieval rounds for facts the first round cannot reach (0 = off)
    hop_followups: int = 3  # max follow-up lookups the model may request per round
    hop_keep: int = 5  # evidence hits merged per follow-up lookup


class RouterConfig(BaseModel):
    default: str = "auto"
    allow_external: bool = True
    timeline_queries: bool = True  # exact SQL over the timeline for counting / listing questions
    timeline_query_rows: int = 60  # max result rows placed in the context
    labels: dict[str, str] = Field(default_factory=dict)


class GenerationConfig(BaseModel):
    max_context_tokens: int = 24000
    require_citations: bool = True


class AuditConfig(BaseModel):
    enabled: bool = True  # append one JSON line per question to data/audit/<case>.jsonl
    store_answer: bool = True  # include the answer text (otherwise only its SHA-256)


class SecurityConfig(BaseModel):
    api_auth: Literal["auto", "required", "off"] = "auto"  # auto: required once a user exists or the client is not loopback
    encrypt_new_cases: bool = False  # create a per-case key at first use (timeline, vector payload text, audit log)
    master_key_file: str = "data/keys/master.key"  # used when DFA_MASTER_KEY is not set; generated on first need
    vol_offline: bool = False  # Volatility: do not fetch symbols online
    vol_symbols: str | None = None  # extra Volatility symbol directory


class EnvOverrides(BaseSettings):
    """Environment / .env overrides for the most commonly changed values."""

    model_config = SettingsConfigDict(env_prefix="DFA_", env_file=".env", extra="ignore")

    ollama_base_url: str | None = None
    generator_model: str | None = None
    qdrant_path: str | None = None
    qdrant_url: str | None = None
    embedding_model: str | None = None
    reranker_model: str | None = None
    device: str | None = None


class Settings(BaseModel):
    generator: GeneratorConfig = GeneratorConfig()
    embedding: EmbeddingConfig = EmbeddingConfig()
    reranker: RerankerConfig = RerankerConfig()
    vector_store: VectorStoreConfig = VectorStoreConfig()
    chunking: ChunkingConfig = ChunkingConfig()
    retrieval: RetrievalParams = RetrievalParams()
    router: RouterConfig = RouterConfig()
    generation: GenerationConfig = GenerationConfig()
    audit: AuditConfig = AuditConfig()
    security: SecurityConfig = SecurityConfig()

    data_dir: Path = PROJECT_ROOT / "data"

    @property
    def cases_dir(self) -> Path:
        return self.data_dir / "cases"

    @property
    def timeline_dir(self) -> Path:
        return self.data_dir / "timeline"

    def resolve(self, p: str | Path) -> Path:
        p = Path(p)
        return p if p.is_absolute() else PROJECT_ROOT / p


def _load_yaml(name: str) -> dict:
    f = CONFIG_DIR / name
    if not f.exists():
        return {}
    with f.open() as fh:
        return yaml.safe_load(fh) or {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    models = _load_yaml("models.yaml")
    retrieval = _load_yaml("retrieval.yaml")
    router = _load_yaml("router.yaml")
    security = _load_yaml("security.yaml")

    merged = {
        "generator": models.get("generator", {}),
        "embedding": models.get("embedding", {}),
        "reranker": models.get("reranker", {}),
        "vector_store": models.get("vector_store", {}),
        "chunking": retrieval.get("chunking", {}),
        "retrieval": retrieval.get("retrieval", {}),
        "router": {**retrieval.get("router", {}), **router},
        "generation": retrieval.get("generation", {}),
        "audit": retrieval.get("audit", {}),
        "security": security.get("security", security),
    }
    s = Settings.model_validate(merged)

    env = EnvOverrides(_env_file=str(PROJECT_ROOT / ".env") if (PROJECT_ROOT / ".env").exists() else None)
    if env.ollama_base_url:
        s.generator.base_url = env.ollama_base_url
    if env.generator_model:
        s.generator.model = env.generator_model
    if env.qdrant_url:
        s.vector_store.url = env.qdrant_url
        s.vector_store.path = None
    elif env.qdrant_path:
        s.vector_store.path = env.qdrant_path
    if env.embedding_model:
        s.embedding.model = env.embedding_model
    if env.reranker_model:
        s.reranker.model = env.reranker_model
    if env.device:
        s.embedding.device = env.device
        s.reranker.device = env.device
    if d := os.environ.get("DFA_DATA_DIR"):
        s.data_dir = Path(d)
    if a := os.environ.get("DFA_API_AUTH"):
        s.security.api_auth = a  # type: ignore[assignment]
    if os.environ.get("DFA_ENCRYPT_NEW_CASES", "").lower() in ("1", "true", "yes"):
        s.security.encrypt_new_cases = True
    return s
