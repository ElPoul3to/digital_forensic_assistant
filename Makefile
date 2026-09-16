.PHONY: install download-models smoke test lint update-attack eval eval-baselines bundle bundle-verify qdrant-server

install:
	uv sync --all-extras

download-models:
	uv run python -c "from dfa.retrieval.embedder import Embedder; Embedder().warmup()"

smoke:
	uv run dfa smoke

test:
	uv run pytest -q

lint:
	uv run ruff check src tests

update-attack:
	uv run dfa external update-attack

eval:
	uv run python eval/run_eval.py $(ARGS)

eval-baselines:  # default vs dense-only vs no-rerank, JSON per variant
	uv run python eval/run_eval.py --json eval/out-default.json
	uv run python eval/run_eval.py --dense-only --json eval/out-dense-only.json
	uv run python eval/run_eval.py --no-rerank --json eval/out-no-rerank.json

bundle:  # air-gapped install bundle (needs network): make bundle OUT=/media/usb/dfa-bundle
	uv run dfa bundle build $(OUT)

bundle-verify:
	uv run dfa bundle verify $(OUT)

QDRANT_VERSION ?= v1.19.1
qdrant-server:  # standalone Qdrant server on 127.0.0.1:6333 (no Docker); data in data/qdrant-server. Then set DFA_QDRANT_URL.
	@test -x .tools/qdrant || (mkdir -p .tools && echo "downloading qdrant $(QDRANT_VERSION)..." && \
	  curl -sL https://github.com/qdrant/qdrant/releases/download/$(QDRANT_VERSION)/qdrant-x86_64-unknown-linux-musl.tar.gz | tar xz -C .tools)
	@mkdir -p data/qdrant-server
	QDRANT__STORAGE__STORAGE_PATH=data/qdrant-server QDRANT__SERVICE__HOST=127.0.0.1 .tools/qdrant
