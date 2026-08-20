# Halgate

Halgate is a single-operator, local AI harness for authorized security
research. It combines a terminal UI with target-scoped tools, approval gates,
budgets, audit logs, and encrypted handling of discovered credentials.

![Halgate terminal UI](assets/halgate-screenshot.png)

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- An OpenAI-compatible LLM endpoint

## Install

```sh
uv sync --extra dev
```

Create your local configuration, then set the API key if your endpoint needs
one:

```sh
cp config.example.yaml config.yaml
export LLM_API_KEY="..."
```

Update `config.yaml` with an LLM endpoint you control. It is ignored by Git;
keep real API keys in environment variables instead of committing them.

## Run

```sh
uv run harness --help
uv run harness --dry-run
uv run pytest -q
```

## Run in a container

Requires Docker (or Podman with `podman compose`). The container runs as a
non-root user (uid 1000); pick the host folder that stores the harness state
(`.harness_memory`, `.harness_audit`, `.harness_sessions`, `.harness_evidence`)
with `HALGATE_DATA_HOST` (default `./halgate-data`).

```sh
mkdir -p halgate-data          # Podman needs the folder to exist; Docker creates it
docker compose up
```

The container expects `config.yaml` (with LLM endpoints) and
`scope_packages.yaml` in the project root and mounts them read-only; set
`LLM_API_KEY` in the environment if `config.yaml` references `${LLM_API_KEY}`.
The image has no `gpg` binary, so use `audit.crypto_backend: pgpy` for
forensic audit.

Overrides:

```sh
# Put state elsewhere on the host (reuse the repo-root folders with "."):
HALGATE_DATA_HOST=./data/docker docker compose up

# Install heavier assessment tools at build time:
EXTRA_TOOLS="sqlmap ffuf masscan hydra thc-hydra nikto whatweb" docker compose up

# Run a subcommand instead of the TUI:
docker compose run --rm halgate harness session list
```

The in-container state root is the `HALGATE_DATA_DIR` build arg (default
`/halgate`); keep it in sync between `Dockerfile` and `docker-compose.yml` if
you change it.

## Safety

Use Halgate only against systems you own or for which you have explicit,
written authorization. You are responsible for defining a narrow engagement
scope and complying with applicable law, contracts, and organizational policy.

Do not use it to access, disrupt, or probe systems without permission, or to
handle credentials or personal data beyond what an authorized engagement
requires. Tool execution is constrained by engagement scope, package
permissions, operator approval, and resource budgets, but these controls do
not replace professional judgment. Review the configuration and proposed
actions before every engagement.

## License

MIT. See [LICENSE](LICENSE).
