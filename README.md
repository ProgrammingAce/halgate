# Halgate

Halgate is a local AI harness for authorized security
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
```

Update `config.yaml` with your local LLM endpoint you control.

## Run

```sh
uv run halgate --help
uv run halgate --dry-run
uv run pytest -q
```

## Run in a container

Requires Docker (or Podman with `podman compose`). The container runs as a
non-root user (uid 1000); pick the host folder that stores the harness state
(`.halgate_memory`, `.halgate_audit`, `.halgate_sessions`, `.halgate_evidence`)
with `HALGATE_DATA_HOST` (default `./halgate-data`).

### Build the image

The image is built from the repository `Dockerfile`; build it as
`halgate:latest` (override the tag with
`HALGATE_IMAGE`); rebuild it whenever the code or `Dockerfile` changes. To
build it standalone (for `podman run` or `docker run`):

```sh
docker build -t halgate:latest .        # or: podman build -t halgate:latest .
```

Two build-time arguments are available (`docker compose` forwards matching
environment variables): `HALGATE_DATA_DIR` sets the in-container state root
(default `/halgate`), and `EXTRA_TOOLS` installs extra assessment tools.

```sh
mkdir -p halgate-data          # Podman needs the folder to exist; Docker creates it
# Run attached to a real terminal; the TUI needs this for keyboard and mouse input.
docker compose run --rm --build halgate
```

Do not start the TUI with detached Compose (`docker compose up -d`) or through
a log viewer: those attach output but do not provide an interactive terminal.

The container expects `config.yaml` (with LLM endpoints) and
`scope_packages.yaml` in the project root and mounts them read-only; set
`LLM_API_KEY` in the environment if `config.yaml` references `${LLM_API_KEY}`.

Overrides:

```sh
# Put state elsewhere on the host (reuse the repo-root folders with "."):
HALGATE_DATA_HOST=./data/docker docker compose up

# Install heavier assessment tools at build time:
EXTRA_TOOLS="sqlmap ffuf masscan hydra thc-hydra nikto whatweb" docker compose up

# Run a subcommand instead of the TUI:
docker compose run --rm halgate halgate session list
```

The in-container state root is the `HALGATE_DATA_DIR` build arg (default
`/halgate`); keep it in sync between `Dockerfile` and `docker-compose.yml` if
you change it.

Run the image directly (instead of `docker compose`), on a shared network:

```sh
podman build -t halgate:latest .
podman network create halnet
podman run -it --rm --env TERM="${TERM:-xterm-256color}" --network=halnet --name halgate \
  -v "$PWD/halgate-data:/halgate" \
  -v "$PWD/config.yaml:/home/halgate/.config/halgate/config.yaml:ro" \
  -v "$PWD/scope_packages.yaml:/home/halgate/.config/halgate/scope_packages.yaml:ro" \
  halgate:latest
```

Add other containers to the halnet network for Halgate to reach them.

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
