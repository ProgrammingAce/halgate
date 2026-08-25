# Halgate

Halgate is a local AI harness for performing security research. It combines a
terminal UI with target-scoped tools, approval gates, budgets, audit logs, and
encryption for managing discovered and injected secrets.

![Halgate terminal UI](assets/halgate-screenshot.png)

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- An OpenAI-compatible LLM endpoint

## Install

```sh
uv sync --extra dev
```

Create your local configuration by copying the example, then configure the AI
endpoint:

```sh
cp config.example.yaml config.yaml
```

Update `config.yaml` with your local LLM endpoint.

To encrypt credentials or forensic payloads, the harness will ask you to create
a key and store the displayed recovery phrase offline:

### Encryption and recovery keys

`halgate key init` creates a random local root key and shows a recovery phrase
only once. the root key encrypts discovered credentials and forensic audit
payloads. It does not encrypt the app configuration or LLM API credentials.

Keep the recovery phrase offline and store any encrypted key backup separately.
Without both the key envelope and its phrase, encrypted records cannot be
recovered.

## Run

```sh
uv run halgate --help
uv run halgate --dry-run
uv run pytest -q
```

## Docker/Containerization

Halgate supports containerization, but does not provide a default Docker config
or Dockerfile. The choices around securing the environment this harness runs in
should be carefully considered, as different configurations may lead to data
loss, and that may or may not be intentional by the operator. Choices like
running the container as rootless, or where and whether to store the output of
an engagement in a volume cannot be simple defaults. Consider the type of
engagement and research you're doing, and configure the environment accordingly.

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
