FROM python:3.12-slim

# In-container root for the harness state dirs (.halgate_* live here, since
# config defaults are CWD-relative). Override at build:
#   docker build --build-arg HALGATE_DATA_DIR=/data ...
# and keep HALGATE_DATA_DIR in docker-compose.yml in sync.
ARG HALGATE_DATA_DIR=/halgate
ARG HALGATE_USER=halgate
# Additional apt packages for less common assessment tools, e.g.:
#   sqlmap ffuf hydra thc-hydra masscan nikto whatweb ldap-utils snmp smbclient
ARG EXTRA_TOOLS=""

# Textual needs a capable terminal description to enable its input driver.
# Docker does not reliably propagate TERM through compose.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TERM=xterm-256color

# Deterministic uid/gid 1000 so rootless host bind mounts match the container
# user, and so the state root exists with correct ownership before the
# volume is mounted over it at runtime.
RUN groupadd -g 1000 ${HALGATE_USER} \
    && useradd -u 1000 -g 1000 -m -d /home/${HALGATE_USER} ${HALGATE_USER} \
    && mkdir -p ${HALGATE_DATA_DIR} \
    # Placeholder config/package tree: the app falls back to
    # ~/.config/halgate/ after CWD. File mounts land here (never inside the
    # state volume), so runtime creation stays in the container's own layer.
    && mkdir -p /home/${HALGATE_USER}/.config/halgate \
    && touch /home/${HALGATE_USER}/.config/halgate/config.yaml \
             /home/${HALGATE_USER}/.config/halgate/scope_packages.yaml \
    && chown -R 1000:1000 ${HALGATE_DATA_DIR} /home/${HALGATE_USER}

# Core assessment/CLI tooling the harness expects. The shell tool executes
# direct argv (no shell interpreter), so each requested binary must exist.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl wget nmap netcat-openbsd dnsutils iputils-ping traceroute \
        openssh-client openssl whois \
        ${EXTRA_TOOLS} \
    && rm -rf /var/lib/apt/lists/*

# Copy only what the build needs (the classic podman builder does not honor
# .dockerignore, so an explicit COPY list keeps the context minimal). Build
# from /src rather than / so setuptools package discovery scans the package
# instead of the whole filesystem.
WORKDIR /src
COPY pyproject.toml README.md LICENSE requirements.txt scope_packages.yaml ./
COPY halgate/ halgate/
RUN pip install --no-cache .

ENV HOME=/home/${HALGATE_USER}
USER ${HALGATE_USER}
WORKDIR ${HALGATE_DATA_DIR}

CMD ["halgate", "tui"]
