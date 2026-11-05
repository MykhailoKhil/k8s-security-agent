# syntax=docker/dockerfile:1
FROM python:3.13-slim

ARG TARGETARCH
ARG KUBECTL_VERSION=v1.34.1
ARG TRIVY_VERSION=v0.70.0
ARG KUBESCAPE_VERSION=v4.0.17

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git jq \
    && rm -rf /var/lib/apt/lists/*

# kubectl: verified against the published checksum
RUN curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
    && echo "$(curl -fsSL https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum -c - \
    && chmod +x /usr/local/bin/kubectl
# shortcut: trivy/kubescape use their official install scripts (no checksum pin here); pin by digest when this goes to prod
RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin ${TRIVY_VERSION}
RUN curl -fsSL https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | RELEASE=${KUBESCAPE_VERSION} /bin/bash

RUN useradd -m -u 10001 agent
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py triage.py scan.py render.py test_scan.py test_render.py ./
RUN python test_scan.py && python test_render.py

USER 10001
ENV OUT_DIR=/out HOME=/home/agent
VOLUME /out
ENTRYPOINT ["python", "/app/agent.py"]
