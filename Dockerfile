# syntax=docker/dockerfile:1
# Base image pinned by digest (python:3.13-slim). To update: docker buildx imagetools inspect python:3.13-slim
FROM python:3.13-slim@sha256:09a17cad02668ae61ece136b4fd36ac3849e14f670ebedb637ea3e15580525bc

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# kubectl, trivy, kubescape, jq: pinned versions, sha256 verified (tools.lock); the build fails on a mismatch
COPY tools.lock install-tools.sh /opt/tools/
RUN /opt/tools/install-tools.sh /usr/local/bin

RUN useradd -m -u 10001 agent
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY agent.py triage.py investigate.py history.py remediate.py yamlguard.py gitutil.py scan.py render.py \
     test_scan.py test_render.py test_history.py test_investigate.py test_remediate.py test_gitutil.py ./
RUN python test_scan.py && python test_render.py && python test_history.py && python test_investigate.py && python test_remediate.py && python test_gitutil.py

USER 10001
ENV OUT_DIR=/out HOME=/home/agent
VOLUME /out
ENTRYPOINT ["python", "/app/agent.py"]
