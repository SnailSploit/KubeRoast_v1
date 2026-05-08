FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY kuberoast ./kuberoast
RUN pip install --no-cache-dir --user .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="KubeRoast"
LABEL org.opencontainers.image.description="Offensive Kubernetes misconfiguration & attack-path scanner"
LABEL org.opencontainers.image.source="https://github.com/SnailSploit/KubeRoast_v1"
LABEL org.opencontainers.image.licenses="MIT"

RUN groupadd -g 65532 kuberoast \
    && useradd -u 65532 -g kuberoast -m -s /usr/sbin/nologin kuberoast

COPY --from=builder /root/.local /home/kuberoast/.local
RUN chown -R kuberoast:kuberoast /home/kuberoast/.local

USER kuberoast
ENV PATH="/home/kuberoast/.local/bin:${PATH}"
WORKDIR /workspace

ENTRYPOINT ["kuberoast"]
CMD ["--help"]
