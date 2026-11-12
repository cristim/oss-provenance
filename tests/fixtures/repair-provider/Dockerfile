FROM ai-cleanroom-claude:2.1.285
USER root
COPY --chmod=755 claude /fixture/claude
ENV PATH=/fixture:/usr/local/bin:/usr/bin:/bin
USER 65534:65534
