FROM node:22-bookworm-slim@sha256:a0ddbc73510e98f5e824fd64266ffe1c2c343ba9cf260d95ca2985ad632a3f3e
RUN npm install --global @anthropic-ai/claude-code@2.1.285 && claude --version
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["claude"]
