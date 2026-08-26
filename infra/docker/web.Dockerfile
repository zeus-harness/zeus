# syntax=docker/dockerfile:1.7

ARG NODE_VERSION=24.18.0
ARG PNPM_VERSION=10.33.0

FROM node:${NODE_VERSION}-bookworm-slim AS base
ARG PNPM_VERSION
ENV PNPM_HOME=/pnpm
ENV PATH=/pnpm:$PATH
RUN corepack enable && corepack prepare pnpm@${PNPM_VERSION} --activate
WORKDIR /workspace

FROM base AS dependencies
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./
COPY apps/web/package.json apps/web/package.json
COPY packages/eslint-config/package.json packages/eslint-config/package.json
COPY packages/typescript-config/package.json packages/typescript-config/package.json
COPY packages/ui/package.json packages/ui/package.json
RUN --mount=type=cache,id=zeus-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile

FROM dependencies AS dev
COPY . .
ENV HOST=0.0.0.0
ENV PORT=3000
EXPOSE 3000
CMD ["pnpm", "--filter", "web", "dev", "--host", "0.0.0.0", "--port", "3000"]

FROM dev AS debug
EXPOSE 9229
CMD ["pnpm", "--filter", "web", "exec", "node", "--inspect=0.0.0.0:9229", "node_modules/vite/bin/vite.js", "--host", "0.0.0.0", "--port", "3000"]

FROM dependencies AS builder
COPY . .
RUN --mount=type=cache,id=zeus-pnpm-store,target=/pnpm/store \
    pnpm --filter web build \
    && pnpm --filter web deploy --prod --legacy /opt/zeus-web \
    && cp -R apps/web/build /opt/zeus-web/build

FROM node:${NODE_VERSION}-bookworm-slim AS runtime
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
WORKDIR /app
COPY --from=builder --chown=node:node /opt/zeus-web/ ./
USER node
EXPOSE 3000
CMD ["node", "build"]
