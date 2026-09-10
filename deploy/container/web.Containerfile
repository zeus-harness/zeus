FROM docker.io/library/node:24.18.0-bookworm-slim AS build
WORKDIR /workspace
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./
COPY packages/ui packages/ui
COPY apps/web apps/web
COPY openapi openapi
RUN pnpm install --frozen-lockfile \
    && pnpm --filter @zeus/ui build \
    && pnpm --filter @zeus/web build

FROM docker.io/library/node:24.18.0-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /workspace/apps/web/build ./build
COPY --from=build /workspace/apps/web/package.json ./package.json
USER node
EXPOSE 3000
CMD ["node", "build"]
