FROM docker.io/library/node:24.18.0-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY build ./build
USER node
EXPOSE 3000
CMD ["node", "build"]
