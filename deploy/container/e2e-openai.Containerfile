FROM docker.io/library/node:24.18.0-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY fake-openai.mjs ./fake-openai.mjs
RUN chown node:node ./fake-openai.mjs && chmod 0444 ./fake-openai.mjs
USER node
EXPOSE 4010
CMD ["node", "fake-openai.mjs"]
