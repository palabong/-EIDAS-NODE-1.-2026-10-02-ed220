# syntax=docker/dockerfile:1

FROM node:20-bookworm-slim AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci --include=dev

COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:20-bookworm-slim

LABEL fly_launch_runtime="Node.js"

WORKDIR /app

# Install runtime dependencies required for SAML 2.0 engine execution and cryptography
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends python3 python-is-python3 openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV PORT=3000

COPY --from=build /app/package.json ./package.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/saml_engine ./saml_engine

EXPOSE 3000

CMD ["npm", "run", "start"]
