<<<<<<< HEAD
# syntax = docker/dockerfile:1

# Adjust BUN_VERSION as desired
ARG BUN_VERSION=1
FROM oven/bun:${BUN_VERSION}-slim AS base

LABEL fly_launch_runtime="Node.js"

# Node.js app lives here
WORKDIR /app

# Set production environment
ENV NODE_ENV="production"


# Throw-away build stage to reduce size of final image
FROM base AS build

# Install packages needed to build node modules
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential pkg-config python-is-python3

# Install node modules
COPY bun.lock package-lock.json package.json ./
RUN bun install --no-frozen-lockfile

# Copy application code
COPY . .

# Build application
RUN bun --bun run build

# Remove development dependencies
RUN rm -rf node_modules && bun install --production --no-frozen-lockfile


# Final stage for app image
FROM base

# Install runtime dependencies required for SAML 2.0 engine execution and cryptography
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y python3 python-is-python3 openssl && \
    rm -rf /var/lib/apt/lists/*

# Copy built application
COPY --from=build /app /app

# Start the server by default, this can be overwritten at runtime
EXPOSE 3000
CMD [ "bun", "run", "start" ]
=======
# syntax=docker/dockerfile:1
FROM node:20-bookworm-slim

WORKDIR /app

# The app uses Python for the embedded SAML validation engine.
RUN apt-get update && apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --include=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=8080

RUN npm run build

EXPOSE 8080

CMD ["npm", "run", "start"]
>>>>>>> origin/main
