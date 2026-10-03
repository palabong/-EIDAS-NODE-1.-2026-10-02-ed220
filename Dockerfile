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
