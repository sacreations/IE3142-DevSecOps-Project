# Stage 1: Build & Dependency Installation Stage
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

# Copy dependency manifests
COPY package*.json ./

# Install production dependencies cleanly and deterministically
RUN npm ci --omit=dev

# Copy application source code
COPY . .

# Stage 2: Minimal Hardened Production Runtime Stage
FROM node:20-alpine AS runtime

WORKDIR /usr/src/app
ENV NODE_ENV=production

# Harden runtime: Remove npm and npx package managers to eliminate build-tool CVE surface
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/bin/npm \
           /usr/local/bin/npx

# Copy application artifacts from builder with non-root ownership
COPY --from=builder --chown=node:node /usr/src/app ./

# Drop privileges to unprivileged user
USER node

# Expose web application port
EXPOSE 4000

# Start directly with node binary (npm is omitted from runtime)
CMD ["node", "server.js"]
