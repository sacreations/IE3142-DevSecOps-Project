FROM node:20-alpine

# Set working directory and configure directory permissions
WORKDIR /usr/src/app
RUN chown -R node:node /usr/src/app

# Update npm globally to patch bundled tool dependencies (sigstore/node-tar CVE-2026-73566)
RUN npm install --global npm@latest && npm cache clean --force

# Copy dependency manifests
COPY --chown=node:node package*.json ./

# Switch to unprivileged user
USER node

# Install production dependencies cleanly and deterministically
RUN npm ci --omit=dev

# Copy application source code
COPY --chown=node:node . .

# Expose web application port
EXPOSE 4000

# Container entrypoint
CMD ["npm", "start"]
