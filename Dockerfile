FROM node:20-alpine

# Set working directory and configure directory permissions
WORKDIR /usr/src/app
RUN chown -R node:node /usr/src/app

# Update npm globally to patch bundled tool dependencies (compatible with Node.js 20)
RUN npm install --global npm@11.6.2 && npm cache clean --force

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
