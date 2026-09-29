FROM node:20-alpine

# Set working directory and configure directory permissions
WORKDIR /usr/src/app
RUN chown -R node:node /usr/src/app

# Copy dependency manifests
COPY --chown=node:node package*.json ./

# Switch to unprivileged user
USER node

# Install production dependencies
RUN npm install --only=production 2>/dev/null || npm install 2>/dev/null || true

# Copy application source code
COPY --chown=node:node . .

# Expose web application port
EXPOSE 4000

# Container entrypoint
CMD ["npm", "start"]
