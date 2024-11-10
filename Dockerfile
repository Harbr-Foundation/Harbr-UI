# syntax=docker/dockerfile:1
ARG NODE_VERSION=22.11.0

################################################################################
# Use node image for base image for all stages.
FROM node:${NODE_VERSION}-alpine as base

# Set working directory for all build stages.
WORKDIR /usr/src/app

################################################################################
# Create a stage for installing production dependencies.
FROM base as deps

# Download dependencies as a separate step to take advantage of Docker's caching.
RUN --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev

################################################################################
# Create a stage for building the application.
FROM base as build

# Define build argument
ARG JWT_SECRET
ENV JWT_SECRET=${JWT_SECRET}

# Download additional development dependencies
RUN --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci

# Copy the rest of the source files into the image.
COPY . .

# Create .env file with the JWT_SECRET
RUN touch .env && \
    echo "JWT_SECRET=${JWT_SECRET}" >> .env && \
    cat .env

# Run the build script.
RUN npm run build

################################################################################
# Final stage
FROM base as final

# Use production node environment by default.
ENV NODE_ENV production
ENV HOST 0.0.0.0

# Create directory and set permissions
RUN mkdir -p /usr/src/app && chown -R node:node /usr/src/app

# Copy package files
COPY --chown=node:node package.json package-lock.json ./

# Install production dependencies
RUN npm i -v
RUN npm install -v vite

# Copy the built application and config
COPY --chown=node:node --from=build /usr/src/app/ ./

# Ensure .env is copied
COPY --chown=node:node --from=build /usr/src/app/.env ./.env

# Switch to non-root user
USER node

# Expose port
EXPOSE 4173

# Run the application
CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0"]