# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install

# Install matching esbuild version globally to work around permission issues
RUN npm install -g esbuild@0.21.5

# Copy source code
COPY . .

# Build the application (use global esbuild)
ENV ESBUILD_BINARY_PATH=/usr/local/bin/esbuild
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose port
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
