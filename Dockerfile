# Build stage
FROM node:18 AS build

# Set build arguments
ARG VITE_OAUTH_BASE_URL
ARG VITE_OAUTH_CLIENT_ID
ARG VITE_OAUTH_CLIENT_SECRET
ARG VITE_OAUTH_REDIRECT_URI
ARG VITE_OAUTH_PROTECTED_RESOURCE

# Set environment variables
ENV VITE_OAUTH_BASE_URL=$VITE_OAUTH_BASE_URL
ENV VITE_OAUTH_CLIENT_ID=$VITE_OAUTH_CLIENT_ID
ENV VITE_OAUTH_CLIENT_SECRET=$VITE_OAUTH_CLIENT_SECRET
ENV VITE_OAUTH_REDIRECT_URI=$VITE_OAUTH_REDIRECT_URI
ENV VITE_OAUTH_PROTECTED_RESOURCE=$VITE_OAUTH_PROTECTED_RESOURCE

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy source code and build
COPY . .
RUN npm run build

# Production stage
FROM nginx:stable-alpine

# Copy build output and nginx config
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"] 