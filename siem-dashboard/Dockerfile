# ── Stage 1: Build Angular app ────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build -- --configuration production

# ── Stage 2: Serve with Nginx ─────────────────────────────────────────────────

FROM nginx:1.27-alpine

# Angular 18 (new esbuild builder) puts browser assets in dist/.../browser/
COPY --from=builder /app/dist/siem-dashboard/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# SSL certs are mounted at runtime via docker-compose volume
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
