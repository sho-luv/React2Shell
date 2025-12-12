FROM node:20-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN npm run build

# Production image
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Create flag files for CTF
RUN echo "FLAG{r00t_4cc3ss_ach13v3d_2025}" > /root/flag.txt && \
    chmod 644 /root/flag.txt && \
    chmod 755 /root

# Copy app
RUN mkdir -p ./public
RUN mkdir -p ./secret
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/app/secret/flag.txt ./secret/flag.txt

# Fix permissions for CTF flags
RUN chmod 644 ./secret/flag.txt

# Copy .env file (intentionally included for CTF)
COPY .env .env

# Note: Running as nextjs user but flag in /root is readable
USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
