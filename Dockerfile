# SOC Triage Desk: one image with the API and the built frontend.
#   docker compose up -d --build
# Settings come from .env (see .env.example). The SQLite database lives in the
# "socdesk-data" volume at /data, so it survives rebuilds.

# ---------- build ----------
FROM node:20-bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Frontend packages (yarn.lock is the frontend's lockfile).
COPY frontend/package.json frontend/yarn.lock frontend/
RUN corepack enable && cd frontend && yarn install --frozen-lockfile --ignore-engines --network-timeout 600000

# Backend packages (postinstall runs prisma generate, so the schema goes in first).
COPY package.json package-lock.json ./
COPY prisma/schema.prisma prisma/schema.prisma
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build && npm prune --omit=dev

# ---------- run ----------
FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates tini && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /data && chown node:node /data
WORKDIR /app
ENV NODE_ENV=production PORT=3000 DATABASE_URL="file:/data/soc.db"
COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/public ./public
COPY --from=build --chown=node:node /app/prisma ./prisma
# src/ is only for the sample-data seed (run with tsx); the server runs from dist/.
COPY --from=build --chown=node:node /app/src ./src
COPY --from=build --chown=node:node /app/tsconfig.json ./tsconfig.json
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Apply any pending migrations, then start. Seeding and create-admin are run on demand:
#   docker compose exec app npm run create-admin -- --username <name>
ENTRYPOINT ["/usr/bin/tini", "--"]
# SEED_SAMPLE_DATA=true also loads the sample tickets and playbooks (used on Render's free plan,
# where the database starts empty after every restart).
CMD ["sh", "-c", "npx prisma migrate deploy && if [ \"$SEED_SAMPLE_DATA\" = true ]; then npx tsx prisma/seed.ts; fi && node dist/src/server.js"]
