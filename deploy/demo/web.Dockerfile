FROM node:24.13.1-bookworm-slim AS build

WORKDIR /source
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile
COPY apps/web apps/web
RUN pnpm --filter @faultlane/web build

FROM node:24.13.1-bookworm-slim

ENV HOSTNAME=0.0.0.0
ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /app
COPY --from=build /source/apps/web/.next/standalone ./
COPY --from=build /source/apps/web/.next/static ./apps/web/.next/static
USER 65532:65532
CMD ["node", "apps/web/server.js"]
