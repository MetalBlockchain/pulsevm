# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim AS build
WORKDIR /src
# Do not copy the caller's node_modules, compiled output, or git metadata.
RUN --mount=from=bloks,source=/,target=/upstream \
    tar -C /upstream --exclude=node_modules --exclude=dist --exclude=.git --exclude='.env*' \
    -cf - package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json packages apps/frontend \
    | tar -xf -
RUN corepack enable && corepack prepare pnpm@10.19.0 --activate
RUN --mount=type=cache,target=/pnpm/store \
    pnpm install --frozen-lockfile --filter 'frontend...' --store-dir /pnpm/store
# Override only the build copy; the supplied Bloks checkout is left intact.
COPY docker/localnet/bloks-local.ts packages/constants/src/networks/local.ts
COPY docker/localnet/configure-bloks.mjs /tmp/configure-bloks.mjs
COPY docker/localnet/bloks.env apps/frontend/.env.production
RUN node /tmp/configure-bloks.mjs
RUN pnpm exec turbo run build --filter='frontend^...'
ENV VITE_CHAIN=local
RUN pnpm --filter frontend build-only \
    && sed -i 's#<head>#<head><script src="/localnet-config.js"></script>#' apps/frontend/dist/index.html

FROM nginx:1.28-alpine
COPY --from=build /src/apps/frontend/dist /usr/share/nginx/html
COPY docker/localnet/nginx.conf /etc/nginx/conf.d/default.conf
