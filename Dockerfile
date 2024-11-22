FROM node:18-alpine AS builder
WORKDIR /app

# dependencies
# Install bash
RUN apk add --no-cache bash
ADD package.json package-lock.json ./
RUN npm install

# library code
ADD src src

# bundle
RUN npx esbuild src/bin/start.ts --outdir=lib --platform=node --target=node18 --bundle

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/lib .

# bindings
EXPOSE 9229
ENV HOST=0.0.0.0
ENV PORT=9229
VOLUME /app/.cognito
ENTRYPOINT ["node", "/app/start.js"]
