FROM mcr.microsoft.com/playwright:v1.62.0-noble

WORKDIR /worker
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src

ENV NODE_ENV=production
USER pwuser
EXPOSE 8080
CMD ["node", "src/server.mjs"]
