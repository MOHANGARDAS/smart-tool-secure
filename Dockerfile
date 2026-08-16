# SMART-TOOL/M — production image (Oracle Always Free / any VPS)
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/app/data

VOLUME ["/app/data"]
EXPOSE 3000

CMD ["node", "server.js"]
