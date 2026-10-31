FROM node:24-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
ENV NODE_ENV=production DATA_DIR=/data PORT=3001
VOLUME /data
EXPOSE 3001
CMD ["node", "server.js"]
