FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# mTLS certs are mounted via volume in docker-compose
EXPOSE 8443

CMD ["node", "src/index.js"]
