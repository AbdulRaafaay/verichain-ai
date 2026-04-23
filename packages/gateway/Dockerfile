FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN rm -rf node_modules && npm install

COPY src/ ./src/
COPY tsconfig.json ./

# mTLS certs are mounted via volume in docker-compose
EXPOSE 8443

CMD ["npm", "run", "dev"]
