FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install
RUN apk add --no-cache netcat-openbsd

COPY . .

# Expose Hardhat node port
EXPOSE 8545

# Use entrypoint script for auto-deployment
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
