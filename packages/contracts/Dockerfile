FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Expose Hardhat node port
EXPOSE 8545

# Start local hardhat node by default
CMD ["npx", "hardhat", "node", "--hostname", "0.0.0.0"]
