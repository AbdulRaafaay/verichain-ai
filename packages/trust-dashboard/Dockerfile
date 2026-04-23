FROM node:20-alpine as build

WORKDIR /app

COPY package*.json ./
RUN rm -rf node_modules && npm install

# Copy source code but AVOID copying node_modules from host explicitly
COPY src/ ./src/
COPY public/ ./public/
COPY tsconfig.json ./
# Add any other root files needed

# In development, we use the react-scripts server
# In production, we would build and serve with nginx
# For simplicity in this SSD project, we'll use react-scripts start
EXPOSE 3000

CMD ["npm", "start"]
