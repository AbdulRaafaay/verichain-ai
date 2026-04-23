FROM node:20-alpine as build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# In development, we use the react-scripts server
# In production, we would build and serve with nginx
# For simplicity in this SSD project, we'll use react-scripts start
EXPOSE 3000

CMD ["npm", "start"]
