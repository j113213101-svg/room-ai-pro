FROM node:18-alpine
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
RUN mkdir -p /data
EXPOSE 8080
ENV PORT=8080
ENV DB_PATH=/data/app.db
CMD ["node", "server.js"]
