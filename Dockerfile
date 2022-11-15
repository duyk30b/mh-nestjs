FROM node:16.18.1-alpine3.15 AS production
WORKDIR /app
COPY ["package.json", "package-lock.json*", ".env.production", "./"]
RUN npm install --production --silent
COPY ./dist ./dist

FROM node:16.18.1-alpine3.15 AS development
WORKDIR /app
COPY ["package.json", "package-lock.json*", ".env.development" , "./"]
RUN npm install
COPY . .