FROM node:16.18.1-alpine3.15
WORKDIR /app
COPY ["package.json", "package-lock.json*", "./"]
RUN npm install --production --silent
COPY ./dist ./dist
CMD ["npm", "run", "serve"]
