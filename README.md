# RUN PROJECT
1. Prepare
```
nvm use 16.18.1
npm install
npm run build
docker compose build --no-cache
```

2. Run with local
```
npm run start:local
```
Now, access: http://localhost:3000/document

3. Run with docker-compose
```
docker compose --env-file .env.development up -d
docker compose --env-file .env.production up -d
```
Now, access: http://localhost:7300/document

# MIGRATION
- Must migration:run then migration:generate
