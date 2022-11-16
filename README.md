## I. RUN PROJECT
### Prepare
```
nvm use 16.18.1
npm install
npm run build
docker compose build --no-cache
```

### Run project
1. At localhost
- Run `npm run start:local`. Now, access: http://localhost:3000/document

2. At docker in local
- Delete image **mhi_nestjs:1.0.0** in docker image, or change version to **mhi_nestjs:1.0.1** in docker-compose.yml
- Run `docker compose --env-file .env.development up -d` . Now, access: http://localhost:7300/document

3. At docker in production
- Delete image **mhi_nestjs:1.0.0** in docker image, or change version to **mhi_nestjs:1.0.1** in docker-compose.yml
- Run `docker compose --env-file .env.production up -d` . Now, access: http://localhost:7300/document

## II. MIGRATION
1. At local, if hava change entity
- Run `npm run migration:generate` ==> create new migration in ./src/typeorm/migrations
- Run `npm build` ==> create new migration in ./dist/typeorm/migrations
- Run `npm run migration:run:local` ==> up migrate to database and run migration

2. At docker
- In **docker-compose.yml**, command in nestjs project include: migration and run
- Run: `docker compose --env-file .env.development up -d` or `docker compose --env-file .env.development up -d`
