## I. Run project
- Required: Intall **Docker**

1. At docker in local, run `docker compose --env-file .env.development up -d --build`
Now, access: http://localhost:7200/document

2. At docker in staging, run `docker compose --env-file .env.staging up -d --build`
Now, access: http://localhost:7200/document

2. At docker in production, run `docker compose --env-file .env.production up -d --build`
Now, access: http://localhost:7200/document

3. If you are also want to run **app** in localhost, and **database** is still installed on docker
- Install nvm on Windows: https://github.com/coreybutler/nvm-windows/releases
- Install nvm on Ubuntu: 
```
sudo apt install curl 
curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash 
source ~/.bashrc   
```
- Install NodeJs and dependencies 
```
nvm install 16.18.1
nvm use 16.18.1
npm install
npm run start:local
```
Now, access: http://localhost:7100/document

## II. MIGRATION
1. At local, if hava change entity
- Run `npm run migration:generate` ==> create new migration in ./src/typeorm/migrations
- Run `npm build` ==> create new migration in ./dist/typeorm/migrations
- Run `npm run migration:run:local` ==> up migrate to database and run migration

2. At docker
- In **docker-compose.yml**, command in nestjs project include: migration and run
- Run: `docker compose --env-file .env.development up -d` or `docker compose --env-file .env.development up -d`
