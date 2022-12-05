## I. Run project
- Required: Intall **Docker**

1. At docker in local, run `docker compose --env-file .env.development up -d --build`
Now, access: http://localhost:7200/document

2. At docker in staging, run `docker compose -f docker-compose.staging.yml --env-file .env.staging up -d --build`
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
- Run `npm run migration:run` ==> up migrate to database and run migration

2. At docker
- In **docker-compose.yml**, command in nestjs project include: migration and run
- Run: `docker compose --env-file .env.development up -d` or `docker compose --env-file .env.development up -d`

## III. Nginx
1. SSL/TLS
```
openssl req -days 3650 -x509 -newkey rsa:2048 -sha256 -nodes -keyout %UserProfile%\Desktop\key.pem -out %UserProfile%\Desktop\cert.pem -subj "/C=/ST=/L=/O=/OU=web/CN=medihome.vn"

sudo docker run -it --rm --name certbot -v "/etc/letsencrypt:/etc/letsencrypt" -v "/var/lib/letsencrypt:/var/lib/letsencrypt" -p 80:80 certbot/certbot certonly
rm -rf ~/mh-nestjs/nginx/ssl/letsencrypt/
cp -R /etc/letsencrypt/archive/ ~/mh-nestjs/nginx/ssl/letsencrypt/
```

2. Nginx
- Check syntax: `docker exec mhc_nginx nginx -t`
- Reload: `docker exec mhc_nginx nginx -s reload`

## IV. Other
1. Show all port: `netstat -tulpn`
2. Github
```
git fetch --all
git log --all --oneline --graph -10
git reset --hard origin/master
```
3. NestJS
- Create new app: `nest generate app my-app`
- Create new library: `nest g library my-library`
- Create new module: `nest g resource my-module`
