## I. Run project in local
1. Install Nodejs
- Install nvm on Windows: https://github.com/coreybutler/nvm-windows/releases
- Install nvm on Ubuntu: 
```
sudo apt install curl 
curl https://raw.githubusercontent.com/creationix/nvm/master/install.sh | bash 
source ~/.bashrc   
```
- Install NodeJs 16 and dependencies 
```
nvm install 16.18.1
nvm use 16.18.1
npm install
```

2. Create database on **Docker**
- Create MariaDB: `docker compose up mariadb -d`
- Run Migration for create database entity: `npm run migration:run`
- Run Seed for create fake database: `npm run fake:data`
- When change entity, create migration: `npm run migration:generate` (recommend) or `npm run migration:create`
- When revert migration: `npm run migration:revert`

3. Run project NestJS: `npm run dev`
4. Now, access: http://localhost:7100/document
5. When build: `npm run build`

## I. Run project in Docker
- Required: Install **Docker**

1. At docker in local, run `docker compose --env-file .env.development up -d --build`
Now, access: http://localhost:7200/document

2. At docker in staging, run `docker compose -f docker-compose.staging.yml --env-file .env.staging up -d --build`
Now, access: http://localhost:7300/document

3. At docker in production, Pending ... 
Now, access: http://localhost:7400/document

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

4. Linux
- List env: `printenv`
