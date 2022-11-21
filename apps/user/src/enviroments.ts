import { registerAs } from '@nestjs/config'
import { TypeOrmModuleOptions } from '@nestjs/typeorm'

export const JwtConfig = registerAs('jwt', () => ({
	accessKey: process.env.JWT_ACCESS_KEY,
	refreshKey: process.env.JWT_REFRESH_KEY,
	accessTime: Number(process.env.JWT_ACCESS_TIME),
	refreshTime: Number(process.env.JWT_REFRESH_TIME),
}))

export const MysqlConfig = registerAs('mysql', (): TypeOrmModuleOptions => ({
	type: 'mysql',
	host: process.env.MYSQL_HOST,
	port: parseInt(process.env.MYSQL_PORT, 10),
	database: process.env.MYSQL_DATABASE,
	username: process.env.MYSQL_USERNAME,
	password: process.env.MYSQL_PASSWORD,
	autoLoadEntities: true,
	logging: process.env.NODE_ENV !== 'production',
	synchronize: process.env.NODE_ENV === 'local',
}))
