import { registerAs } from '@nestjs/config'
import { TypeOrmModuleOptions } from '@nestjs/typeorm'

export const JwtConfig = registerAs('jwt', () => ({
	accessKey: process.env.JWT_ACCESS_KEY,
	refreshKey: process.env.JWT_REFRESH_KEY,
	accessTime: Number(process.env.JWT_ACCESS_TIME),
	refreshTime: Number(process.env.JWT_REFRESH_TIME),
}))

export const MariadbConfig = registerAs('mariadb', (): TypeOrmModuleOptions => ({
	type: 'mariadb',
	host: process.env.MARIADB_HOST,
	port: parseInt(process.env.MARIADB_PORT, 10),
	database: process.env.MARIADB_DATABASE,
	username: process.env.MARIADB_USERNAME,
	password: process.env.MARIADB_PASSWORD,
	autoLoadEntities: true,
	// logging: process.env.NODE_ENV !== 'production',
	synchronize: process.env.NODE_ENV === 'local',
}))
