import * as dotenv from 'dotenv'
import * as path from 'path'
import { DataSource, DataSourceOptions } from 'typeorm'

dotenv.config({ path: path.resolve(__dirname, '../', `.env.${process.env.NODE_ENV}`) })

const Env = {
	server: { port: Number(process.env.PORT) || 3000 },

	mysql: {
		type: 'mysql',
		host: process.env.MYSQL_HOST,
		port: Number(process.env.MYSQL_PORT) || 3306,
		database: process.env.MYSQL_DATABASE,
		username: process.env.MYSQL_USERNAME || 'root',
		password: process.env.MYSQL_PASSWORD || '',
		entities: [path.resolve(__dirname, 'typeorm/entities/*.entity{.ts,.js}')],
		migrations: [path.resolve(__dirname, 'typeorm/migrations/*{.ts,.js}')],
		migrationsTableName: 'tbl_typeorm_migration',
		migrationsTransactionMode: 'each',
		autoLoadEntities: true,
		logging: process.env.NODE_ENV !== 'production',
		synchronize: false,
	},

	mongoDB: {
		endPoint: process.env.MONGODB_ENDPOINT,
		host: process.env.MONGODB_HOST,
		port: Number(process.env.MONGODB_PORT),
		database: process.env.MONGODB_DATABASE,
		username: process.env.MONGODB_USERNAME,
		password: process.env.MONGODB_PASSWORD || '',
	},

	email: {
		service: process.env.EMAIL_SERVICE,
		username: process.env.EMAIL_USERNAME,
		password: process.env.EMAIL_PASSWORD,
	},

	jwt: {
		accessKey: process.env.JWT_ACCESS_KEY,
		refreshKey: process.env.JWT_REFRESH_KEY,
		accessTime: Number(process.env.JWT_ACCESS_TIME),
		refreshTime: Number(process.env.JWT_REFRESH_TIME),
	},
}

export const dataSource = new DataSource(Env.mysql as DataSourceOptions)

export default Env
