import * as dotenv from 'dotenv'
import * as path from 'path'
import { DataSource, DataSourceOptions } from 'typeorm'

dotenv.config({ path: path.resolve(__dirname, '../', `.env.${process.env.NODE_ENV || 'local'}`) })

export const dataSource = new DataSource({
	type: 'mysql',
	host: process.env.MYSQL_HOST,
	port: Number(process.env.MYSQL_PORT),
	database: process.env.MYSQL_DATABASE,
	username: process.env.MYSQL_USERNAME,
	password: process.env.MYSQL_PASSWORD,
	entities: [path.resolve(__dirname, './entities/*.entity.{ts,js}')],
	migrations: [path.resolve(__dirname, './migrations/*.{ts,js}')],
	migrationsTableName: 'typeorm_migration',
	migrationsTransactionMode: 'each',
} as DataSourceOptions)
