import * as dotenv from 'dotenv'
import * as path from 'path'
import { DataSource, DataSourceOptions } from 'typeorm'

dotenv.config({ path: path.resolve(__dirname, `../.env.${process.env.NODE_ENV || 'local'}`) })
dotenv.config({ path: path.resolve(__dirname, '../.env') })

export const dataSource = new DataSource({
	type: 'mariadb',
	host: process.env.MARIADB_HOST,
	port: Number(process.env.MARIADB_PORT),
	database: process.env.MARIADB_DATABASE,
	username: process.env.MARIADB_USERNAME,
	password: process.env.MARIADB_PASSWORD,
	entities: [path.resolve(__dirname, './entities/*.entity.{ts,js}')],
	migrations: [path.resolve(__dirname, './migrations/*.{ts,js}')],
	migrationsTableName: 'typeorm_migration',
	migrationsTransactionMode: 'each',
} as DataSourceOptions)
