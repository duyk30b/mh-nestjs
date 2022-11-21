import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { ConfigModule, ConfigService, ConfigType } from '@nestjs/config'
import { TypeOrmModule } from '@nestjs/typeorm'
import { DataSource } from 'typeorm'
import { MysqlConfig } from './enviroments'
import { LoggerMiddleware } from './middlewares/logger.middleware'
import { AuthModule } from './modules/auth/auth.module'
import { ClinicModule } from './modules/clinic/clinic.module'
import { EmployeeModule } from './modules/employee/employee.module'

@Module({
	imports: [
		ConfigModule.forRoot({
			envFilePath: ['.env', `.env.${process.env.NODE_ENV}`],
			isGlobal: true,
		}),
		TypeOrmModule.forRootAsync({
			imports: [ConfigModule.forRoot({ load: [MysqlConfig] })],
			inject: [MysqlConfig.KEY],
			useFactory: (mysqlConfig: ConfigType<typeof MysqlConfig>) => mysqlConfig,
			// inject: [ConfigService],
			// useFactory: (configService: ConfigService) => configService.get('mysql'),
		}),
		AuthModule,
		ClinicModule,
		EmployeeModule,
	],
})
export class AppModule implements NestModule {
	constructor(private dataSource: DataSource) { }
	configure(consumer: MiddlewareConsumer) {
		consumer
			.apply(LoggerMiddleware)
			.forRoutes('*')
	}
}
