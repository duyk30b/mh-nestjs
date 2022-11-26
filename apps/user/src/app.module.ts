import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { ConfigModule, ConfigType } from '@nestjs/config'
import { TypeOrmModule } from '@nestjs/typeorm'
import { DataSource } from 'typeorm'
import { MysqlConfig } from './enviroments'
import { LoggerMiddleware } from './middlewares/logger.middleware'
import { ValidateAccessTokenMiddleware } from './middlewares/validate-access-token.middleware'
import { AuthModule } from './modules/auth/auth.module'
import { ClinicModule } from './modules/clinic/clinic.module'
import { EmployeeModule } from './modules/employee/employee.module'
import { MedicineModule } from './modules/medicine/medicine.module'

@Module({
	imports: [
		ConfigModule.forRoot({
			envFilePath: [`.env.${process.env.NODE_ENV || 'local'}`, '.env'],
			isGlobal: true,
		}),
		TypeOrmModule.forRootAsync({
			imports: [ConfigModule.forFeature(MysqlConfig)],
			inject: [MysqlConfig.KEY],
			useFactory: (mysqlConfig: ConfigType<typeof MysqlConfig>) => mysqlConfig,
			// inject: [ConfigService],
			// useFactory: (configService: ConfigService) => configService.get('mysql'),
		}),
		AuthModule,
		ClinicModule,
		EmployeeModule,
		MedicineModule,
	],
})
export class AppModule implements NestModule {
	constructor(private dataSource: DataSource) { }
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(LoggerMiddleware).forRoutes('*')

		consumer.apply(ValidateAccessTokenMiddleware)
			.exclude('auth/(.*)', '/')
			.forRoutes('*')
	}
}
