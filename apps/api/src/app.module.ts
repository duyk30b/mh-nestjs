import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { ConfigModule, ConfigType } from '@nestjs/config'
import { TypeOrmModule } from '@nestjs/typeorm'
import { DataSource } from 'typeorm'
import { MariadbConfig } from './enviroments'
import { LoggerMiddleware } from './middlewares/logger.middleware'
import { ValidateAccessTokenMiddleware } from './middlewares/validate-access-token.middleware'
import { AuthModule } from './modules/auth/auth.module'
import { ClinicModule } from './modules/clinic/clinic.module'
import { MedicineModule } from './modules/medicine/medicine.module'
import { UserModule } from './modules/user/user.module'

@Module({
	imports: [
		ConfigModule.forRoot({
			envFilePath: [`.env.${process.env.NODE_ENV || 'local'}`, '.env'],
			isGlobal: true,
		}),
		TypeOrmModule.forRootAsync({
			imports: [ConfigModule.forFeature(MariadbConfig)],
			inject: [MariadbConfig.KEY],
			useFactory: (mariadbConfig: ConfigType<typeof MariadbConfig>) => mariadbConfig,
			// inject: [ConfigService],
			// useFactory: (configService: ConfigService) => configService.get('mysql'),
		}),
		AuthModule,
		ClinicModule,
		UserModule,
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
