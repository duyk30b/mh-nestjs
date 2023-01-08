import { ClassSerializerInterceptor, MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common'
import { ConfigModule, ConfigType } from '@nestjs/config'
import { APP_INTERCEPTOR } from '@nestjs/core'
import { TypeOrmModule } from '@nestjs/typeorm'
import { DataSource } from 'typeorm'
import { MariadbConfig } from './environments'
import { LoggerMiddleware } from './middleware/logger.middleware'
import { ValidateAccessTokenMiddleware } from './middleware/validate-access-token.middleware'
import { AdmissionModule } from './modules/admission/admission.module'
import { AuthModule } from './modules/auth/auth.module'
import { ClinicModule } from './modules/clinic/clinic.module'
import { EmployeeModule } from './modules/employee/employee.module'
import { HealthModule } from './modules/health/health.module'
import { MedicineModule } from './modules/medicine/medicine.module'
import { PatientModule } from './modules/patient/patient.module'

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
		HealthModule,
		AuthModule,
		AdmissionModule,
		EmployeeModule,
		PatientModule,
		ClinicModule,
		MedicineModule,
	],
	providers: [
		{
			provide: APP_INTERCEPTOR,
			useClass: ClassSerializerInterceptor,
		},
	],
})
export class AppModule implements NestModule {
	constructor(private dataSource: DataSource) { }
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(LoggerMiddleware).forRoutes('*')

		consumer.apply(ValidateAccessTokenMiddleware)
			.exclude(
				'auth/(.*)',
				'/',
				{ path: 'health', method: RequestMethod.GET }
			)
			.forRoutes('*')
	}
}
