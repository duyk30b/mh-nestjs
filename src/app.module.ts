import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { TypeOrmModule, TypeOrmModuleOptions } from '@nestjs/typeorm'
import { DataSource } from 'typeorm'
import Env from './config'
import { LoggerMiddleware } from './middlewares/logger.middleware'
import { CustomerModule } from './modules/customer/customer.module'
import { ProviderModule } from './modules/provider/provider.module'
import { UserModule } from './modules/user/user.module'
import { AuthModule } from './modules/auth/auth.module'

@Module({
	imports: [
		TypeOrmModule.forRoot(Env.mysql as TypeOrmModuleOptions),
		UserModule,
		ProviderModule,
		CustomerModule,
		AuthModule,
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
