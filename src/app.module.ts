import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common'
import { TypeOrmModule } from '@nestjs/typeorm'
import { DataSource } from 'typeorm'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { LoggerMiddleware } from './common/logger.middleware'
import { UserModule } from './user/user.module'
import { ConfigModule } from '@nestjs/config'

@Module({
	imports: [
		TypeOrmModule.forRoot({
			type: 'mysql',
			host: 'localhost',
			port: 7306,
			username: 'medihome',
			password: 'mh123456',
			database: 'mh_database',
			entities: [],
			// synchronize: true,
		}),
		ConfigModule.forRoot(),
		UserModule,
	],
	controllers: [AppController],
	providers: [AppService],
})
export class AppModule implements NestModule {
	constructor(private dataSource: DataSource) { }
	configure(consumer: MiddlewareConsumer) {
		consumer
			.apply(LoggerMiddleware)
			.forRoutes('user')
	}
}
