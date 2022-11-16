import { NestFactory } from '@nestjs/core'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import { AppModule } from './app.module'
import { setupSwagger } from './common/swagger'
import Env from './config'
import { HttpExceptionFilter } from './exception-filter/http-exception.filter'
import { ValidationExceptionFilter } from './exception-filter/validation-exception.filter'
import { AccessLogInterceptor } from './interceptor/access-log.interceptor'
import { TimeoutInterceptor } from './interceptor/timeout.interceptor'
import * as requestIp from 'request-ip'

async function bootstrap() {
	const PORT = Env.server.port
	const app = await NestFactory.create(AppModule)

	app.use(helmet())
	app.use(rateLimit({
		windowMs: 15 * 60 * 1000, // 15 minutes
		max: 100, // limit each IP to 100 requests per windowMs
	}))
	app.enableCors()

	app.use(requestIp.mw())

	app.useGlobalInterceptors(
		new AccessLogInterceptor(),
		new TimeoutInterceptor(),
	)
	app.useGlobalFilters(
		new ValidationExceptionFilter(),
		new HttpExceptionFilter(),
	)

	setupSwagger(app)

	await app.listen(PORT)
}
bootstrap()
