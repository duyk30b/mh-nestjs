import { HttpExceptionFilter, UnknowExceptionFilter, ValidationException, ValidationExceptionFilter } from '@libs/utils'
import { ValidationError, ValidationPipe } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { NestFactory } from '@nestjs/core'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import * as requestIp from 'request-ip'
import { AppModule } from './app.module'
import { setupSwagger } from './common/swagger'
import { AccessLogInterceptor } from './interceptor/access-log.interceptor'
import { TimeoutInterceptor } from './interceptor/timeout.interceptor'

async function bootstrap() {
	const app = await NestFactory.create(AppModule)

	const configService = app.get(ConfigService)
	const PORT = configService.get('SERVER_PORT')

	app.use(helmet())
	app.use(rateLimit({
		windowMs: 15 * 60 * 1000, // 15 minutes
		max: 100, // limit each IP to 100 requests per windowMs
	}))
	app.enableCors()

	app.use(requestIp.mw())

	app.useGlobalInterceptors(
		new AccessLogInterceptor(),
		new TimeoutInterceptor()
	)
	app.useGlobalFilters(
		new UnknowExceptionFilter(),
		new HttpExceptionFilter(),
		new ValidationExceptionFilter()
	)

	app.useGlobalPipes(new ValidationPipe({
		validationError: { target: false, value: true },
		skipMissingProperties: true,
		exceptionFactory: (errors: ValidationError[] = []) => new ValidationException(errors),
	}))

	if (configService.get('NODE_ENV') !== 'production') {
		setupSwagger(app)
	}

	await app.listen(PORT)
}
bootstrap()
