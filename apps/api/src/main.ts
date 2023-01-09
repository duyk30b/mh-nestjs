import { ValidationError, ValidationPipe } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { NestFactory, Reflector } from '@nestjs/core'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'
import * as requestIp from 'request-ip'
import { AppModule } from './app.module'
import { setupSwagger } from './common/swagger'
import { HttpExceptionFilter } from './exception-filters/http-exception.filter'
import { UnknownExceptionFilter } from './exception-filters/unknown-exception.filter'
import { ValidationException, ValidationExceptionFilter } from './exception-filters/validation-exception.filter'
import { RolesGuard } from './guards/roles.guard'
import { AccessLogInterceptor } from './interceptor/access-log.interceptor'
import { TimeoutInterceptor } from './interceptor/timeout.interceptor'

async function bootstrap() {
	const app = await NestFactory.create(AppModule)

	const configService = app.get(ConfigService)
	const PORT = configService.get('NESTJS_PORT')
	const HOST = configService.get('NESTJS_HOST') || 'localhost'

	app.use(helmet())
	app.use(rateLimit({
		windowMs: 60 * 1000, // 1 minutes
		max: 100, // limit each IP to 100 requests per windowMs
	}))
	app.enableCors()

	app.use(requestIp.mw())

	app.useGlobalInterceptors(
		new AccessLogInterceptor(),
		new TimeoutInterceptor()
	)
	app.useGlobalFilters(
		new UnknownExceptionFilter(),
		new HttpExceptionFilter(),
		new ValidationExceptionFilter()
	)
	
	app.useGlobalGuards(new RolesGuard(app.get(Reflector)))

	app.useGlobalPipes(new ValidationPipe({
		validationError: { target: false, value: true },
		skipMissingProperties: true, // không validate những property undefined
		whitelist: true, // loại bỏ các property không có trong DTO
		forbidNonWhitelisted: true, // xuất hiện property không có trong DTO sẽ bắt lỗi
		transform: true, // use for DTO
		transformOptions: {
			excludeExtraneousValues: false, // exclude field not in class DTO => no
			exposeUnsetFields: false, // expose field undefined in DTO => no
		},
		exceptionFactory: (errors: ValidationError[] = []) => new ValidationException(errors),
	}))

	if (configService.get('NODE_ENV') !== 'production') {
		setupSwagger(app)
	}

	await app.listen(PORT, () => {
		console.log(`🚀 Server document: http://${HOST}:${PORT}/document`)
	})
}
bootstrap()
