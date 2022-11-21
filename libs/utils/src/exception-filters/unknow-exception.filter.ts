import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus } from '@nestjs/common'
import { Request, Response } from 'express'

@Catch(Error)
export class UnknowExceptionFilter implements ExceptionFilter {
	catch(exception: Error, host: ArgumentsHost) {
		const ctx = host.switchToHttp()
		const response = ctx.getResponse<Response>()
		const request = ctx.getRequest<Request>()
		const httpStatus = HttpStatus.INTERNAL_SERVER_ERROR

		response.status(httpStatus).json({
			httpStatus,
			message: exception.message,
			path: request.url,
			timestamp: new Date().toISOString(),
		})
	}
}
