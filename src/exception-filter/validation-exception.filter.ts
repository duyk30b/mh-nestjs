import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus, ValidationError } from '@nestjs/common'
import { Request, Response } from 'express'

export class ValidationException extends Error {
	private readonly errors: ValidationError[]
	constructor(validationErrors: ValidationError[] = []) {
		super('VALIDATION_FAIL')
		this.errors = validationErrors
	}
	getMessage() {
		return this.message
	}
	getStatus() {
		return HttpStatus.BAD_REQUEST
	}
	getErrors() {
		return this.errors
	}
}

@Catch(ValidationException)
export class ValidationExceptionFilter implements ExceptionFilter {
	catch(exception: ValidationException, host: ArgumentsHost) {
		const ctx = host.switchToHttp()
		const response = ctx.getResponse<Response>()
		const request = ctx.getRequest<Request>()
		const status = exception.getStatus()
		const msg = exception.getMessage()
		const errors = exception.getErrors()

		response.status(status).json({
			statusCode: status,
			msg: msg,
			errors: errors,
			path: request.url,
			timestamp: new Date().toISOString(),
		})
	}
}
