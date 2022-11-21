import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus, ValidationError } from '@nestjs/common'
import { Request, Response } from 'express'
import { EValidateError } from './exception.enum'

export class ValidationException extends Error {
	private readonly errors: ValidationError[]
	constructor(validationErrors: ValidationError[] = []) {
		super(EValidateError.FAILD)
		this.errors = validationErrors
	}
	getMessage() {
		return this.message
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
		const httpStatus = HttpStatus.BAD_REQUEST
		const message = exception.getMessage()
		const errors = exception.getErrors()

		response.status(httpStatus).json({
			httpStatus,
			message,
			errors,
			path: request.url,
			timestamp: new Date().toISOString(),
		})
	}
}
