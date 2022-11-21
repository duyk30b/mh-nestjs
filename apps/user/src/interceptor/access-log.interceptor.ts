import { CallHandler, ExecutionContext, Injectable, NestInterceptor, Logger } from '@nestjs/common'
import { getClientIp } from 'request-ip'
import { Observable } from 'rxjs'
import { tap } from 'rxjs/operators'

@Injectable()
export class AccessLogInterceptor implements NestInterceptor {
	constructor(private readonly logger = new Logger('ACCESS_LOG')) { }

	intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
		const startTime = new Date()
		const ctx = context.switchToHttp()
		const request = ctx.getRequest()
		const response = ctx.getRequest()

		const { url, method } = request
		const { statusCode } = response
		const ip = getClientIp(request)

		return next.handle().pipe(tap(() => {
			const msg = `${startTime.toISOString()} | ${ip} | ${method} | ${statusCode} | ${url} | ${Date.now() - startTime.getTime()}ms`
			return this.logger.log(msg)
		}))
	}
}
