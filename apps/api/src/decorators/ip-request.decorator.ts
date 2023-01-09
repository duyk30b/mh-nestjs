import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { getClientIp } from 'request-ip'

export const IpRequest = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
	const request: Request = ctx.switchToHttp().getRequest()
	return getClientIp(request)
})
