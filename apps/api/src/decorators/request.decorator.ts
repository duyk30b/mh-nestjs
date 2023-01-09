import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { Request } from 'express'
import { getClientIp } from 'request-ip'
import { RequestToken } from '../common/constants'

export const IpRequest = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
	const request: Request = ctx.switchToHttp().getRequest()
	return getClientIp(request)
})

export const CidRequest = createParamDecorator((data: unknown, ctx: ExecutionContext) => {
	const request: RequestToken = ctx.switchToHttp().getRequest()
	return request.tokenPayload.cid
})
