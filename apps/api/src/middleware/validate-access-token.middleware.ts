import { Injectable, NestMiddleware } from '@nestjs/common'
import { NextFunction, Response } from 'express'
import { getClientIp } from 'request-ip'
import { IJwtPayload, RequestToken } from '../common/constants'
import { JwtExtendService } from '../modules/auth/jwt-extend.service'

@Injectable()
export class ValidateAccessTokenMiddleware implements NestMiddleware {
	constructor(private readonly jwtExtendService: JwtExtendService) { }

	async use(req: RequestToken, res: Response, next: NextFunction) {
		const ip = getClientIp(req)
		const authorization = req.header('Authorization') || ''
		const [, accessToken] = authorization.split(' ')
		const decode: IJwtPayload = this.jwtExtendService.verifyAccessToken(accessToken, ip)
		req.tokenPayload = decode
		next()
	}
}
