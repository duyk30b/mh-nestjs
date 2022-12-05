import { Injectable, NestMiddleware } from '@nestjs/common'
import { NextFunction, Request, Response } from 'express'
import { IJwtPayload, RequestToken } from '../common/constants'
import { JwtExtendService } from '../modules/auth/jwt-extend.service'

@Injectable()
export class ValidateAccessTokenMiddleware implements NestMiddleware {
	constructor(private readonly jwtExtendService: JwtExtendService) { }

	async use(req: RequestToken, res: Response, next: NextFunction) {
		const authorization = req.header('Authorization') || ''
		const [, accessToken] = authorization.split(' ')
		const decode: IJwtPayload = this.jwtExtendService.verifyAccessToken(accessToken)
		req.tokenPayload = decode
		next()
	}
}
