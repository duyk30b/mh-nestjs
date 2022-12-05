import { HttpException, HttpStatus, Inject } from '@nestjs/common'
import { ConfigType } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import UserEntity from '../../../../../typeorm/entities/user.entity'
import { IJwtPayload } from '../../common/constants'
import { JwtConfig } from '../../enviroments'
import { EError, ETokenError } from '../../exception-filters/exception.enum'

export class JwtExtendService {
	constructor(
		@Inject(JwtConfig.KEY) private jwtConfig: ConfigType<typeof JwtConfig>,
		private readonly jwtService: JwtService
	) { }

	createAccessToken(payload: object) {
		return this.jwtService.sign(payload, {
			secret: this.jwtConfig.accessKey,
			expiresIn: this.jwtConfig.accessTime,
		})
	}

	createRefreshToken(payload: object) {
		return this.jwtService.sign(payload, {
			secret: this.jwtConfig.refreshKey,
			expiresIn: this.jwtConfig.refreshTime,
		})
	}

	createTokenFromUser(user: UserEntity) {
		const userPayload: IJwtPayload = {
			username: user.username,
			role: user.role,
			uid: user.id,
			cid: user.clinicId,
		}
		const accessToken = this.createAccessToken(userPayload)
		const refreshToken = this.createRefreshToken(userPayload)
		return { accessToken, refreshToken }
	}

	verifyAccessToken(accessToken: string) {
		try {
			return this.jwtService.verify(accessToken, { secret: this.jwtConfig.accessKey })
		} catch (error) {
			if (error.name === 'TokenExpiredError') {
				throw new HttpException(ETokenError.Expired, HttpStatus.UNAUTHORIZED)
			} else if (error.name === 'JsonWebTokenError') {
				throw new HttpException(ETokenError.Invalid, HttpStatus.UNAUTHORIZED)
			}
			throw new HttpException(EError.Unknow, HttpStatus.INTERNAL_SERVER_ERROR)
		}
	}

	verifyRefreshToken(refreshToken: string) {
		try {
			return this.jwtService.verify(refreshToken, { secret: this.jwtConfig.refreshKey })
		} catch (error) {
			if (error.name === 'TokenExpiredError') {
				throw new HttpException(ETokenError.Expired, HttpStatus.UNAUTHORIZED)
			} else if (error.name === 'JsonWebTokenError') {
				throw new HttpException(ETokenError.Invalid, HttpStatus.UNAUTHORIZED)
			}
			throw new HttpException(EError.Unknow, HttpStatus.INTERNAL_SERVER_ERROR)
		}
	}
}
