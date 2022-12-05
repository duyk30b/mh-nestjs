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

	createAccessToken(user: UserEntity): string {
		const userPayload: IJwtPayload = {
			username: user.username,
			role: user.role,
			uid: user.id,
			cid: user.clinicId,
		}
		return this.jwtService.sign(userPayload, {
			secret: this.jwtConfig.accessKey,
			expiresIn: this.jwtConfig.accessTime,
		})
	}

	createRefreshToken(uid: number): string {
		return this.jwtService.sign({ uid }, {
			secret: this.jwtConfig.refreshKey,
			expiresIn: this.jwtConfig.refreshTime,
		})
	}

	createTokenFromUser(user: UserEntity) {
		const accessToken = this.createAccessToken(user)
		const refreshToken = this.createRefreshToken(user.id)
		return { accessToken, refreshToken }
	}

	verifyAccessToken(accessToken: string): IJwtPayload {
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

	verifyRefreshToken(refreshToken: string): { uid: number } {
		try {
			return this.jwtService.verify(refreshToken, { secret: this.jwtConfig.refreshKey })
		} catch (error) {
			if (error.name === 'TokenExpiredError') {
				throw new HttpException(ETokenError.Expired, HttpStatus.FORBIDDEN)
			} else if (error.name === 'JsonWebTokenError') {
				throw new HttpException(ETokenError.Invalid, HttpStatus.FORBIDDEN)
			}
			throw new HttpException(EError.Unknow, HttpStatus.INTERNAL_SERVER_ERROR)
		}
	}
}
