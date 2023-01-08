import { HttpException, HttpStatus, Inject } from '@nestjs/common'
import { ConfigType } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import UserEntity from '../../../../../typeorm/entities/employee.entity'
import { IJwtPayload } from '../../common/constants'
import { JwtConfig } from '../../environments'
import { EError, ETokenError } from '../../exception-filters/exception.enum'

export class JwtExtendService {
	constructor(
		@Inject(JwtConfig.KEY) private jwtConfig: ConfigType<typeof JwtConfig>,
		private readonly jwtService: JwtService
	) { }

	createAccessToken(user: UserEntity, ip: string): string {
		const userPayload: IJwtPayload = {
			ip,
			cPhone: user.clinic.phone,
			cid: user.clinic.id,
			uid: user.id,
			username: user.username,
			role: user.role,
		}
		return this.jwtService.sign(userPayload, {
			secret: this.jwtConfig.accessKey,
			expiresIn: this.jwtConfig.accessTime,
		})
	}

	createRefreshToken(uid: number, ip: string): string {
		return this.jwtService.sign({ uid, ip }, {
			secret: this.jwtConfig.refreshKey,
			expiresIn: this.jwtConfig.refreshTime,
		})
	}

	createTokenFromUser(user: UserEntity, ip: string) {
		const accessToken = this.createAccessToken(user, ip)
		const refreshToken = this.createRefreshToken(user.id, ip)
		return { accessToken, refreshToken }
	}

	verifyAccessToken(accessToken: string, ip: string): IJwtPayload {
		try {
			const jwtPayload: IJwtPayload = this.jwtService.verify(accessToken, { secret: this.jwtConfig.accessKey })
			if (jwtPayload.ip !== ip) {
				throw new HttpException(ETokenError.Invalid, HttpStatus.UNAUTHORIZED)
			}
			return jwtPayload
		} catch (error) {
			if (error.name === 'TokenExpiredError') {
				throw new HttpException(ETokenError.Expired, HttpStatus.UNAUTHORIZED)
			} else if (error.name === 'JsonWebTokenError') {
				throw new HttpException(ETokenError.Invalid, HttpStatus.UNAUTHORIZED)
			}
			throw new HttpException(EError.Unknown, HttpStatus.INTERNAL_SERVER_ERROR)
		}
	}

	verifyRefreshToken(refreshToken: string, ip: string): { uid: number } {
		try {
			const jwtPayload = this.jwtService.verify(refreshToken, { secret: this.jwtConfig.refreshKey })
			if (jwtPayload.ip !== ip) {
				throw new HttpException(ETokenError.Invalid, HttpStatus.UNAUTHORIZED)
			}
			return jwtPayload
		} catch (error) {
			if (error.name === 'TokenExpiredError') {
				throw new HttpException(ETokenError.Expired, HttpStatus.FORBIDDEN)
			} else if (error.name === 'JsonWebTokenError') {
				throw new HttpException(ETokenError.Invalid, HttpStatus.FORBIDDEN)
			}
			throw new HttpException(EError.Unknown, HttpStatus.INTERNAL_SERVER_ERROR)
		}
	}
}
