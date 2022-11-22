import { EError, ETokenError } from '@libs/utils'
import { HttpException, HttpStatus, Inject } from '@nestjs/common'
import { ConfigType } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import { IJwtPayload } from '../../common/constants'
import { JwtConfig } from '../../enviroments'
import EmployeeEntity from '../../typeorm/entities/employee.entity'

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

	createTokenFromEmployee(employee: EmployeeEntity) {
		const employeePaylod: IJwtPayload = {
			username: employee.username,
			role: employee.role,
			uid: employee.id,
			cid: employee.clinicId,
		}
		const accessToken = this.createAccessToken(employeePaylod)
		const refreshToken = this.createRefreshToken(employeePaylod)
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
