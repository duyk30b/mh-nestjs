import { randomString } from '@libs/utils'
import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import * as bcrypt from 'bcrypt'
import { DataSource } from 'typeorm'
import ClinicEntity from '../../../../../typeorm/entities/clinic.entity'
import UserEntity, { EUserRole } from '../../../../../typeorm/entities/user.entity'
import { ELoginError, ERegisterError } from '../../exception-filters/exception.enum'
import { LoginDto, RegisterDto } from './auth.dto'
import { JwtExtendService } from './jwt-extend.service'

@Injectable()
export class AuthService {
	constructor(
		private dataSource: DataSource,
		private jwtExtendService: JwtExtendService
	) { }

	async register(registerDto: RegisterDto): Promise<UserEntity> {
		const { email, phone, password } = registerDto
		const hashPassword = await bcrypt.hash(password, 5)

		const { user } = await this.dataSource.transaction(async (manager) => {
			const findUser = await manager.findOne(UserEntity, {
				where: [
					{ email, role: EUserRole.Owner },
					{ phone, role: EUserRole.Owner },
				],
			})
			if (findUser) {
				if (findUser.email === email && findUser.phone === phone) {
					throw new HttpException(ERegisterError.ExistEmailAndPhone, HttpStatus.BAD_REQUEST)
				}
				else if (findUser.email === email) {
					throw new HttpException(ERegisterError.ExistEmail, HttpStatus.BAD_REQUEST)
				}
				else if (findUser.phone === phone) {
					throw new HttpException(ERegisterError.ExistPhone, HttpStatus.BAD_REQUEST)
				}
			}

			const createClinic = manager.create(ClinicEntity, {
				code: randomString(5),
				level: 1,
			})
			const newClinic = await manager.save(createClinic)

			const createUser = manager.create(UserEntity, {
				clinicId: newClinic.id,
				email,
				phone,
				username: 'Admin',
				password: hashPassword,
				role: EUserRole.Owner,
			})
			const newUser = await manager.save(createUser)
			return { clinic: newClinic, user: newUser }
		})
		return user
	}

	async login(loginDto: LoginDto): Promise<UserEntity> {
		let user: UserEntity
		if (loginDto.email) {
			user = await this.dataSource.manager.findOneBy(UserEntity, { email: loginDto.email })
		} else if (loginDto.username) {
			user = await this.dataSource.manager.findOneBy(UserEntity, { username: loginDto.username })
		}
		if (!user) {
			throw new HttpException(ELoginError.UserDoesNotExist, HttpStatus.BAD_REQUEST)
		}

		const checkPassword = await bcrypt.compare(loginDto.password, user.password)
		if (!checkPassword) {
			throw new HttpException(ELoginError.WrongPassword, HttpStatus.BAD_GATEWAY)
		}

		return user
	}

	async grantAccessToken(refreshToken: string): Promise<string> {
		const { uid } = this.jwtExtendService.verifyRefreshToken(refreshToken)
		const user = await this.dataSource.manager.findOneBy(UserEntity, { id: uid })
		const accessToken = this.jwtExtendService.createAccessToken(user)
		return accessToken
	}
}
