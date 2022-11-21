import { ELoginError, ERegisterError, randomString } from '@libs/utils'
import { HttpException, HttpStatus, Inject, Injectable } from '@nestjs/common'
import { ConfigType } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import { JwtConfig } from 'apps/user/src/enviroments'
import * as bcrypt from 'bcrypt'
import { DataSource } from 'typeorm'
import ClinicEntity from '../../typeorm/entities/clinic.entity'
import EmployeeEntity, { UserRole } from '../../typeorm/entities/employee.entity'
import { LoginDto } from './auth.dto'

@Injectable()
export class AuthService {
	constructor(
		@Inject(JwtConfig.KEY) private jwtConfig: ConfigType<typeof JwtConfig>,
		private readonly jwtService: JwtService,
		private dataSource: DataSource
	) { }

	async register(createClinicDto: { email: string; phone: string; password: string }): Promise<EmployeeEntity> {
		const { email, phone, password } = createClinicDto
		const hashPassword = await bcrypt.hash(password, 5)

		const { employee } = await this.dataSource.transaction(async (manager) => {
			const findEmployee = await manager.findOne(EmployeeEntity, {
				where: [
					{ email, role: UserRole.OWNER },
					{ phone, role: UserRole.OWNER },
				],
			})
			if (findEmployee) {
				if (findEmployee.email === email && findEmployee.phone === phone) {
					throw new HttpException(ERegisterError.ExistEmailAndPhone, HttpStatus.BAD_REQUEST)
				}
				else if (findEmployee.email === email) {
					throw new HttpException(ERegisterError.ExistEmail, HttpStatus.BAD_REQUEST)
				}
				else if (findEmployee.phone === phone) {
					throw new HttpException(ERegisterError.ExistPhone, HttpStatus.BAD_REQUEST)
				}
			}

			const createClinic = manager.create(ClinicEntity, {
				code: randomString(5),
				level: 1,
			})
			const newClinic = await manager.save(createClinic)

			const createEmployee = manager.create(EmployeeEntity, {
				clinicId: newClinic.id,
				email,
				phone,
				username: 'Admin',
				password: hashPassword,
				role: UserRole.OWNER,
			})
			const newEmployee = await manager.save(createEmployee)
			return { clinic: newClinic, employee: newEmployee }
		})
		return employee
	}

	async login(loginDto: LoginDto): Promise<EmployeeEntity> {
		let employee: EmployeeEntity
		if (loginDto.email) {
			employee = await this.dataSource.manager.findOneBy(EmployeeEntity, { email: loginDto.email })
		} else if (loginDto.username) {
			employee = await this.dataSource.manager.findOneBy(EmployeeEntity, { username: loginDto.username })
		}
		if (!employee) {
			throw new HttpException(ELoginError.UserDoesNotExist, HttpStatus.BAD_REQUEST)
		}

		const checkPassword = await bcrypt.compare(loginDto.password, employee.password)
		if (!checkPassword) {
			throw new HttpException(ELoginError.WrongPassword, HttpStatus.BAD_GATEWAY)
		}

		return employee
	}

	createAccessToken(payload: object) {
		return this.jwtService.sign(payload, {
			privateKey: this.jwtConfig.accessKey,
			expiresIn: this.jwtConfig.accessTime,
		})
	}

	createRefreshToken(payload: object) {
		return this.jwtService.sign(payload, {
			privateKey: this.jwtConfig.refreshKey,
			expiresIn: this.jwtConfig.refreshTime,
		})
	}
}
