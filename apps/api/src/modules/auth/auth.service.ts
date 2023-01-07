import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import * as bcrypt from 'bcrypt'
import { DataSource } from 'typeorm'
import ClinicEntity from '../../../../../typeorm/entities/clinic.entity'
import EmployeeEntity, { EEmployeeRole } from '../../../../../typeorm/entities/employee.entity'
import { ELoginError, ERegisterError } from '../../exception-filters/exception.enum'
import { LoginDto, RegisterDto } from './auth.dto'
import { JwtExtendService } from './jwt-extend.service'

@Injectable()
export class AuthService {
	constructor(
		private dataSource: DataSource,
		private jwtExtendService: JwtExtendService
	) { }

	async register(registerDto: RegisterDto): Promise<EmployeeEntity> {
		const { email, phone, username, password } = registerDto
		const hashPassword = await bcrypt.hash(password, 5)

		const employee = await this.dataSource.transaction(async (manager) => {
			const findClinic = await manager.findOne(ClinicEntity, { where: [{ email }, { phone }] })
			if (findClinic) {
				if (findClinic.email === email && findClinic.phone === phone) {
					throw new HttpException(ERegisterError.ExistEmailAndPhone, HttpStatus.BAD_REQUEST)
				}
				else if (findClinic.email === email) {
					throw new HttpException(ERegisterError.ExistEmail, HttpStatus.BAD_REQUEST)
				}
				else if (findClinic.phone === phone) {
					throw new HttpException(ERegisterError.ExistPhone, HttpStatus.BAD_REQUEST)
				}
			}
			const snapClinic = manager.create(ClinicEntity, {
				phone,
				email,
				level: 1,
			})
			const newClinic = await manager.save(snapClinic)

			const snapEmployee = manager.create(EmployeeEntity, {
				clinicId: newClinic.id,
				clinic: newClinic,
				username,
				password: hashPassword,
				role: EEmployeeRole.Owner,
			})
			const newEmployee = await manager.save(snapEmployee)

			return newEmployee
		})

		return employee
	}

	async login(loginDto: LoginDto): Promise<EmployeeEntity> {
		const employee = await this.dataSource.manager.findOne(EmployeeEntity, {
			relations: { clinic: true },
			where: {
				username: loginDto.username,
				clinic: { phone: loginDto.cPhone },
			},
		})
		if (!employee) throw new HttpException(ELoginError.EmployeeDoesNotExist, HttpStatus.BAD_REQUEST)

		const checkPassword = await bcrypt.compare(loginDto.password, employee.password)
		if (!checkPassword) throw new HttpException(ELoginError.WrongPassword, HttpStatus.BAD_GATEWAY)

		return employee
	}

	async grantAccessToken(refreshToken: string): Promise<string> {
		const { uid } = this.jwtExtendService.verifyRefreshToken(refreshToken)

		const employee = await this.dataSource.getRepository(EmployeeEntity).findOne({
			relations: { clinic: true },
			where: { id: uid },
		})

		const accessToken = this.jwtExtendService.createAccessToken(employee)
		return accessToken
	}
}
