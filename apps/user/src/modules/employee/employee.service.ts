import { Injectable, HttpStatus, HttpException } from '@nestjs/common'
import { CreateEmployeeDto } from './dto/create-employee.dto'
import { UpdateEmployeeDto } from './dto/update-employee.dto'
import * as bcrypt from 'bcrypt'
import { DataSource } from 'typeorm'
import EmployeeEntity from '../../typeorm/entities/employee.entity'
import { EEmployeeError } from '@libs/utils'

@Injectable()
export class EmployeeService {
	constructor(private dataSource: DataSource) { }

	async create(createEmployeeDto: CreateEmployeeDto) {
		const { username, password, clinicId } = createEmployeeDto
		const hashPassword = await bcrypt.hash(password, 5)

		const employee = await this.dataSource.transaction(async (manager) => {
			const findEmployee = await manager.findOne(EmployeeEntity, { where: { username, clinicId } })
			if (findEmployee) {
				throw new HttpException(EEmployeeError.UsernameExists, HttpStatus.BAD_GATEWAY)
			}
			const createEmployee = manager.create(EmployeeEntity, {
				clinicId,
				username,
				password: hashPassword,
			})
			const newEmployee = await manager.save(createEmployee)
			return newEmployee
		})
		return employee
	}

	findAll() {
		return `This action returns all employee`
	}

	findOne(id: number) {
		return `This action returns a #${id} employee`
	}

	update(id: number, updateEmployeeDto: UpdateEmployeeDto) {
		return `This action updates a #${id} employee`
	}

	remove(id: number) {
		return `This action removes a #${id} employee`
	}
}
