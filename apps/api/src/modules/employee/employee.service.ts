import { Injectable } from '@nestjs/common'
import { HttpStatus } from '@nestjs/common/enums'
import { HttpException } from '@nestjs/common/exceptions'
import { InjectRepository } from '@nestjs/typeorm'
import * as bcrypt from 'bcrypt'
import { plainToClass } from 'class-transformer'
import { Repository } from 'typeorm'
import EmployeeEntity, { EEmployeeRole } from '../../../../../typeorm/entities/employee.entity'
import { EEmployeeError, ERegisterError } from '../../exception-filters/exception.enum'
import { CreateEmployeeDto, UpdateEmployeeDto } from './employee.dto'

@Injectable()
export class EmployeeService {
	constructor(@InjectRepository(EmployeeEntity) private employeeRepository: Repository<EmployeeEntity>) { }

	async findAll(clinicId: number): Promise<EmployeeEntity[]> {
		return await this.employeeRepository.find({ where: { clinicId } })
	}

	async create(clinicId: number, createEmployeeDto: CreateEmployeeDto): Promise<EmployeeEntity> {
		const findEmployee = await this.employeeRepository.findOneBy({
			clinicId,
			username: createEmployeeDto.username,
		})
		if (findEmployee) {
			throw new HttpException(ERegisterError.ExistUsername, HttpStatus.BAD_REQUEST)
		}
		const snapEmployee = plainToClass(EmployeeEntity, createEmployeeDto)
		snapEmployee.password = await bcrypt.hash(createEmployeeDto.password, 5)
		snapEmployee.role = EEmployeeRole.User
		return await this.employeeRepository.save(createEmployeeDto)
	}

	async findOne(clinicId: number, id: number) {
		return await this.employeeRepository.findOneBy({ clinicId, id })
	}

	async update(clinicId: number, id: number, updateEmployeeDto: UpdateEmployeeDto) {
		const findEmployee = await this.employeeRepository.findOneBy({ clinicId, id })
		if (!findEmployee) {
			throw new HttpException(EEmployeeError.NotExists, HttpStatus.BAD_REQUEST)
		}
		return await this.employeeRepository.update({ clinicId, id }, updateEmployeeDto)
	}

	async remove(clinicId: number, employeeId: number) {
		return await this.employeeRepository.softDelete({
			clinicId,
			id: employeeId,
		})
	}

	async restore(clinicId: number, employeeId: number) {
		return await this.employeeRepository.restore({
			clinicId,
			id: employeeId,
		})
	}
}
