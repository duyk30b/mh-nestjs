import { HttpStatus, Injectable } from '@nestjs/common'
import { HttpException } from '@nestjs/common/exceptions'
import { InjectRepository } from '@nestjs/typeorm'
import { Equal, Like, Repository } from 'typeorm'
import PatientEntity from '../../../../../typeorm/entities/patient.entity'
import { EPatientError } from '../../exception-filters/exception.enum'
import { CreatePatientDto, UpdatePatientDto } from './patient.dto'

@Injectable()
export class PatientService {
	constructor(@InjectRepository(PatientEntity) private patientRepository: Repository<PatientEntity>) { }

	async findAll(clinicId: number): Promise<PatientEntity[]> {
		const patientList = await this.patientRepository.find({ where: { clinicId } })
		return patientList
	}

	async create(clinicId: number, createPatientDto: CreatePatientDto): Promise<PatientEntity> {
		const patient = await this.patientRepository.save({
			clinicId,
			...createPatientDto,
		})
		return patient
	}

	async findOne(clinicId: number, id: number) {
		const patient = await this.patientRepository.findOneBy({ clinicId, id })
		return patient
	}

	async findByPhone(clinicId: number, phone: string): Promise<PatientEntity[]> {
		const patientList = await this.patientRepository.find({
			where: {
				clinicId: Equal(clinicId),
				phone: Like(`${phone}%`),
			},
			skip: 0,
			take: 10,
		})
		return patientList
	}
	async findByFullName(clinicId: number, fullName: string): Promise<PatientEntity[]> {
		const patientList = await this.patientRepository.find({
			where: {
				clinicId: Equal(clinicId),
				fullName: Like(`${fullName}%`),
			},
			skip: 0,
			take: 10,
		})
		return patientList
	}

	async update(clinicId: number, id: number, updatePatientDto: UpdatePatientDto) {
		const findPatient = await this.patientRepository.findOneBy({ clinicId, id })
		if (!findPatient) {
			throw new HttpException(EPatientError.NotExists, HttpStatus.BAD_REQUEST)
		}
		return await this.patientRepository.update({ clinicId, id }, updatePatientDto)
	}

	async remove(clinicId: number, id: number) {
		return await this.patientRepository.softDelete({
			clinicId,
			id,
		})
	}

	async restore(clinicId: number, employeeId: number) {
		return await this.patientRepository.restore({
			clinicId,
			id: employeeId,
		})
	}
}
