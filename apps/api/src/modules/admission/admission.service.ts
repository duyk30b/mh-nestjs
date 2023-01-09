import { Injectable } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { instanceToPlain, plainToInstance } from 'class-transformer'
import { Repository } from 'typeorm'
import AdmissionEntity from '../../../../../typeorm/entities/admission.entity'
import PatientEntity from '../../../../../typeorm/entities/patient.entity'
import { CreateAdmissionDto, PatientDto, UpdateAdmissionDto } from './admission.dto'

@Injectable()
export class AdmissionService {
	constructor(
		@InjectRepository(AdmissionEntity) private admissionRepository: Repository<AdmissionEntity>,
		@InjectRepository(PatientEntity) private patientRepository: Repository<PatientEntity>
	) { }

	findAll() {
		return `This action returns all admission`
	}

	findOne(id: number) {
		return `This action returns a #${id} admission`
	}

	async create(clinicId: number, createAdmissionDto: CreateAdmissionDto) {
		const admission = plainToInstance(AdmissionEntity, createAdmissionDto, { exposeUnsetFields: false })
		admission.clinicId = clinicId
		admission.patient.clinicId = clinicId

		if (!admission.patient.id) {
			admission.patient = await this.patientRepository.save(admission.patient)
		} else {
			admission.patient = await this.patientRepository.findOneBy({ id: admission.patient.id })
		}

		admission.patientId = admission.patient.id
		return await this.admissionRepository.save(admission)
	}

	update(id: number, updateAdmissionDto: UpdateAdmissionDto) {
		return `This action updates a #${id} admission`
	}

	remove(id: number) {
		return `This action removes a #${id} admission`
	}
}
