import { Injectable } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { Repository } from 'typeorm'
import AdmissionEntity from '../../../../../typeorm/entities/admission.entity'
import { CreateAdmissionDto, UpdateAdmissionDto } from './admission.dto'

@Injectable()
export class AdmissionService {
	constructor(@InjectRepository(AdmissionEntity) private admissionRepository: Repository<AdmissionEntity>) { }

	findAll() {
		return `This action returns all admission`
	}

	findOne(id: number) {
		return `This action returns a #${id} admission`
	}
	create(clinicId: number, createAdmissionDto: CreateAdmissionDto) {
		return 'This action adds a new admission'
	}
	update(id: number, updateAdmissionDto: UpdateAdmissionDto) {
		return `This action updates a #${id} admission`
	}

	remove(id: number) {
		return `This action removes a #${id} admission`
	}
}
