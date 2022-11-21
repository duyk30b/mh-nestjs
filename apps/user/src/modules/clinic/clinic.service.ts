import { Injectable } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { DataSource, Repository } from 'typeorm'
import ClinicEntity from '../../typeorm/entities/clinic.entity'

@Injectable()
export class ClinicService {
	constructor(
		@InjectRepository(ClinicEntity) private clinicRepository: Repository<ClinicEntity>,
		private dataSource: DataSource
	) { }

	findAll() {
		return `This action returns all clinic`
	}

	findOne(id: number) {
		return `This action returns a #${id} clinic`
	}

	update(id: number) {
		return `This action updates a #${id} clinic`
	}

	remove(id: number) {
		return `This action removes a #${id} clinic`
	}
}
