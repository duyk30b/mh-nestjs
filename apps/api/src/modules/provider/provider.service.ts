import { Injectable } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { Repository } from 'typeorm'
import ProviderEntity from '../../../../../typeorm/entities/provider.entity'
import { CreateProviderDto } from './dto/create-provider.dto'
import { UpdateProviderDto } from './dto/update-provider.dto'

@Injectable()
export class ProviderService {
	constructor(@InjectRepository(ProviderEntity)
		private providersRepository: Repository<ProviderEntity>) { }

	create(createProviderDto: CreateProviderDto) {
		return 'This action adds a new provider'
	}

	findAll() {
		return this.providersRepository.find()
	}

	findOne(id: number) {
		return this.providersRepository.findOneBy({ id })
	}

	update(id: number, updateProviderDto: UpdateProviderDto) {
		return `This action updates a #${id} provider`
	}

	async remove(id: number) {
		await this.providersRepository.delete(id)
	}
}
