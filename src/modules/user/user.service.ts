import { Injectable } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import UserEntity from 'src/typeorm/entities/user.entity'
import { Repository } from 'typeorm'
import { CreateUserDto } from './dto/create-user.dto'
import { UpdateUserDto } from './dto/update-user.dto'

@Injectable()
export class UserService {
	constructor(
		@InjectRepository(UserEntity)
		private usersRepository: Repository<UserEntity>,
	) { }

	create(createUserDto: CreateUserDto): Promise<UserEntity> {
		return this.usersRepository.save(createUserDto)
	}

	findAll(): Promise<UserEntity[]> {
		return this.usersRepository.find()
	}

	findOne(id: number): Promise<UserEntity> {
		return this.usersRepository.findOneBy({ id })
	}

	update(id: number, updateUserDto: UpdateUserDto) {
		return `This action updates a #${id} user`
	}

	remove(id: number): Promise<any> {
		return this.usersRepository.delete(id)
	}
}
