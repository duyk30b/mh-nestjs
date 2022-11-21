import { Inject, Injectable } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import UserEntity from '../../typeorm/entities/employee.entity'
import { Repository } from 'typeorm'
import { CreateUserDto } from './dto/create-user.dto'
import { UpdateUserDto } from './dto/update-user.dto'
import { JwtConfig } from '../../enviroments'
import { ConfigType } from '@nestjs/config'

@Injectable()
export class UserService {
	constructor(
		@InjectRepository(UserEntity) private usersRepository: Repository<UserEntity>,
		@Inject(JwtConfig.KEY) private jwtConfig: ConfigType<typeof JwtConfig>
	) { }

	async checkUserExist(info: { email: string; username: string; phone: string }) {
		this.usersRepository.find()
		console.log('-----------------------', this.jwtConfig.accessKey)
		return true
	}

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
