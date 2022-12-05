import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import * as bcrypt from 'bcrypt'
import { DataSource } from 'typeorm'
import UserEntity from '../../../../../typeorm/entities/user.entity'
import { EUserError } from '../../exception-filters/exception.enum'
import { CreateUserDto } from './dto/create-user.dto'
import { UpdateUserDto } from './dto/update-user.dto'

@Injectable()
export class UserService {
	constructor(private dataSource: DataSource) { }

	async create(createUserDto: CreateUserDto) {
		const { username, password, clinicId } = createUserDto
		const hashPassword = await bcrypt.hash(password, 5)

		const user = await this.dataSource.transaction(async (manager) => {
			const findUser = await manager.findOne(UserEntity, { where: { username, clinicId } })
			if (findUser) {
				throw new HttpException(EUserError.UsernameExists, HttpStatus.BAD_GATEWAY)
			}
			const createUser = manager.create(UserEntity, {
				clinicId,
				username,
				password: hashPassword,
			})
			const newUser = await manager.save(createUser)
			return newUser
		})
		return user
	}

	findAll() {
		return `This action returns all user`
	}

	findOne(id: number) {
		return `This action returns a #${id} user`
	}

	update(id: number, updateUserDto: UpdateUserDto) {
		return `This action updates a #${id} user`
	}

	remove(id: number) {
		return `This action removes a #${id} user`
	}
}
