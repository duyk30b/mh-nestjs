import { Body, Controller, Delete, Get, Param, Patch, Post, HttpException, HttpStatus } from '@nestjs/common'
import { ApiTags } from '@nestjs/swagger'
import { CreateUserDto } from './dto/create-user.dto'
import { UpdateUserDto } from './dto/update-user.dto'
import { UserService } from './user.service'

@ApiTags('user')
@Controller('user')
export class UserController {
	constructor(private readonly userService: UserService) { }

	@Post()
	create(@Body() createUserDto: CreateUserDto) {
		return this.userService.create(createUserDto)
	}

	@Get()
	async findAll() {
		const a = new Promise((res, rej) => {
			setTimeout(() => {
				res(1123)
			}, 10000)
		})
		await a
		return this.userService.findAll()
	}

	@Get(':id')
	findOne(@Param('id') id: string) {
		throw new Error('Khoong biet loi gif')
	}

	@Patch(':id')
	update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
		throw new HttpException('Http exception', HttpStatus.FORBIDDEN)
	}

	@Delete(':id')
	remove(@Param('id') id: string) {
		return this.userService.remove(+id)
	}
}
