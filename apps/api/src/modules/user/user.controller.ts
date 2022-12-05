import { Body, Controller, Delete, Get, Param, Patch, Post, Req } from '@nestjs/common'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'
import { RequestToken } from '../../common/constants'
import { UserRoles } from '../../guards/user-roles.guard'
import { CreateUserDto } from './dto/create-user.dto'
import { UpdateUserDto } from './dto/update-user.dto'
import { UserService } from './user.service'

@ApiTags('User')
@ApiBearerAuth('access-token')
@Controller('user')
export class UserController {
	constructor(private readonly userService: UserService) { }

	@Post()
	@UserRoles('Owner', 'Admin')
	async create(@Body() createUserDto: CreateUserDto, @Req() request: RequestToken) {
		createUserDto.clinicId = request.tokenPayload.cid
		return this.userService.create(createUserDto)
	}

	@Get()
	findAll() {
		return this.userService.findAll()
	}

	@Get(':id')
	findOne(@Param('id') id: string) {
		return this.userService.findOne(+id)
	}

	@Patch(':id')
	update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
		return this.userService.update(+id, updateUserDto)
	}

	@Delete(':id')
	remove(@Param('id') id: string) {
		return this.userService.remove(+id)
	}
}
