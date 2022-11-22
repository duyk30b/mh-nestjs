import { Body, Controller, Delete, Get, Param, Patch, Post, Req } from '@nestjs/common'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'
import { RequestToken } from '../../common/constants'
import { UserRoles } from '../../guards/user-roles.guard'
import { CreateEmployeeDto } from './dto/create-employee.dto'
import { UpdateEmployeeDto } from './dto/update-employee.dto'
import { EmployeeService } from './employee.service'

@ApiTags('Employee')
@ApiBearerAuth('access-token')
@Controller('employee')
export class EmployeeController {
	constructor(private readonly employeeService: EmployeeService) { }

	@Post()
	@UserRoles('Owner', 'Admin')
	async create(@Body() createEmployeeDto: CreateEmployeeDto, @Req() request: RequestToken) {
		createEmployeeDto.clinicId = request.tokenPayload.cid
		return this.employeeService.create(createEmployeeDto)
	}

	@Get()
	findAll() {
		return this.employeeService.findAll()
	}

	@Get(':id')
	findOne(@Param('id') id: string) {
		return this.employeeService.findOne(+id)
	}

	@Patch(':id')
	update(@Param('id') id: string, @Body() updateEmployeeDto: UpdateEmployeeDto) {
		return this.employeeService.update(+id, updateEmployeeDto)
	}

	@Delete(':id')
	remove(@Param('id') id: string) {
		return this.employeeService.remove(+id)
	}
}
