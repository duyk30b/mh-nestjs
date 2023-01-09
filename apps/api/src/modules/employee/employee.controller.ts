import { Body, Controller, Delete, Get, Param, Patch, Post, Req } from '@nestjs/common'
import { ApiBearerAuth, ApiParam, ApiTags } from '@nestjs/swagger'
import { ERole } from '../../../../../typeorm/entities/employee.entity'
import { RequestToken } from '../../common/constants'
import { Roles } from '../../guards/roles.guard'
import { CreateEmployeeDto, UpdateEmployeeDto } from './employee.dto'
import { EmployeeService } from './employee.service'

@ApiTags('Employee')
@ApiBearerAuth('access-token')
@Roles(ERole.Admin, ERole.Owner)
@Controller('employee')
export class EmployeeController {
	constructor(private readonly employeeService: EmployeeService) { }

	@Get()
	findAll(@Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.employeeService.findAll(clinicId)
	}

	@Post()
	create(@Body() createEmployeeDto: CreateEmployeeDto, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.employeeService.create(clinicId, createEmployeeDto)
	}

	@Get(':id')
	@ApiParam({ name: 'id', example: 1 })
	findOne(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.employeeService.findOne(clinicId, +id)
	}

	@Patch('update/:id')
	@ApiParam({ name: 'id', example: 1 })
	async update(@Param('id') id: string, @Req() request: RequestToken, @Body() updateEmployeeDto: UpdateEmployeeDto) {
		const clinicId = request.tokenPayload.cid
		await this.employeeService.update(clinicId, +id, updateEmployeeDto)
		return { message: 'success' }
	}

	@Delete('remove/:id')
	@ApiParam({ name: 'id', example: 1 })
	async remove(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		await this.employeeService.remove(clinicId, +id)
		return { message: 'success' }
	}

	@Patch('restore/:id')
	@ApiParam({ name: 'id', example: 1 })
	async restore(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		await this.employeeService.restore(clinicId, +id)
		return { message: 'success' }
	}
}
