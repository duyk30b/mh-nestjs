import { Body, Controller, Delete, Get, Param, Patch, Post, Req } from '@nestjs/common'
import { UseInterceptors } from '@nestjs/common/decorators'
import { ClassSerializerInterceptor } from '@nestjs/common/serializer'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'
import { RequestToken } from '../../common/constants'
import { CreateEmployeeDto, UpdateEmployeeDto } from './employee.dto'
import { EmployeeService } from './employee.service'

@ApiTags('Employee')
@ApiBearerAuth('access-token')
@UseInterceptors(ClassSerializerInterceptor)
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
	findOne(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.employeeService.findOne(clinicId, +id)
	}

	@Patch('update/:id')
	async update(@Param('id') id: string, @Req() request: RequestToken, @Body() updateEmployeeDto: UpdateEmployeeDto) {
		const clinicId = request.tokenPayload.cid
		await this.employeeService.update(clinicId, +id, updateEmployeeDto)
		return { message: 'success' }
	}

	@Delete('remove/:id')
	async remove(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		await this.employeeService.remove(clinicId, +id)
		return { message: 'success' }
	}

	@Patch('restore/:id')
	async restore(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		await this.employeeService.restore(clinicId, +id)
		return { message: 'success' }
	}
}
