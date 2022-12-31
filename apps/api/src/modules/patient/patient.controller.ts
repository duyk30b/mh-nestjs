import { Body, ClassSerializerInterceptor, Controller, Delete, Get, Param, Patch, Post, Query, Req, UseInterceptors } from '@nestjs/common'
import { ApiBearerAuth, ApiParam, ApiQuery, ApiTags } from '@nestjs/swagger'
import { RequestToken } from '../../common/constants'
import { CreatePatientDto, UpdatePatientDto } from './patient.dto'
import { PatientService } from './patient.service'

@ApiTags('Patient')
@ApiBearerAuth('access-token')
@UseInterceptors(ClassSerializerInterceptor)
@Controller('patient')
export class PatientController {
	constructor(private readonly patientService: PatientService) { }

	@Get()
	findAll(@Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.patientService.findAll(clinicId)
	}

	@Get('search')
	@ApiQuery({ name: 'searchText', example: '0986123456' })
	search(@Query('searchText') searchText: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		if (/^\d+$/.test(searchText)) {
			return this.patientService.findByPhone(clinicId, searchText)
		}
		return this.patientService.findByFullName(clinicId, searchText)
	}

	@Post()
	create(@Body() createPatientDto: CreatePatientDto, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.patientService.create(clinicId, createPatientDto)
	}

	@Get(':id')
	@ApiParam({ name: 'id', example: 1 })
	findOne(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.patientService.findOne(clinicId, +id)
	}

	@Patch('update/:id')
	@ApiParam({ name: 'id', example: 1 })
	async update(@Param('id') id: string, @Body() updatePatientDto: UpdatePatientDto, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		await this.patientService.update(clinicId, +id, updatePatientDto)
		return { message: 'success' }
	}

	@Delete('remove/:id')
	@ApiParam({ name: 'id', example: 1 })
	async remove(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		await this.patientService.remove(clinicId, +id)
		return { message: 'success' }
	}

	@Patch('restore/:id')
	@ApiParam({ name: 'id', example: 1 })
	async restore(@Param('id') id: string, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		await this.patientService.restore(clinicId, +id)
		return { message: 'success' }
	}
}
