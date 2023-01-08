import { Body, Controller, Delete, Get, Param, Patch, Post, Req, SerializeOptions } from '@nestjs/common'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'
import { RequestToken } from '../../common/constants'
import { CreateAdmissionDto, UpdateAdmissionDto } from './admission.dto'
import { AdmissionService } from './admission.service'

@ApiTags('Admission')
@SerializeOptions({ excludeExtraneousValues: true, exposeUnsetFields: false })
@ApiBearerAuth('access-token')
@Controller('admission')
export class AdmissionController {
	constructor(private readonly admissionService: AdmissionService) { }

	@Get()
	findAll() {
		return this.admissionService.findAll()
	}

	@Get(':id')
	findOne(@Param('id') id: string) {
		return this.admissionService.findOne(+id)
	}

	@Post()
	create(@Body() createAdmissionDto: CreateAdmissionDto, @Req() request: RequestToken) {
		const clinicId = request.tokenPayload.cid
		return this.admissionService.create(clinicId, createAdmissionDto)
	}

	@Patch(':id')
	update(@Param('id') id: string, @Body() updateAdmissionDto: UpdateAdmissionDto) {
		return this.admissionService.update(+id, updateAdmissionDto)
	}

	@Delete(':id')
	remove(@Param('id') id: string) {
		return this.admissionService.remove(+id)
	}
}
