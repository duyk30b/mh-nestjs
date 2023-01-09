import { Body, Controller, Delete, Get, Param, Patch, Post, SerializeOptions } from '@nestjs/common'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'
import { CidRequest } from '../../decorators/request.decorator'
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
	async create(@Body() createAdmissionDto: CreateAdmissionDto, @CidRequest() cid: number) {
		return await this.admissionService.create(cid, createAdmissionDto)
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
