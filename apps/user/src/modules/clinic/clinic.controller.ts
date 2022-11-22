import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common'
import { ClinicService } from './clinic.service'
import { CreateClinicDto, UpdateClinicDto } from './clinic.dto'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'

@ApiTags('Clinic')
@ApiBearerAuth('access-token')
@Controller('clinic')
export class ClinicController {
	constructor(private readonly clinicService: ClinicService) { }

	@Post()
	create(@Body() createClinicDto: CreateClinicDto) {
		return ''
	}

	@Get()
	findAll() {
		return this.clinicService.findAll()
	}

	@Get(':id')
	findOne(@Param('id') id: string) {
		return this.clinicService.findOne(+id)
	}

	@Delete(':id')
	remove(@Param('id') id: string) {
		return this.clinicService.remove(+id)
	}
}
