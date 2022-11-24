import { Module } from '@nestjs/common'
import { TypeOrmModule } from '@nestjs/typeorm'
import ClinicEntity from '../../../../../typeorm/entities/clinic.entity'
import { ClinicController } from './clinic.controller'
import { ClinicService } from './clinic.service'

@Module({
	imports: [TypeOrmModule.forFeature([ClinicEntity])],
	controllers: [ClinicController],
	providers: [ClinicService],
	exports: [ClinicService],
})
export class ClinicModule { }
