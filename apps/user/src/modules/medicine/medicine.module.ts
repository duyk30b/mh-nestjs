import { Module } from '@nestjs/common'
import { MedicineService } from './medicine.service'
import { MedicineController } from './medicine.controller'
import { TypeOrmModule } from '@nestjs/typeorm'
import MedicineEntity from '../../typeorm/entities/medicine.entity'

@Module({
	imports: [TypeOrmModule.forFeature([MedicineEntity])],
	controllers: [MedicineController],
	providers: [MedicineService],
})
export class MedicineModule { }
