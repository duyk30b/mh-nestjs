import { Module } from '@nestjs/common'
import { TypeOrmModule } from '@nestjs/typeorm'
import MedicineEntity from '../../../../../typeorm/entities/medicine.entity'
import { MedicineController } from './medicine.controller'
import { MedicineService } from './medicine.service'

@Module({
	imports: [TypeOrmModule.forFeature([MedicineEntity])],
	controllers: [MedicineController],
	providers: [MedicineService],
})
export class MedicineModule { }
