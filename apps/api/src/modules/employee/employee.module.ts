import { Module } from '@nestjs/common'
import { TypeOrmModule } from '@nestjs/typeorm'
import ClinicEntity from '../../../../../typeorm/entities/clinic.entity'
import EmployeeEntity from '../../../../../typeorm/entities/employee.entity'
import { EmployeeController } from './employee.controller'
import { EmployeeService } from './employee.service'

@Module({
	imports: [TypeOrmModule.forFeature([EmployeeEntity])],
	controllers: [EmployeeController],
	providers: [EmployeeService],
})
export class EmployeeModule { }
