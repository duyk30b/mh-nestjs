import { Module } from '@nestjs/common'
import { EmployeeService } from './employee.service'
import { EmployeeController } from './employee.controller'
import { TypeOrmModule } from '@nestjs/typeorm'
import EmployeeEntity from '../../typeorm/entities/employee.entity'

@Module({
	imports: [TypeOrmModule.forFeature([EmployeeEntity])],
	controllers: [EmployeeController],
	providers: [EmployeeService],
})
export class EmployeeModule { }
