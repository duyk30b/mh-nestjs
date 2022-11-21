import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { TypeOrmModule } from '@nestjs/typeorm'
import { JwtConfig } from '../../enviroments'
import ClinicEntity from '../../typeorm/entities/clinic.entity'
import EmployeeEntity from '../../typeorm/entities/employee.entity'
import { AuthController } from './auth.controller'
import { AuthService } from './auth.service'

@Module({
	imports: [
		TypeOrmModule.forFeature([ClinicEntity, EmployeeEntity]),
		ConfigModule.forRoot({ load: [JwtConfig] }),
		JwtModule,
	],
	controllers: [AuthController],
	providers: [AuthService],
})
export class AuthModule { }
