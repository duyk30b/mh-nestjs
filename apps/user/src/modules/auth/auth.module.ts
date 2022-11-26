import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { TypeOrmModule } from '@nestjs/typeorm'
import ClinicEntity from '../../../../../typeorm/entities/clinic.entity'
import EmployeeEntity from '../../../../../typeorm/entities/employee.entity'
import { JwtConfig } from '../../enviroments'
import { AuthController } from './auth.controller'
import { AuthService } from './auth.service'
import { JwtExtendService } from './jwt-extend.service'

@Module({
	imports: [
		TypeOrmModule.forFeature([ClinicEntity, EmployeeEntity]),
		ConfigModule.forFeature(JwtConfig),
		JwtModule,
	],
	controllers: [AuthController],
	providers: [AuthService, JwtExtendService],
	exports: [JwtExtendService],
})
export class AuthModule { }
