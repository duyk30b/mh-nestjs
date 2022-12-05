import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { TypeOrmModule } from '@nestjs/typeorm'
import ClinicEntity from '../../../../../typeorm/entities/clinic.entity'
import UserEntity from '../../../../../typeorm/entities/user.entity'
import { JwtConfig } from '../../enviroments'
import { AuthController } from './auth.controller'
import { AuthService } from './auth.service'
import { JwtExtendService } from './jwt-extend.service'

@Module({
	imports: [
		TypeOrmModule.forFeature([ClinicEntity, UserEntity]),
		ConfigModule.forFeature(JwtConfig),
		JwtModule,
	],
	controllers: [AuthController],
	providers: [AuthService, JwtExtendService],
	exports: [JwtExtendService],
})
export class AuthModule { }
