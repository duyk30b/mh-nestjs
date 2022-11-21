import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { TypeOrmModule } from '@nestjs/typeorm'
import { JwtConfig } from '../../enviroments'
import UserEntity from '../../typeorm/entities/employee.entity'
import { UserController } from './user.controller'
import { UserService } from './user.service'

@Module({
	imports: [
		TypeOrmModule.forFeature([UserEntity]),
		ConfigModule.forRoot({ load: [JwtConfig] }),
	],
	controllers: [UserController],
	providers: [UserService],
	exports: [UserService],
})
export class UserModule { }
