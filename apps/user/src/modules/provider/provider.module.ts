import { Module } from '@nestjs/common'
import { TypeOrmModule } from '@nestjs/typeorm'
import ProviderEntity from '../../typeorm/entities/provider.entity'
import { ProviderController } from './provider.controller'
import { ProviderService } from './provider.service'

@Module({
	imports: [TypeOrmModule.forFeature([ProviderEntity])],
	controllers: [ProviderController],
	providers: [ProviderService],
})
export class ProviderModule { }
