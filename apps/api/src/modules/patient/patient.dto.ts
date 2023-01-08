import { ApiPropertyOptional, PartialType } from '@nestjs/swagger'
import { Type } from 'class-transformer'
import { IsDate, IsDefined, IsEnum, IsString, Validate } from 'class-validator'
import { EGender } from '../../../../../typeorm/base.entity'
import { IsPhone } from '../../common/class-validator.custom'

export class CreatePatientDto {
	@ApiPropertyOptional({ example: 'Phạm Hoàng Mai' })
	@IsDefined()
	fullName: string

	@ApiPropertyOptional({ example: '0986123456' })
	@Validate(IsPhone)
	phone: string

	@ApiPropertyOptional({ example: EGender.Female })
	@IsEnum(EGender)
	gender: EGender

	@ApiPropertyOptional({ example: 'Thành phố Hà Nội -- Quận Long Biên -- Phường Thạch Bàn -- số 8 - tòa nhà Đảo Cầu Vồng' })
	@IsString()
	address: string

	@ApiPropertyOptional({ example: '1998-11-28T00:00:00.000Z' })
	@Type(() => Date)
	@IsDate()
	birthday: Date
}

export class UpdatePatientDto extends PartialType(CreatePatientDto) { }
