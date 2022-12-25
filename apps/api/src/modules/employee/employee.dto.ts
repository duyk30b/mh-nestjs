import { ApiProperty, PartialType } from '@nestjs/swagger'
import { IsDefined, MinLength } from 'class-validator'

export class CreateEmployeeDto {
	@ApiProperty({ example: 'nhatduong2019' })
	@IsDefined()
	username: string

	@ApiProperty({ example: 'Abc@123456' })
	@IsDefined()
	@MinLength(6)
	password: string

	@ApiProperty({ example: 'Ngô Nhật Dương' })
	fullName: string
}

export class UpdateEmployeeDto extends PartialType(CreateEmployeeDto) { }
