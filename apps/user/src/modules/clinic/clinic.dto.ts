import { PartialType } from '@nestjs/swagger'
import { IsEmail, Length } from 'class-validator'

export class CreateClinicDto {
	@IsEmail()
	email: string

	@Length(10, 10)
	phone: string

	@Length(6)
	password: string
}

export class UpdateClinicDto extends PartialType(CreateClinicDto) { }
