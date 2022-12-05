import { ApiProperty, PartialType } from '@nestjs/swagger'
import { MinLength, Validate } from 'class-validator'
import { IsGmail, IsPhone } from '../../common/class-validator.custom'

export class RegisterDto {
	@ApiProperty({ example: 'example@gmail.com' })
	@Validate(IsGmail)
	email: string

	@ApiProperty({ example: '0987123456' })
	@Validate(IsPhone)
	phone: string

	@ApiProperty({ example: 'Abc@123456' })
	@MinLength(6)
	password: string
}

export class LoginDto {
	@ApiProperty({ example: 'example@gmail.com' })
	@Validate(IsGmail)
	email?: string

	@ApiProperty({ example: 'Admin' })
	username?: string

	@ApiProperty({ example: 1 })
	clinicId?: number

	@ApiProperty({ example: 'Abc@123456' })
	@MinLength(6)
	password: string
}
