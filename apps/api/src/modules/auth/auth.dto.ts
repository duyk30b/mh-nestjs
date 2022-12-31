import { ApiProperty } from '@nestjs/swagger'
import { IsDefined, Length, MinLength, Validate } from 'class-validator'
import { IsGmail, IsPhone } from '../../common/class-validator.custom'

export class RegisterDto {
	@ApiProperty({ example: 'example-2@gmail.com' })
	@IsDefined()
	@Validate(IsGmail)
	email: string

	@ApiProperty({ example: '0376899866' })
	@IsDefined()
	@Validate(IsPhone)
	phone: string

	@ApiProperty({ example: 'admin' })
	@IsDefined()
	username: string

	@ApiProperty({ example: 'Abc@123456' })
	@IsDefined()
	@MinLength(6)
	password: string
}

export class LoginDto {
	@ApiProperty({ example: '0986021190' })
	@IsDefined()
	@Length(10, 10)
	cPhone: string

	@ApiProperty({ example: 'admin' })
	@IsDefined()
	username: string

	@ApiProperty({ example: 'Abc@123456' })
	@IsDefined()
	@MinLength(6)
	password: string
}

export class RefreshTokenDto {
	@ApiProperty()
	@IsDefined()
	refreshToken: string
}
