import { ApiProperty } from '@nestjs/swagger'
import { Expose } from 'class-transformer'
import { IsNotEmpty, MinLength, Validate } from 'class-validator'
import { IsGmail, IsPhone } from '../../common/class-validator.custom'

export class RegisterDto {
	@ApiProperty({ example: 'example-2@gmail.com' })
	@Expose()
	@IsNotEmpty()
	@Validate(IsGmail)
	email: string

	@ApiProperty({ example: '0376899866' })
	@Expose()
	@IsNotEmpty()
	@Validate(IsPhone)
	phone: string

	@ApiProperty({ example: 'admin' })
	@Expose()
	@IsNotEmpty()
	username: string

	@ApiProperty({ example: 'Abc@123456' })
	@Expose()
	@IsNotEmpty()
	@MinLength(6)
	password: string
}

export class LoginDto {
	@ApiProperty({ name: 'c_phone', example: '0986021190' })
	@Expose({ name: 'c_phone' })
	@IsNotEmpty()
	@Validate(IsPhone)
	cPhone: string

	@ApiProperty({ example: 'admin' })
	@Expose()
	@IsNotEmpty()
	username: string

	@ApiProperty({ example: 'Abc@123456' })
	@Expose()
	@IsNotEmpty()
	@MinLength(6)
	password: string
}

export class RefreshTokenDto {
	@ApiProperty({ name: 'refresh_token' })
	@Expose({ name: 'refresh_token' })
	@IsNotEmpty()
	refreshToken: string
}

export class TokensResponse {
	@Expose({ name: 'access_token' })
	accessToken: string

	@Expose({ name: 'refresh_token' })
	refreshToken: string

	constructor(partial: Partial<TokensResponse>) {
		Object.assign(this, partial)
	}
}
