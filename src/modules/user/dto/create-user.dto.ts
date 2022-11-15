import { ApiProperty } from '@nestjs/swagger'

export class CreateUserDto {
	@ApiProperty({ default: 'example1' })
	username: string

	@ApiProperty({ default: 'example1@gmail.com' })
	email: string

	@ApiProperty({ default: '0986123456' })
	phone: string

	@ApiProperty({ default: 'abc123!@#' })
	password: string
}
