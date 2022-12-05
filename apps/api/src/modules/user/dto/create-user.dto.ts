import { ApiProperty } from '@nestjs/swagger'

export class CreateUserDto {
	@ApiProperty({ example: 'user_example_1' })
	username: string

	@ApiProperty({ example: 'Abc@123456' })
	password: string

	clinicId: number
}
