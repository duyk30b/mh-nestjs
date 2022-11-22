import { ApiProperty } from '@nestjs/swagger'

export class CreateEmployeeDto {
	@ApiProperty({ example: 'employee1' })
	username: string

	@ApiProperty({ example: 'Abc@123456' })
	password: string

	clinicId: number
}
