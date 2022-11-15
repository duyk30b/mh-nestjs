import { ApiProperty } from '@nestjs/swagger'

export class CreateProviderDto {
	@ApiProperty({ default: 'Ngô Nhật Dương' })
	providerName: string

	@ApiProperty({ default: '0986123456' })
	phone: string

	@ApiProperty({ default: 'Thạch Bàn - Long Biên - Hà Nội' })
	address: string
}
