import { ApiProperty, ApiPropertyOptional, PartialType } from '@nestjs/swagger'
import { Expose, Type } from 'class-transformer'
import { IsDate, IsEnum, IsNumber, IsString, ValidateNested } from 'class-validator'
import { EGender } from '../../../../../typeorm/base.entity'
import PatientEntity from '../../../../../typeorm/entities/patient.entity'

class PatientDto {
	@ApiPropertyOptional({ name: 'patient_id', example: '' })
	@Expose({ name: 'patient_id' })
	@Type(() => Number)
	@IsNumber()
	patientId: number

	@ApiPropertyOptional({ name: 'full_name', example: 'Nguyễn Thị Ánh' })
	@Expose({ name: 'full_name' })
	@IsString()
	fullName: string

	@ApiPropertyOptional({ example: '0987445223' })
	@Expose()
	@IsString()
	phone: string

	@ApiPropertyOptional({ example: '1927-04-28T00:00:00.000Z' })
	@Expose()
	@Type(() => Date)
	@IsDate()
	birthday: Date

	@ApiPropertyOptional({ enum: EGender, example: EGender.Female })
	@Expose()
	@IsEnum(EGender)
	gender: EGender

	@ApiPropertyOptional({ example: 'Tỉnh Hà Tĩnh -- Huyện Đức Thọ -- Xã Lâm Trung Thủy -- Thôn Phan Thắng' })
	@Expose()
	@IsString()
	address: string
}

export class CreateAdmissionDto {
	@ApiProperty({ type: PatientDto })
	@Expose()
	@ValidateNested({ each: true })
	@Type(() => PatientDto)
	patient: PatientEntity

	@ApiPropertyOptional({ example: 'Sốt cao ngày thứ 3' })
	@Expose()
	@IsString()
	reason: string
}

export class UpdateAdmissionDto extends PartialType(CreateAdmissionDto) { }
