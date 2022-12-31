import { Exclude, Expose } from 'class-transformer'
import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

export enum EGender {
	Male = 'Male',
	Female = 'Female',
}

@Entity('patient')
@Index(['clinicId', 'fullName'])
@Index(['clinicId', 'phone'])
export default class PatientEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'full_name' })
	fullName: string

	@Column({ length: 10, nullable: true })
	phone: string

	@Column({ nullable: true })
	birthday: Date

	@Column({ type: 'enum', enum: EGender, nullable: true })
	gender: EGender

	@Column({ nullable: true })
	address: string
}
