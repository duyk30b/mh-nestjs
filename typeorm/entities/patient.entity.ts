import { Exclude } from 'class-transformer'
import { Column, Entity, Index } from 'typeorm'
import { BaseEntity, EGender } from '../base.entity'

@Entity('patient')
@Index(['clinicId', 'fullName'])
@Index(['clinicId', 'phone'])
export default class PatientEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	@Exclude()
	clinicId: number

	@Column({ name: 'full_name' })
	fullName: string

	@Column({ length: 10, nullable: true })
	phone: string

	@Column({ type: 'date', nullable: true })
	birthday: Date

	@Column({ type: 'enum', enum: EGender, nullable: true })
	gender: EGender

	@Column({ nullable: true })
	address: string

	@Column({ name: 'health_history', type: 'text', nullable: true })
	healthHistory: string // Tiền sử bệnh
}
