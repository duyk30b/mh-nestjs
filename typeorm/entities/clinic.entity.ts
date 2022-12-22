import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('clinic')
export default class ClinicEntity extends BaseEntity {
	@Index('clinic_phone')
	@Column({ unique: true, length: 10, nullable: false })
	phone: string

	@Column({ unique: true, nullable: false })
	email: string

	@Column({ type: 'tinyint', default: 1 })
	level: number

	@Column({ nullable: true })
	name: string

	@Column({ nullable: true })
	address: string
}
