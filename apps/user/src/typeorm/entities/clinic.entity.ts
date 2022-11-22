import { Column, Entity } from 'typeorm'
import { BaseEntity } from '../common/base.entity'

@Entity('clinic')
export default class ClinicEntity extends BaseEntity {
	@Column({ type: 'tinyint', default: 1 })
	level: number

	@Column({ name: 'code', nullable: true })
	code: string

	@Column({ nullable: true })
	clinicName: string

	@Column({ nullable: true })
	address: string
}
