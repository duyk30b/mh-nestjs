import { Column, Entity } from 'typeorm'
import { BaseEntities } from '../common/base.entities'

@Entity('clinic')
export default class ClinicEntity extends BaseEntities {
	@Column({ type: 'tinyint', default: 1 })
	level: number

	@Column({ name: 'code', nullable: true })
	code: string

	@Column({ nullable: true })
	clinicName: string

	@Column({ nullable: true })
	address: string
}
