import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../common/base.entity'

@Entity('customer')
@Index(['clinicId', 'name'])
export default class CustomerEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'name' })
	public name: string

	@Column()
	public phone: string

	@Column()
	public address: string
}
