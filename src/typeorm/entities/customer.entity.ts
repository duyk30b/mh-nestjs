import { Column, Entity } from 'typeorm'
import { BaseEntities } from '../common/base.entities'

@Entity('customer')
export default class CustomerEntity extends BaseEntities {
	@Column({ name: 'organize_id' })
	organizeId: number

	@Column({ name: 'customer_name' })
	public customerName: string

	@Column()
	public phone: string

	@Column()
	public address: string
}
