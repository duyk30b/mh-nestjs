import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('customer')
@Index(['cPhone', 'name'])
export default class CustomerEntity extends BaseEntity {
	@Column({ name: 'c_phone', length: 10 })
	cPhone: string

	@Column({ name: 'name' })
	public name: string

	@Column()
	public phone: string

	@Column()
	public address: string
}
