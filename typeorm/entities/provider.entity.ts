import { Column, Entity } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('provider')
export default class ProviderEntity extends BaseEntity {
	@Column({ name: 'c_phone', length: 10 })
	cPhone: string

	@Column({ name: 'provider_name' })
	public providerName: string

	@Column()
	public phone: string

	@Column()
	public address: string
}
