import { Column, Entity } from 'typeorm'
import { BaseEntity } from '../common/base.entity'

@Entity('provider')
export default class ProviderEntity extends BaseEntity {
	@Column({ name: 'organize_id' })
	organizeId: number

	@Column({ name: 'provider_name' })
	public providerName: string

	@Column()
	public phone: string

	@Column()
	public address: string
}
