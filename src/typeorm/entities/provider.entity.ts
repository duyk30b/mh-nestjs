import { Column, Entity } from 'typeorm'
import { BaseEntities } from '../common/base.entities'

@Entity('provider')
export default class ProviderEntity extends BaseEntities {
	@Column({ name: 'organize_id' })
	organizeId: number

	@Column({ name: 'provider_name' })
	public providerName: string

	@Column()
	public phone: string

	@Column()
	public address: string
}
