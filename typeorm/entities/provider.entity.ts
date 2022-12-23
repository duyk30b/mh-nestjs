import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('provider')
@Index(['clinicId', 'id'], { unique: true })
export default class ProviderEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'provider_name' })
	public providerName: string

	@Column()
	public phone: string

	@Column()
	public address: string
}
