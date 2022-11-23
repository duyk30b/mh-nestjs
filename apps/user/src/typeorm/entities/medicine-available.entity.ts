import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../common/base.entity'

@Entity('medicine_available')
@Index(['clinicId', 'medicineId'])
export default class MedicineAvailableEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'medicine_id' })
	medicineId: number

	@Column({ default: 0 })
	quantity: number

	@Column({ name: 'expiry_date' })
	expiryDate: Date

	@Column({ name: 'cost_price' })
	costPrice: number

	@Column({ name: 'retail_price' })
	retailPrice: number

	@Column({ name: 'wholesale_price' })
	wholesalePrice: number
}
