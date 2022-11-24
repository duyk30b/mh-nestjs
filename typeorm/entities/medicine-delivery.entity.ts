import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('medicine_delivery')
@Index(['clinicId', 'medicineId'])
@Index(['clinicId', 'deliveryNoteId'])
export default class MedicineDeliveryEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'medicine_id' })
	medicineId: number

	@Column({ name: 'delivery_note_id' })
	deliveryNoteId: number

	@Column({ default: 0 })
	quantity: number

	@Column({ name: 'expiry_date' })
	expiryDate: Date

    @Column({ name: 'cost_price' })
    public costPrice: number

    @Column({ name: 'expected_price' })
    public expectedPrice: number

    @Column({ name: 'actual_price' })
    public actualPrice: number

    @Column()
    public discount: number
}
