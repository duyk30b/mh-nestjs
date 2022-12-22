import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('medicine_receipt')
@Index(['cPhone', 'medicineId'])
@Index(['cPhone', 'receiptNoteId'])
export default class MedicineReceiptEntity extends BaseEntity {
	@Column({ name: 'c_phone', length: 10 })
	cPhone: string

	@Column({ name: 'medicine_id' })
	medicineId: number

	@Column({ name: 'receipt_note_id' })
	receiptNoteId: number

	@Column({ default: 0 })
	quantity: number

	@Column({ name: 'expiry_date' })
	expiryDate: Date

	@Column({ name: 'cost_price' })
	costPrice: number
}
