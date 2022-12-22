import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('medicine_delivery_note')
@Index(['cPhone', 'userId'])
@Index(['cPhone', 'customerId'])
export default class MedicineDeliveryNoteEntity extends BaseEntity {
	@Column({ name: 'c_phone', length: 10 })
	cPhone: string

	@Column({ name: 'customer_id' })
	customerId: number

	@Column({ name: 'user_id' })
	userId: number
}
