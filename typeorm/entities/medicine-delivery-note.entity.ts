import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('medicine_delivery_note')
@Index(['clinicId', 'employeeId'])
@Index(['clinicId', 'customerId'])
export default class MedicineDeliveryNoteEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'customer_id' })
	customerId: number

	@Column({ name: 'employee_id' })
	employeeId: number
}
