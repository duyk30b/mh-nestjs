import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../common/base.entity'

@Entity('medicine_receipt_note')
@Index(['clinicId', 'medicineId'])
@Index(['clinicId', 'employeeId'])
export default class MedicineReceiptNoteEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'provider_id' })
	providerId: number

	@Column({ name: 'employee_id' })
	employeeId: number
}
