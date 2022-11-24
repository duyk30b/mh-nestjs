import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('medicine_receipt_note')
@Index(['clinicId', 'employeeId'])
@Index(['clinicId', 'providerId'])
export default class MedicineReceiptNoteEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'provider_id' })
	providerId: number

	@Column({ name: 'employee_id' })
	employeeId: number

	@Column({ name: 'buyer_pays_ship' })
	buyerPaysShip: number

	@Column({ name: 'seller_pays_ship' })
	sellerPaysShip: number

	@Column()
	discount: number                                   // tiền giảm giá

	@Column()
	debt: number                                       // tiền nợ

	@Column({ name: 'total_money' })
	totalMoney: number                                 // tổng tiền = tiền sản phẩm + buyerPaysShip - tiền giảm giá
}
