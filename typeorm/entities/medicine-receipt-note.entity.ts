import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('medicine_receipt_note')
@Index(['cPhone', 'userId'])
@Index(['cPhone', 'providerId'])
export default class MedicineReceiptNoteEntity extends BaseEntity {
	@Column({ name: 'c_phone', length: 10 })
	cPhone: string

	@Column({ name: 'provider_id' })
	providerId: number

	@Column({ name: 'user_id' })
	userId: number

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
