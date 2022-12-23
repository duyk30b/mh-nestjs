import { Entity, Column, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('medicine')
@Index(['clinicId', 'id'], { unique: true })
export default class MedicineEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'brand_name', nullable: true })
	brandName: string                              // tên biệt dược

	@Column({ name: 'chemical_name', nullable: true })
	chemicalName: string                           // tên gốc

	@Column({ name: 'calculation_unit', nullable: true })
	calculationUnit: string                        // đơn vị tính: lọ, ống, vỉ

	@Column({ name: 'image', nullable: true })
	image: string
}
