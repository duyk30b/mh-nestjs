import { Entity, Column } from 'typeorm'
import { BaseEntity } from '../common/base.entity'

@Entity('medicine')
export default class MedicineEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ name: 'brand_name', nullable: true })
	public brandName: string                              // tên biệt dược

	@Column({ name: 'chemical_name', nullable: true })
	public chemicalName: string                           // tên gốc

	@Column({ name: 'calculation_unit', nullable: true })
	public calculationUnit: string                        // đơn vị tính: lọ, ống, vỉ
}
