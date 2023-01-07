import { Exclude } from 'class-transformer'
import { Column, Entity } from 'typeorm'
import { BaseEntity } from '../base.entity'

@Entity('admission')
export default class AdmissionEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	@Exclude()
	clinicId: number

	@Column({ name: 'patient_id' })
	patientId: number

	@Column({ name: 'reason', nullable: true })
	reason: string // Lý do vào viện

	@Column({ name: 'medical_record', type: 'text' })
	medicalRecord: string // Tóm tăt bệnh án

	@Column({ nullable: true })
	diagnosis: string // Chẩn đoán

	@Column({ type: 'tinyint', unsigned: true, nullable: true })               // ----- tinyint_unsigned: 0 -> 256
	pulse: number

	@Column({ type: 'float', precision: 3, scale: 1, nullable: true })
	temperature: number

	@Column({ name: 'blood_pressure', length: 10, nullable: true })
	bloodPressure: string

	@Column({ name: 'respiratory_rate', type: 'tinyint', nullable: true })     // ----- tinyint: -128 -> 127
	respiratoryRate: number

	@Column({ type: 'tinyint', nullable: true })
	spO2: number

	@Column({ nullable: true })
	note: string // Ghi chú
}
