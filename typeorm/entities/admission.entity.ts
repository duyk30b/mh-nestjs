import { Exclude, Expose, Type } from 'class-transformer'
import { Column, Entity, JoinColumn, ManyToOne } from 'typeorm'
import { BaseEntity } from '../base.entity'
import PatientEntity from './patient.entity'

@Entity('admission')
export default class AdmissionEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	@Exclude()
	clinicId: number

	@Column({ name: 'patient_id' })
	@Expose({ name: 'patient_id' })
	patientId: number

	@ManyToOne(type => PatientEntity, { createForeignKeyConstraints: false })
	@JoinColumn({ name: 'patient_id', referencedColumnName: 'id' })
	@Type(() => PatientEntity)
	@Expose()
	patient: PatientEntity

	@Column({ name: 'reason', nullable: true })
	@Expose()
	reason: string // Lý do vào viện

	@Column({ name: 'medical_record', type: 'text', nullable: true })
	@Expose({ name: 'medical_record' })
	medicalRecord: string // Tóm tăt bệnh án

	@Column({ nullable: true })
	@Expose()
	diagnosis: string // Chẩn đoán

	@Column({ type: 'tinyint', unsigned: true, nullable: true })               // ----- tinyint_unsigned: 0 -> 256
	@Expose()
	pulse: number

	@Column({ type: 'float', precision: 3, scale: 1, nullable: true })
	@Expose()
	temperature: number

	@Column({ name: 'blood_pressure', length: 10, nullable: true })
	@Expose({ name: 'blood_pressure' })
	bloodPressure: string

	@Column({ name: 'respiratory_rate', type: 'tinyint', nullable: true })     // ----- tinyint: -128 -> 127
	@Expose({ name: 'respiratory_rate' })
	respiratoryRate: number

	@Column({ type: 'tinyint', nullable: true })
	@Expose()
	spO2: number

	@Column({ nullable: true })
	@Expose()
	note: string // Ghi chú
}
