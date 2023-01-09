import { Exclude } from 'class-transformer'
import { Column, Entity, Index, JoinColumn, ManyToOne } from 'typeorm'
import { BaseEntity, EGender } from '../base.entity'
import ClinicEntity from './clinic.entity'

export enum ERole {
	Owner = 'Owner',
	Admin = 'Admin',
	User = 'User',
}

export type TRole = keyof typeof ERole

@Entity('employee')
@Index(['clinicId', 'username'], { unique: true })
export default class EmployeeEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	@Exclude()
	clinicId: number

	@ManyToOne(type => ClinicEntity)
	@JoinColumn({ name: 'clinic_id', referencedColumnName: 'id' })
	clinic: ClinicEntity

	@Column({ length: 10, nullable: true })
	phone: string

	@Column()
	username: string

	@Column()
	@Exclude()
	password: string

	@Column({ type: 'enum', enum: ERole, default: ERole.User })
	role: ERole

	@Column({ name: 'full_name', nullable: true })
	fullName: string

	@Column({ type: 'date', nullable: true })
	birthday: Date

	@Column({ type: 'enum', enum: EGender, nullable: true })
	gender: EGender
}
