import { Column, Entity, Index, JoinColumn, ManyToOne } from 'typeorm'
import { BaseEntity } from '../base.entity'
import ClinicEntity from './clinic.entity'

export enum EEmployeeRole {
	Owner = 'Owner',
	Admin = 'Admin',
	User = 'User',
}

export type TEmployeeRole = keyof typeof EEmployeeRole

@Entity('employee')
@Index(['clinicId', 'username'], { unique: true })
export default class UserEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@ManyToOne(type => ClinicEntity)
	@JoinColumn({ name: 'clinic_id', referencedColumnName: 'id' })
	clinic: ClinicEntity

	@Column({ length: 10, nullable: true })
	phone: string

	@Column()
	username: string

	@Column()
	password: string

	@Column({ type: 'enum', enum: EEmployeeRole, default: EEmployeeRole.User })
	role: EEmployeeRole
}
