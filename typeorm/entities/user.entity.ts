import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

export enum EUserRole {
	Owner = 'Owner',
	Admin = 'Admin',
	User = 'User',
}

export type TUserRole = keyof typeof EUserRole

@Entity('user')
@Index(['clinicId', 'email'])
@Index(['clinicId', 'username'])
export default class UserEntity extends BaseEntity {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ unique: true, nullable: true })
	email: string

	@Column({ unique: true, nullable: true })
	phone: string

	@Column()
	username: string

	@Column()
	password: string

	@Column({ nullable: true })
	address: string

	@Column({ type: 'enum', enum: EUserRole, default: EUserRole.User })
	role: EUserRole
}
