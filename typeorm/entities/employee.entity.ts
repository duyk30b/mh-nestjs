import { Column, Entity, Index } from 'typeorm'
import { BaseEntity } from '../base.entity'

export enum EEmployeeRole {
	Owner = 'Owner',
	Admin = 'Admin',
	User = 'User',
}

export type TEmployeeRole = keyof typeof EEmployeeRole

@Entity('employee')
@Index(['cPhone', 'username'])
export default class UserEntity extends BaseEntity {
	@Column({ name: 'c_phone', length: 10 })
	cPhone: string

	@Column({ length: 10, nullable: true })
	phone: string

	@Column()
	username: string

	@Column()
	password: string

	@Column({ type: 'enum', enum: EEmployeeRole, default: EEmployeeRole.User })
	role: EEmployeeRole
}
