import { Column, Entity } from 'typeorm'
import { BaseEntities } from '../common/base.entities'

export enum UserRole {
	OWNER = 'OWNER',
	USER = 'USER',
}

@Entity('user')
export default class EmployeeEntity extends BaseEntities {
	@Column({ name: 'clinic_id' })
	clinicId: number

	@Column({ unique: true })
	email: string

	@Column({ unique: true })
	phone: string

	@Column()
	username: string

	@Column()
	password: string

	@Column({ nullable: true })
	address: string

	@Column({ type: 'enum', enum: UserRole, default: UserRole.USER })
	role: UserRole
}
