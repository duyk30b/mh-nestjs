import { Column, Entity, Index } from 'typeorm'
import { EUserRole } from '../../common/constants'
import { BaseEntity } from '../common/base.entity'

@Entity('employee')
@Index(['clinicId', 'email'])
@Index(['clinicId', 'username'])
export default class EmployeeEntity extends BaseEntity {
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
