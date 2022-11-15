import { Column, Entity, Unique } from 'typeorm'
import { BaseEntities } from '../common/base.entities'

@Entity('user')
export default class UserEntity extends BaseEntities {
	@Column({ name: 'organize_id', default: 1 })
	organizeId: number

	@Column()
	@Unique(['username'])
	public username: string

	@Column()
	@Unique(['email'])
	public email: string

	@Column()
	@Unique(['phone'])
	public phone: string

	@Column()
	public password: string

	@Column({ default: 'HN' })
	public adress: string
}
