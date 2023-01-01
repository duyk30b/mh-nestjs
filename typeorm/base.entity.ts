import { Exclude } from 'class-transformer'
import { CreateDateColumn, DeleteDateColumn, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm'

export enum EGender {
	Male = 'Male',
	Female = 'Female',
}

export class BaseEntity {
	@PrimaryGeneratedColumn({ name: 'id' })
	id: number

	@CreateDateColumn({ name: 'created_at' })
	createdAt: Date

	@UpdateDateColumn({ name: 'updated_at' })
	updatedAt: Date

	@DeleteDateColumn({ name: 'deleted_at' })
	@Exclude()
	deletedAt: Date
}
