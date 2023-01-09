import { Exclude, Expose } from 'class-transformer'
import { CreateDateColumn, DeleteDateColumn, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm'

export enum EGender {
	Male = 'Male',
	Female = 'Female',
}

export type TGender = keyof typeof EGender

export class BaseEntity {
	@PrimaryGeneratedColumn({ name: 'id' })
	@Expose()
	id: number

	@CreateDateColumn({ name: 'created_at' })
	@Expose({ name: 'created_at' })
	createdAt: Date

	@UpdateDateColumn({ name: 'updated_at' })
	updatedAt: Date

	@DeleteDateColumn({ name: 'deleted_at' })
	@Exclude()
	deletedAt: Date
}
