import {
	PrimaryGeneratedColumn, Column,
	CreateDateColumn, UpdateDateColumn, DeleteDateColumn, VersionColumn,
} from 'typeorm'

export class BaseEntities {
	@PrimaryGeneratedColumn({ name: 'id' })
	id: number

	@Column({ name: 'created_by', default: 1 })
	createdBy: number

	@Column({ name: 'updated_by', default: 1 })
	updatedBy: number

	@CreateDateColumn({ name: 'created_at' })
	createdAt: Date

	@UpdateDateColumn({ name: 'updated_at' })
	updatedAt: Date

	@DeleteDateColumn({ name: 'deleted_at' })
	deletedAt: Date

	@VersionColumn()
	version: number
}
