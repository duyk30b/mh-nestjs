import {
	PrimaryGeneratedColumn, Column,
	CreateDateColumn, UpdateDateColumn, DeleteDateColumn, VersionColumn,
} from 'typeorm'

export class BaseEntities {
	@PrimaryGeneratedColumn({ name: 'id' })
	id: number

	@Column({ name: 'created_by', nullable: true })
	createdBy: number

	@Column({ name: 'updated_by', nullable: true })
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
