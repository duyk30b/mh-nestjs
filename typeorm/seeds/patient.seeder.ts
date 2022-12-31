import { Seeder, SeederFactoryManager } from 'typeorm-extension'
import { DataSource } from 'typeorm'
import PatientEntity from '../entities/patient.entity'

export default class PatientSeeder implements Seeder {
	public async run(dataSource: DataSource, factoryManager: SeederFactoryManager): Promise<any> {
		const factory = factoryManager.get(PatientEntity)
		await factory.saveMany(1000)
	}
}
