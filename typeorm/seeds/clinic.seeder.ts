import { DataSource } from 'typeorm'
import { Seeder, SeederFactoryManager } from 'typeorm-extension'
import ClinicEntity from '../entities/clinic.entity'

export default class ClinicSeeder implements Seeder {
	public async run(dataSource: DataSource, factoryManager: SeederFactoryManager): Promise<any> {
		const repository = dataSource.getRepository(ClinicEntity)

		let firstClinic = await repository.findOneBy({ id: 1 })
		if (!firstClinic) {
			firstClinic = new ClinicEntity()
			firstClinic.id = 1
		}
		firstClinic.email = 'example-1@gmail.com'
		firstClinic.phone = '0986021190'
		await repository.save(firstClinic)

		const factory = factoryManager.get(ClinicEntity)
		await factory.saveMany(2)
	}
}
