import { Seeder, SeederFactoryManager } from 'typeorm-extension'
import { DataSource } from 'typeorm'
import EmployeeEntity, { EEmployeeRole } from '../entities/employee.entity'
import * as bcrypt from 'bcrypt'

export default class EmployeeSeeder implements Seeder {
	public async run(dataSource: DataSource, factoryManager: SeederFactoryManager): Promise<any> {
		const repository = dataSource.getRepository(EmployeeEntity)

		let firstEmployee = await repository.findOneBy({ id: 1 })
		if (!firstEmployee) {
			firstEmployee = new EmployeeEntity()
			firstEmployee.id = 1
		}
		firstEmployee.clinicId = 1
		firstEmployee.username = 'admin'
		firstEmployee.password = await bcrypt.hash('Abc@123456', 5)
		firstEmployee.role = EEmployeeRole.Owner
		await repository.save(firstEmployee)

		const factory = factoryManager.get(EmployeeEntity)
		await factory.saveMany(50)
	}
}
