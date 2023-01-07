import * as bcrypt from 'bcrypt'
import { randomDate, randomFullName, randomItemsInArray, randomPhoneNumber, randomUsername } from '../../utils/helpers/random.helper'
import EmployeeEntity from '../entities/employee.entity'

export const employeeFactory = async (clinicId: number) => {
	const gender = randomItemsInArray(['Male', 'Female'])
	const fullName = randomFullName(gender)
	const birthday = randomDate('1980-03-28', '2001-12-29')
	const userName = randomUsername(fullName, birthday)
	const hashPassword = await bcrypt.hash('Abc@123456', 5)

	const employee = new EmployeeEntity()

	employee.clinicId = clinicId
	employee.phone = randomPhoneNumber()
	employee.username = userName
	employee.password = hashPassword
	employee.role = randomItemsInArray(['Owner', 'Admin', 'User'])
	employee.fullName = fullName
	employee.birthday = birthday
	employee.gender = gender

	return employee
}

export const employeeSeeder = async (clinicId: number, number: number) => {
	const factoryList = []
	for (let i = 0; i < number; i++) {
		factoryList.push(employeeFactory(clinicId))
	}
	return await Promise.all(factoryList)
}
