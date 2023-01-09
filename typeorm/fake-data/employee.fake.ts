import { randomDate, randomFullName, randomItemsInArray, randomPhoneNumber, randomUsername } from '../../utils/helpers/random.helper'
import { EGender } from '../base.entity'
import EmployeeEntity, { ERole } from '../entities/employee.entity'

export const employeeFactory = (clinicId: number) => {
	const gender = randomItemsInArray(Object.values(EGender))
	const fullName = randomFullName(gender)
	const birthday = randomDate('1980-03-28', '2001-12-29')
	const userName = randomUsername(fullName, birthday)
	const hashPassword = '$2b$05$G17lx6yO8fK2iJK6tqX2XODsCrawFzSht5vJQjE7wlDJO0.4zxPxO'  // Abc@123456'

	const employee = new EmployeeEntity()

	employee.clinicId = clinicId
	employee.phone = randomPhoneNumber()
	employee.username = userName
	employee.password = hashPassword
	employee.role = randomItemsInArray(Object.values(ERole))
	employee.fullName = fullName
	employee.birthday = birthday
	employee.gender = gender

	return employee
}

export const employeeSeeder = (clinicId: number, number: number) => {
	const factoryList: EmployeeEntity[] = []
	for (let i = 0; i < number; i++) {
		const employee = employeeFactory(clinicId)
		factoryList.push(employee)
	}

	return factoryList
}
