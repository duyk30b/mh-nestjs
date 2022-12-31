import { setSeederFactory } from 'typeorm-extension'
import { randomDate, randomFullName, randomItemsInArray, randomNumber, randomPhoneNumber, randomUsername } from '../../utils/helpers/random.helper'
import EmployeeEntity from '../entities/employee.entity'
import * as bcrypt from 'bcrypt'

export default setSeederFactory(EmployeeEntity, async (faker) => {
	const employee = new EmployeeEntity()

	const gender = randomItemsInArray(['Male', 'Female'])
	const fullName = randomFullName(gender)
	const birthday = randomDate('1980-03-28', '2001-12-29')
	const userName = randomUsername(fullName, birthday)
	const hashPassword = await bcrypt.hash('Abc@123456', 5)

	employee.clinicId = randomNumber(1, 3)
	employee.phone = randomPhoneNumber()
	employee.username = userName
	employee.password = hashPassword
	employee.role = randomItemsInArray(['Owner', 'Admin', 'User'])
	employee.fullName = fullName
	employee.birthday = birthday
	employee.gender = gender

	return employee
})
