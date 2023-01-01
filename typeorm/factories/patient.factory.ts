import { setSeederFactory } from 'typeorm-extension'
import { AddressData } from '../../utils/address/address.service'
import { randomDate, randomFullName, randomItemsInArray, randomNumber, randomPhoneNumber } from '../../utils/helpers/random.helper'
import PatientEntity from '../entities/patient.entity'

export default setSeederFactory(PatientEntity, (faker) => {
	const gender = randomItemsInArray(['Male', 'Female'])
	const fullName = randomFullName(gender)

	const patient = new PatientEntity()
	patient.clinicId = randomNumber(1, 3)
	patient.fullName = fullName
	patient.phone = randomPhoneNumber()
	patient.birthday = randomDate('1965-03-28', '2020-12-29')
	patient.gender = gender
	patient.address = AddressData.getRandomAddress()

	return patient
})
