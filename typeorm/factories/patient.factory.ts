import { setSeederFactory } from 'typeorm-extension'
import { AddressData } from '../../utils/address/address.service'
import { randomDate, randomFullName, randomItemsInArray, randomNumber, randomPhoneNumber } from '../../utils/helpers/random.helper'
import PatientEntity from '../entities/patient.entity'

export default setSeederFactory(PatientEntity, (faker) => {
	const patient = new PatientEntity()
	patient.clinicId = randomNumber(1, 3)
	patient.fullName = randomFullName()
	patient.phone = randomPhoneNumber()
	patient.birthday = randomDate('1965-03-28', '2020-12-29')
	patient.gender = randomItemsInArray(['Male', 'Female'])
	patient.address = AddressData.getRandomAddress()

	return patient
})
