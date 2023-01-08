import { faker } from '@faker-js/faker'
import { randomDate, randomFullName, randomItemsInArray, randomPhoneNumber } from '../../utils/helpers/random.helper'
import PatientEntity from '../entities/patient.entity'
import { AddressData } from './common/address.service'

export const patientFactory = (clinicId: number) => {
	const gender = randomItemsInArray(['Male', 'Female'])
	const fullName = randomFullName(gender)

	const patient = new PatientEntity()

	patient.clinicId = clinicId
	patient.fullName = fullName
	patient.phone = randomPhoneNumber()
	patient.birthday = randomDate('1965-03-28', '2020-12-29')
	patient.gender = gender
	patient.address = AddressData.getRandomAddress()
	patient.healthHistory = faker.lorem.paragraphs()

	return patient
}

export const patientSeeder = (clinicId: number, number: number) => {
	const factoryList: PatientEntity[] = []
	for (let i = 0; i < number; i++) {
		const patient = patientFactory(clinicId)
		factoryList.push(patient)
	}

	return factoryList
}
