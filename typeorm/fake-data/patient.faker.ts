import { faker } from '@faker-js/faker'
import { randomDate, randomFullName, randomItemsInArray, randomPhoneNumber } from '../../utils/helpers/random.helper'
import PatientEntity from '../entities/patient.entity'
import { AddressData } from '../random/address.service'

export const patientFactory = async (clinicId: number) => {
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

export const patientSeeder = async (clinicId: number, number: number) => {
	const factoryList = []
	for (let i = 0; i < number; i++) {
		factoryList.push(patientFactory(clinicId))
	}
	return await Promise.all(factoryList)
}
