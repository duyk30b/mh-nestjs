import { faker } from '@faker-js/faker'
import { randomBloodPressure, randomItemsInArray, randomNumber } from '../../utils/helpers/random.helper'
import AdmissionEntity from '../entities/admission.entity'

export const admissionFactory = async (clinicId: number, patientIds: number[]) => {
	const admission = new AdmissionEntity()

	admission.clinicId = clinicId
	admission.patientId = randomItemsInArray(patientIds)
	admission.reason = faker.lorem.sentence()
	admission.medicalRecord = faker.lorem.paragraphs()
	admission.diagnosis = faker.lorem.sentence()

	admission.pulse = randomNumber(60, 140)
	admission.temperature = randomNumber(36.5, 40, 0.1)
	admission.bloodPressure = randomBloodPressure()
	admission.respiratoryRate = randomNumber(15, 30)
	admission.spO2 = randomNumber(92, 100)

	admission.note = faker.lorem.sentence()

	return admission
}

export const admissionSeeder = async (clinicId: number, patientIds: number[], number: number) => {
	const factoryList = []
	for (let i = 0; i < number; i++) {
		factoryList.push(admissionFactory(clinicId, patientIds))
	}
	return await Promise.all(factoryList)
}
