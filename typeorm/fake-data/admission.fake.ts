import { faker } from '@faker-js/faker'
import { randomItemsInArray, randomNumber } from '../../utils/helpers/random.helper'
import AdmissionEntity from '../entities/admission.entity'
import { randomBloodPressure } from './common/random'

export const admissionFactory = (clinicId: number, patientIds: number[]) => {
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

export const admissionSeeder = (clinicId: number, patientIds: number[], number: number) => {
	const factoryList: AdmissionEntity[] = []
	for (let i = 0; i < number; i++) {
		const admission = admissionFactory(clinicId, patientIds)
		factoryList.push(admission)
	}

	return factoryList
}
