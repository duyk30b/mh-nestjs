import { dataSource } from '../data-source'
import AdmissionEntity from '../entities/admission.entity'
import ClinicEntity from '../entities/clinic.entity'
import EmployeeEntity from '../entities/employee.entity'
import PatientEntity from '../entities/patient.entity'
import { AddressData } from './common/address.service'
import { admissionSeeder } from './admission.fake'
import { employeeSeeder } from './employee.fake'
import { patientSeeder } from './patient.faker'

export const start = async () => {
	console.time('[SUCCESS] - Congratulation, Fake data successfully')

	await AddressData.init()
	await dataSource.initialize()

	// Save one clinic
	const upsertClinicResult = await dataSource.getRepository(ClinicEntity).upsert({
		id: 1,
		email: 'example-1@gmail.com',
		phone: '0986021190',
	}, { skipUpdateIfNoValuesChanged: true, conflictPaths: {} })
	const clinicId = upsertClinicResult.identifiers[0].id

	// Save employees
	await dataSource.getRepository(EmployeeEntity).upsert({
		id: 1,
		clinicId,
		username: 'admin',
		password: '$2b$05$G17lx6yO8fK2iJK6tqX2XODsCrawFzSht5vJQjE7wlDJO0.4zxPxO', // Abc@123456'
	}, { skipUpdateIfNoValuesChanged: true, conflictPaths: {} })
	const snapEmployeeList = employeeSeeder(clinicId, 20)
	await dataSource.getRepository(EmployeeEntity).save(snapEmployeeList)

	// Save patients
	const snapPatientList = patientSeeder(clinicId, 200)
	const patientList: PatientEntity[] = await dataSource.getRepository(PatientEntity).save(snapPatientList)
	const patientListId = patientList.map(item => item.id)

	// Save admissions
	const snapAdmissionList = admissionSeeder(clinicId, patientListId, 300)
	await dataSource.getRepository(AdmissionEntity).save(snapAdmissionList)

	await dataSource.destroy()
	console.timeEnd('[SUCCESS] - Congratulation, Fake data successfully')
}

start()
