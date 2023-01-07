import { dataSource } from '../data-source'
import AdmissionEntity from '../entities/admission.entity'
import ClinicEntity from '../entities/clinic.entity'
import EmployeeEntity from '../entities/employee.entity'
import PatientEntity from '../entities/patient.entity'
import { AddressData } from '../random/address.service'
import { admissionSeeder } from './admission.fake'
import { employeeSeeder } from './employee.fake'
import { patientSeeder } from './patient.faker'

export const start = async () => {
	await AddressData.init()
	await dataSource.initialize()
	console.log('[START] - Connect Database successfully !!!')

	// Save one clinic
	const upsertClinicResult = await dataSource.getRepository(ClinicEntity).upsert({
		id: 1,
		email: 'example-1@gmail.com',
		phone: '0986021190',
	}, { skipUpdateIfNoValuesChanged: true, conflictPaths: {} })
	const clinicId = upsertClinicResult.identifiers[0].id

	// Save 20 employee
	const snapEmployeeList = await employeeSeeder(clinicId, 20)
	await dataSource.getRepository(EmployeeEntity).save(snapEmployeeList)

	// Save 1000 patient
	const snapPatientList = await patientSeeder(clinicId, 100)
	const patientList: PatientEntity[] = await dataSource.getRepository(PatientEntity).save(snapPatientList)
	const patientListId = patientList.map(item => item.id)

	// Save 3000 admission
	const snapAdmissionList = await admissionSeeder(clinicId, patientListId, 200)
	await dataSource.getRepository(AdmissionEntity).save(snapAdmissionList)

	await dataSource.destroy()
	console.log('[END] - Fake data successfully !!!')
}

start()
