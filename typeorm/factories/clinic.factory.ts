import { setSeederFactory } from 'typeorm-extension'
import { AddressData } from '../../utils/address/address.service'
import { randomItemsInArray, randomPhoneNumber } from '../../utils/helpers/random.helper'
import ClinicEntity from '../entities/clinic.entity'

export default setSeederFactory(ClinicEntity, (faker) => {
	const clinic = new ClinicEntity()

	clinic.phone = randomPhoneNumber()
	clinic.email = faker.internet.email()
	clinic.level = randomItemsInArray([1, 2, 3, 4, 5])
	clinic.address = AddressData.getRandomAddress()
	clinic.name = faker.name.fullName()

	return clinic
})
