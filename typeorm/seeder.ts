import { runSeeders } from 'typeorm-extension'
import { dataSource } from './data-source'
import { AddressData } from '../utils/address/address.service'

const startSeed = async () => {
	await AddressData.init()

	await dataSource.initialize()
	await runSeeders(dataSource)
	await dataSource.destroy()
	console.log('Typeorm seed database successfully !!!')
}

startSeed()
