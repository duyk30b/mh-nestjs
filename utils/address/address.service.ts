import * as fs from 'fs'
import { randomItemsInArray } from '../helpers/random.helper'
import { HttpsGet } from '../helpers/request.helper'

type Ward = {
	name: string
}

type District = {
	code: number
	name: string
	wards: Ward[]
}

type Province = {
	code: number
	name: string
	districts: District[]
}

const DIR = 'utils/address'

class Address {
	provinces: Province[] = []

	async init() {
		try {
			this.provinces = JSON.parse(fs.readFileSync(`${DIR}/address-min.json`, 'utf-8'))
		} catch (error) {
			console.log('🚀 ~ file: address.service.ts:29 ~ Address ~ initProvince ~ error', error)
		}

		if (this.provinces.length) return

		const response = await HttpsGet('https://provinces.open-api.vn/api/p/') as string
		this.provinces = JSON.parse(response)

		await Promise.all(this.provinces.map(item => this.initDistrict(item)))

		fs.writeFileSync(`${DIR}/address.json`, JSON.stringify(this.provinces, null, 4))
		fs.writeFileSync(`${DIR}/address-min.json`, JSON.stringify(this.provinces))
	}

	async initDistrict(province: Province) {
		if (province.districts.length === 0) {
			const response = await HttpsGet(`https://provinces.open-api.vn/api/p/${province.code}?depth=3`) as string
			const data: Province = JSON.parse(response)
			province.districts = data.districts
		}
	}

	getRandomAddress(): string {
		const province: Province = randomItemsInArray(this.provinces)
		const district: District = randomItemsInArray(province.districts)
		const ward: Ward = randomItemsInArray(district.wards)
		return `${province?.name} -- ${district?.name} -- ${ward?.name}`
	}
}

export const AddressData = new Address()
