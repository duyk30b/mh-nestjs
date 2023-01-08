import { randomNumber } from '../../../utils/helpers/random.helper'

export const randomBloodPressure = () => {
	const diastolic = randomNumber(60, 120)
	const systolic = diastolic + randomNumber(25, 70)
	return `${systolic}/${diastolic}`
}
