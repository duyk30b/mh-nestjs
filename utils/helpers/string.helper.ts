const _CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

const generateCharset = (privateKey = 'Abc123', charset = _CHARSET): string => {
	let tempString = charset
	let result = ''
	for (let i = 0; i < _CHARSET.length; i += 1) {
		const kIndex = i % privateKey.length
		const charCode = privateKey.charCodeAt(kIndex)
		const tIndex = charCode % tempString.length

		result = tempString[tIndex] + result
		tempString = tempString.substring(tIndex + 1) + tempString.substring(0, tIndex)
	}
	return result
}

export const randomId = (): string => {
	const now = new Date().getTime().toString(36) // l0u2ifgu - ... - ... - todo
	return now
}

export const randomString = (length = 10, characters = _CHARSET): string => {
	let result = ''
	for (let i = 0; i < length; i += 1) {
		result += characters.charAt(Math.floor(Math.random() * characters.length))
	}
	return result
}

export const encrypt = (rootString: string, privateKey?: string): string => {
	const hash = generateCharset(privateKey)
	let result = ''
	for (let i = 0; i < rootString.length; i += 1) {
		const index = _CHARSET.indexOf(rootString[i])
		if (index === -1) {
			result += rootString[i]
		} else {
			result += hash[index]
		}
	}
	return result
}

export const decrypt = (cipherText: string, privateKey?: string): string => {
	const hash = generateCharset(privateKey)
	let result = ''
	for (let i = 0; i < cipherText.length; i += 1) {
		const index = hash.indexOf(cipherText[i])
		if (index === -1) {
			result += cipherText[i]
		} else {
			result += _CHARSET[index]
		}
	}
	return result
}

export const convertViToEn = (root: string): string =>
	root
		.normalize('NFD')
		.replace(/[\u0300-\u036f]/g, '')
		.replace(/đ/g, 'd')
		.replace(/Đ/g, 'D')

export const formatNumber = (number: number, fixed = 3, part = 3, sec = ',', dec = '.') => {
	const regex = '\\d(?=(\\d{' + part + '})+' + (fixed > 0 ? '\\D' : '$') + ')'
	return number
		.toFixed(fixed)
		.replace('.', dec)
		.replace(new RegExp(regex, 'g'), '$&' + sec)
}
