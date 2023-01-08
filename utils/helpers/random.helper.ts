import { convertViToEn } from './string.helper'

export const randomItemsInArray = (items: any[]) => items[Math.floor(Math.random() * items.length)]

export const randomNumber = (min: number, max: number, step = 1) => {
	const count = (max - min) / step + 1
	return Math.floor(Math.random() * count) * step + min
}

export const randomPhoneNumber = (): string => {
	const headNumber = randomItemsInArray(['03', '05', '07', '08', '09'])
	const tailNumber = ('00000000' + randomNumber(0, 99_999_999)).slice(-8)
	return headNumber + tailNumber
}

export const randomFullName = (gender?: 'Male' | 'Female', hasMiddle = true): string => {
	const surname = randomItemsInArray(['Nguyễn', 'Lê', 'Phạm', 'Vũ', 'Phan', 'Trương', 'Trần', 'Bùi', 'Đặng', 'Đỗ', 'Ngô', 'Dương'])
	let middleName = '',
		lastName = ''
	if (gender === 'Female') {
		middleName = randomItemsInArray(['Hồng', 'Lệ', 'Thị', 'Thu', 'Thanh', 'Tuyết', 'Thảo', 'Trúc', 'Quỳnh'])
		lastName = randomItemsInArray(['Bích', 'Chi', 'Diệp', 'Diệu', 'Duyên', 'Hoa', 'Huyền', 'Hương', 'Linh', 'Mai', 'Nga', 'Ngọc', 'Thảo', 'Trang', 'Quỳnh'])
	} else {
		middleName = randomItemsInArray(['Anh', 'Đình', 'Huy', 'Mạnh', 'Minh', 'Nam', 'Ngọc', 'Nhật', 'Thái', 'Thanh', 'Văn', 'Việt'])
		lastName = randomItemsInArray(['Đạt', 'Khánh', 'Khôi', 'Kiên', 'Lâm', 'Huy', 'Hùng', 'Hoàng', 'Minh', 'Nghĩa', 'Sơn', 'Tùng', 'Trung', 'Trường', 'Thắng', 'Quang', 'Quân'])
	}
	if (!hasMiddle) return `${surname} ${lastName}`
	return `${surname} ${middleName} ${lastName}`
}

export const randomDate = (minDate?: Date | string | number, maxDate?: Date | string | number): Date => {
	if (!minDate) minDate = new Date('1950-12-25')
	if (!maxDate) maxDate = new Date('2050-12-25')
	if (typeof minDate !== 'object') minDate = new Date(minDate)
	if (typeof maxDate !== 'object') maxDate = new Date(maxDate)

	const timeRandom = randomNumber(minDate.getTime(), maxDate.getTime())
	return new Date(timeRandom)
}

export const randomUsername = (fullName?: string, birthday?: Date): string => {
	if (!fullName) fullName = randomFullName('Male')
	if (!birthday) birthday = randomDate('1960-01-29', '2000-12-25')
	const nameEng = convertViToEn(fullName).toLowerCase()
	const text = nameEng.split(' ').slice(-2).join('')
	const number = birthday.getFullYear().toString().slice(-2)
	return text + number
}
