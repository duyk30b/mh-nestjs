export enum EValidateError {
	FAILD = 'V00.VALIDATE_FAIL'
}

export enum ERegisterError {
	ExistEmailAndPhone = 'R01.EMAIL_AND_PHONE_EXISTS',
	ExistEmail = 'R02.EMAIL_EXISTS',
	ExistPhone = 'R03.PHONE_EXISTS',
}

export enum ELoginError {
	UserDoesNotExist = 'L01.USER_DOES_NOT_EXIST',
	WrongPassword = 'L02.WRONG_PASSWORD'
}
