export enum EError {
	Unknow = 'A00.UNKNOW'
}

export enum EValidateError {
	Faild = 'V00.VALIDATE_FAIL'
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

export enum ETokenError {
	Expired = 'T01.EXPIRED',
	Invalid = 'T02.INVALID'
}

export enum EUserError {
	UsernameExists = 'U01.Username_Exists'
}