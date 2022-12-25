export enum EError {
	Unknown = 'A00.UNKNOWN'
}

export enum EValidateError {
	Failed = 'V00.VALIDATE_FAILED'
}

export enum ERegisterError {
	ExistEmailAndPhone = 'R01.EXIST_EMAIL_AND_PHONE',
	ExistEmail = 'R02.EXIST_EMAIL',
	ExistPhone = 'R03.EXIST_PHONE',
	ExistUsername = 'R04.EXIST_USERNAME'
}

export enum ELoginError {
	EmployeeDoesNotExist = 'L01.EMPLOYEE_DOES_NOT_EXIST',
	WrongPassword = 'L02.WRONG_PASSWORD'
}

export enum ETokenError {
	Expired = 'T01.EXPIRED',
	Invalid = 'T02.INVALID'
}

export enum EEmployeeError {
	UsernameExists = 'U01.USERNAME_EXISTS',
	NotExists = 'U02.EMPLOYEE_DOES_NOT_EXIST'
}
