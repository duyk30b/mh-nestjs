import { Request } from 'express'
import { TEmployeeRole } from '../../../../typeorm/entities/employee.entity'

export interface IJwtPayload {
	username: string,
	role: TEmployeeRole,
	uid: number,
	cPhone: string
}

export interface RequestToken extends Request {
	tokenPayload: IJwtPayload
}
