import { Request } from 'express'
import { TEmployeeRole } from '../../../../typeorm/entities/employee.entity'

export interface IJwtPayload {
	ip: string
	username: string,
	role: TEmployeeRole,
	cid: number,
	uid: number,
	cPhone: string
}

export interface RequestToken extends Request {
	tokenPayload: IJwtPayload
}
