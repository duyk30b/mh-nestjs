import { Request } from 'express'
import { ERole } from '../../../../typeorm/entities/employee.entity'

export interface IJwtPayload {
	ip: string
	username: string,
	role: ERole,
	cid: number,
	uid: number,
	cPhone: string
}

export interface RequestToken extends Request {
	tokenPayload: IJwtPayload
}
