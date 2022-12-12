import { Request } from 'express'
import { TUserRole } from '../../../../typeorm/entities/user.entity'

export interface IJwtPayload {
	username: string,
	role: TUserRole,
	uid: number,
	cid: number
}

export interface RequestToken extends Request {
	tokenPayload: IJwtPayload
}
