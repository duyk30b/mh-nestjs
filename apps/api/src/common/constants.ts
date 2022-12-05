import { Request } from 'express'

export enum EUserRole {
	Owner = 'Owner',
	Admin = 'Admin',
	User = 'User',
}

export type TUserRole = keyof typeof EUserRole

export interface IJwtPayload {
	username: string,
	role: TUserRole,
	uid: number,
	cid: number
}

export interface RequestToken extends Request {
	tokenPayload: IJwtPayload
}
