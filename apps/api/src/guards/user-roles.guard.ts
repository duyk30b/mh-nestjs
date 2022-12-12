import { CanActivate, ExecutionContext, Injectable, SetMetadata } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { TUserRole } from 'typeorm/entities/user.entity'
import { RequestToken } from '../common/constants'

export const UserRoles = (...userRoles: TUserRole[]) => SetMetadata('user_roles', userRoles)
@Injectable()
export class UserRolesGuard implements CanActivate {
	constructor(private reflector: Reflector) { }

	canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
		const roles = this.reflector.get<TUserRole[]>('user_roles', context.getHandler())
		if (!roles) return true

		const request: RequestToken = context.switchToHttp().getRequest()
		const { role } = request.tokenPayload
		return roles.includes(role)
	}
}