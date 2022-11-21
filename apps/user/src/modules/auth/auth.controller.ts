import { Body, Controller, Param, Post, Req } from '@nestjs/common'
import { ApiTags } from '@nestjs/swagger'
import { Request } from 'express'
import { getClientIp } from 'request-ip'
import { AuthService } from './auth.service'
import { LoginDto, RegisterDto } from './auth.dto'

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
	constructor(private readonly authService: AuthService) { }

	@Post('register')
	async register(@Body() registerDto: RegisterDto, @Req() request: Request) {
		const ip = getClientIp(request)
		const employeeInfo = await this.authService.register(registerDto)
		const employee = {
			username: employeeInfo.username,
			role: employeeInfo.role,
		}
		const accessToken = this.authService.createAccessToken(employee)
		const refreshToken = this.authService.createRefreshToken(employee)
		return { employee, accessToken, refreshToken }
	}

	@Post('login')
	async login(@Body() loginDto: LoginDto) {
		const employeeInfo = await this.authService.login(loginDto)
		const employee = {
			username: employeeInfo.username,
			role: employeeInfo.role,
		}
		const accessToken = this.authService.createAccessToken(employee)
		const refreshToken = this.authService.createRefreshToken(employee)
		return { employee, accessToken, refreshToken }
	}

	@Post('logout')
	findOne(@Param('id') id: string) {
		// return this.authService.findOne(+id)
	}

	@Post('change-password')
	update(@Param('id') id: string, @Body() updateAuthDto: LoginDto) {
		// return this.authService.update(+id, updateAuthDto)
	}

	@Post('forgot-password')
	remove(@Param('id') id: string) {
		// return this.authService.remove(+id)
	}
}
