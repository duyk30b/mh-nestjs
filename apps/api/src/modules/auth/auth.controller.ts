import { Body, Controller, Param, Post, Req } from '@nestjs/common'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'
import { Request } from 'express'
import { getClientIp } from 'request-ip'
import { LoginDto, RefreshTokenDto, RegisterDto } from './auth.dto'
import { AuthService } from './auth.service'
import { JwtExtendService } from './jwt-extend.service'

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
	constructor(
		private readonly authService: AuthService,
		private readonly jwtExtendService: JwtExtendService
	) { }

	@Post('register')
	@ApiBearerAuth('access-token')
	async register(@Body() registerDto: RegisterDto, @Req() request: Request) {
		const ip = getClientIp(request)
		const user = await this.authService.register(registerDto)
		const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(user)
		return { user, accessToken, refreshToken }
	}

	@Post('login')
	async login(@Body() loginDto: LoginDto) {
		const user = await this.authService.login(loginDto)
		const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(user)
		return { user, accessToken, refreshToken }
	}

	@Post('logout')
	logout(@Param('id') id: string) {
		// return this.authService.findOne(+id)
	}

	@Post('change-password')
	changePassword(@Param('id') id: string, @Body() updateAuthDto: LoginDto) {
		// return this.authService.update(+id, updateAuthDto)
	}

	@Post('forgot-password')
	forgotPassword(@Param('id') id: string) {
		// return this.authService.remove(+id)
	}

	@Post('refresh-token')
	async grantAccessToken(@Body() refreshTokenDto: RefreshTokenDto) {
		const refreshToken = await this.authService.grantAccessToken(refreshTokenDto.refreshToken)
		return { refreshToken }
	}
}