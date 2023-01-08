import { Body, Controller, Param, Post, Req, SerializeOptions } from '@nestjs/common'
import { ApiTags } from '@nestjs/swagger'
import { Request } from 'express'
import { getClientIp } from 'request-ip'
import { LoginDto, RefreshTokenDto, RegisterDto, TokensResponse } from './auth.dto'
import { AuthService } from './auth.service'
import { JwtExtendService } from './jwt-extend.service'

@ApiTags('Auth')
@SerializeOptions({ excludeExtraneousValues: true, exposeUnsetFields: false })
@Controller('auth')
export class AuthController {
	constructor(
		private readonly authService: AuthService,
		private readonly jwtExtendService: JwtExtendService
	) { }

	@Post('register')
	async register(@Body() registerDto: RegisterDto, @Req() request: Request): Promise<TokensResponse> {
		const ip = getClientIp(request)
		const employee = await this.authService.register(registerDto)
		const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee, ip)
		return new TokensResponse({ accessToken, refreshToken })
	}

	@Post('login')
	async login(@Body() loginDto: LoginDto, @Req() request: Request): Promise<TokensResponse> {
		console.log('🚀 ~ file: auth.controller.ts:33 ~ AuthController ~ login ~ loginDto', loginDto)
		const ip = getClientIp(request)
		const employee = await this.authService.login(loginDto)
		const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee, ip)
		return new TokensResponse({ accessToken, refreshToken })
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
	async grantAccessToken(@Body() refreshTokenDto: RefreshTokenDto, @Req() request: Request): Promise<TokensResponse> {
		const ip = getClientIp(request)
		const accessToken = await this.authService.grantAccessToken(refreshTokenDto.refreshToken, ip)
		return new TokensResponse({ accessToken })
	}
}
