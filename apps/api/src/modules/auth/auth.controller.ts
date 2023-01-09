import { Body, Controller, Param, Post, SerializeOptions } from '@nestjs/common'
import { ApiTags } from '@nestjs/swagger'
import { IpRequest } from '../../decorators/request.decorator'
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
	async register(@Body() registerDto: RegisterDto, @IpRequest() ip: string): Promise<TokensResponse> {
		const employee = await this.authService.register(registerDto)
		const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee, ip)
		return new TokensResponse({ accessToken, refreshToken })
	}

	@Post('login')
	async login(@Body() loginDto: LoginDto, @IpRequest() ip: string): Promise<TokensResponse> {
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
	async grantAccessToken(@Body() refreshTokenDto: RefreshTokenDto, @IpRequest() ip: string): Promise<TokensResponse> {
		const accessToken = await this.authService.grantAccessToken(refreshTokenDto.refreshToken, ip)
		return new TokensResponse({ accessToken })
	}
}
