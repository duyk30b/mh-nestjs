import { Controller, Post, Body, Param } from '@nestjs/common'
import { AuthService } from './auth.service'
import { CreateAuthDto } from './dto/create-auth.dto'
import { UpdateAuthDto } from './dto/update-auth.dto'

@Controller('auth')
export class AuthController {
	constructor(private readonly authService: AuthService) { }

	@Post('register')
	create(@Body() createAuthDto: CreateAuthDto) {
		return this.authService.create(createAuthDto)
	}

	@Post('login')
	findAll() {
		return this.authService.findAll()
	}

	@Post('logout')
	findOne(@Param('id') id: string) {
		return this.authService.findOne(+id)
	}

	@Post('change-password')
	update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
		return this.authService.update(+id, updateAuthDto)
	}

	@Post('forgot-password')
	remove(@Param('id') id: string) {
		return this.authService.remove(+id)
	}
}
