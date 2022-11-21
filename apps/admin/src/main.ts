import { NestFactory } from '@nestjs/core'
import { AdminModule } from './admin.module'
import Env from '../../../config/env'

async function bootstrap() {
	const app = await NestFactory.create(AdminModule)
	await app.listen(3000)
	console.log(Env)
}
bootstrap()
