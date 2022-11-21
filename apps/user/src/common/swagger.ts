import { INestApplication } from '@nestjs/common'
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger'

export const setupSwagger = (app: INestApplication) => {
	const config = new DocumentBuilder()
		.setTitle('Simple API')
		.setDescription('Simple API use Swagger')
		.setVersion('1.0')
		.addBearerAuth()
		.build()
	const document = SwaggerModule.createDocument(app, config)
	SwaggerModule.setup('document', app, document)
}
