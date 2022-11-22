import { INestApplication } from '@nestjs/common'
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger'

export const setupSwagger = (app: INestApplication) => {
	const config = new DocumentBuilder()
		.setTitle('Simple API')
		.setDescription('Medihome API use Swagger')
		.setVersion('1.0')
		.addBearerAuth(
			{ type: 'http', description: 'Access token' },
			'access-token'
		)
		.build()
	const document = SwaggerModule.createDocument(app, config)
	SwaggerModule.setup('document', app, document)
}
