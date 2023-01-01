import { Controller, Get } from '@nestjs/common'
import { ApiTags } from '@nestjs/swagger'
import {
	DiskHealthIndicator, HealthCheck, HealthCheckService, HttpHealthIndicator,
	MemoryHealthIndicator, TypeOrmHealthIndicator,
} from '@nestjs/terminus'

@ApiTags('Health')
@Controller('health')
export class HealthController {
	constructor(
		private readonly health: HealthCheckService,
		private readonly http: HttpHealthIndicator,
		private readonly db: TypeOrmHealthIndicator,
		private readonly disk: DiskHealthIndicator,
		private readonly memory: MemoryHealthIndicator
	) { }

	@Get()
	@HealthCheck()
	check() {
		return this.health.check([
			() => this.http.pingCheck('nestjs-docs', 'https://medihome.vn/document'),
			() => this.db.pingCheck('database'),
			() => this.disk.checkStorage('storage', { path: '/', thresholdPercent: 0.5 }),
			() => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
			() => this.memory.checkRSS('memory_rss', 150 * 1024 * 1024),
		])
	}
}