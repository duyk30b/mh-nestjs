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
		const pathStorage = process.platform === 'win32' ? 'C:\\' : '/'
		const thresholdPercent = process.platform === 'win32' ? 0.9 : 0.5

		return this.health.check([
			() => this.http.pingCheck('nestjs-docs', 'https://medihome.vn/document'),
			() => this.db.pingCheck('database'),
			() => this.disk.checkStorage('storage', { path: pathStorage, thresholdPercent }),
			() => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
			() => this.memory.checkRSS('memory_rss', 150 * 1024 * 1024),
		])
	}
}
