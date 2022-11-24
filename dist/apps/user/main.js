/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/user/src/app.module.ts":
/*!*************************************!*\
  !*** ./apps/user/src/app.module.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const enviroments_1 = __webpack_require__(/*! ./enviroments */ "./apps/user/src/enviroments.ts");
const logger_middleware_1 = __webpack_require__(/*! ./middlewares/logger.middleware */ "./apps/user/src/middlewares/logger.middleware.ts");
const validate_access_token_middleware_1 = __webpack_require__(/*! ./middlewares/validate-access-token.middleware */ "./apps/user/src/middlewares/validate-access-token.middleware.ts");
const auth_module_1 = __webpack_require__(/*! ./modules/auth/auth.module */ "./apps/user/src/modules/auth/auth.module.ts");
const clinic_module_1 = __webpack_require__(/*! ./modules/clinic/clinic.module */ "./apps/user/src/modules/clinic/clinic.module.ts");
const employee_module_1 = __webpack_require__(/*! ./modules/employee/employee.module */ "./apps/user/src/modules/employee/employee.module.ts");
const medicine_module_1 = __webpack_require__(/*! ./modules/medicine/medicine.module */ "./apps/user/src/modules/medicine/medicine.module.ts");
let AppModule = class AppModule {
    constructor(dataSource) {
        this.dataSource = dataSource;
    }
    configure(consumer) {
        consumer.apply(logger_middleware_1.LoggerMiddleware).forRoutes('*');
        consumer.apply(validate_access_token_middleware_1.ValidateAccessTokenMiddleware)
            .exclude('auth/(.*)')
            .forRoutes('*');
    }
};
AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                envFilePath: ['.env', `.env.${process.env.NODE_ENV}`],
                isGlobal: true,
            }),
            typeorm_1.TypeOrmModule.forRootAsync({
                imports: [config_1.ConfigModule.forRoot({ load: [enviroments_1.MysqlConfig] })],
                inject: [enviroments_1.MysqlConfig.KEY],
                useFactory: (mysqlConfig) => mysqlConfig,
            }),
            auth_module_1.AuthModule,
            clinic_module_1.ClinicModule,
            employee_module_1.EmployeeModule,
            medicine_module_1.MedicineModule,
        ],
    }),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.DataSource !== "undefined" && typeorm_2.DataSource) === "function" ? _a : Object])
], AppModule);
exports.AppModule = AppModule;


/***/ }),

/***/ "./apps/user/src/common/class-validator.custom.ts":
/*!********************************************************!*\
  !*** ./apps/user/src/common/class-validator.custom.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IsGmail = exports.IsPhone = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
let IsPhone = class IsPhone {
    validate(text, args) {
        return /((09|03|07|08|05)+([0-9]{8})\b)/g.test(text);
    }
    defaultMessage(args) {
        return '$property must be real numberphone !';
    }
};
IsPhone = __decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'isPhone', async: false })
], IsPhone);
exports.IsPhone = IsPhone;
let IsGmail = class IsGmail {
    validate(text, args) {
        return /^([a-zA-Z0-9]|\.|-|_)+(@gmail.com)$/.test(text);
    }
    defaultMessage(args) {
        return '$property must be a gmail address !';
    }
};
IsGmail = __decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'isGmail', async: false })
], IsGmail);
exports.IsGmail = IsGmail;


/***/ }),

/***/ "./apps/user/src/common/constants.ts":
/*!*******************************************!*\
  !*** ./apps/user/src/common/constants.ts ***!
  \*******************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EUserRole = void 0;
var EUserRole;
(function (EUserRole) {
    EUserRole["Owner"] = "Owner";
    EUserRole["Admin"] = "Admin";
    EUserRole["User"] = "User";
})(EUserRole = exports.EUserRole || (exports.EUserRole = {}));


/***/ }),

/***/ "./apps/user/src/common/swagger.ts":
/*!*****************************************!*\
  !*** ./apps/user/src/common/swagger.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.setupSwagger = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const setupSwagger = (app) => {
    const config = new swagger_1.DocumentBuilder()
        .setTitle('Simple API')
        .setDescription('Medihome API use Swagger')
        .setVersion('1.0')
        .addBearerAuth({ type: 'http', description: 'Access token' }, 'access-token')
        .build();
    const document = swagger_1.SwaggerModule.createDocument(app, config);
    swagger_1.SwaggerModule.setup('document', app, document);
};
exports.setupSwagger = setupSwagger;


/***/ }),

/***/ "./apps/user/src/enviroments.ts":
/*!**************************************!*\
  !*** ./apps/user/src/enviroments.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MysqlConfig = exports.JwtConfig = void 0;
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
exports.JwtConfig = (0, config_1.registerAs)('jwt', () => ({
    accessKey: process.env.JWT_ACCESS_KEY,
    refreshKey: process.env.JWT_REFRESH_KEY,
    accessTime: Number(process.env.JWT_ACCESS_TIME),
    refreshTime: Number(process.env.JWT_REFRESH_TIME),
}));
exports.MysqlConfig = (0, config_1.registerAs)('mysql', () => ({
    type: 'mysql',
    host: process.env.MYSQL_HOST,
    port: parseInt(process.env.MYSQL_PORT, 10),
    database: process.env.MYSQL_DATABASE,
    username: process.env.MYSQL_USERNAME,
    password: process.env.MYSQL_PASSWORD,
    autoLoadEntities: true,
    logging: process.env.NODE_ENV !== 'production',
    synchronize: process.env.NODE_ENV === 'local',
}));


/***/ }),

/***/ "./apps/user/src/guards/user-roles.guard.ts":
/*!**************************************************!*\
  !*** ./apps/user/src/guards/user-roles.guard.ts ***!
  \**************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserRolesGuard = exports.UserRoles = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const UserRoles = (...userRoles) => (0, common_1.SetMetadata)('user_roles', userRoles);
exports.UserRoles = UserRoles;
let UserRolesGuard = class UserRolesGuard {
    constructor(reflector) {
        this.reflector = reflector;
    }
    canActivate(context) {
        const roles = this.reflector.get('user_roles', context.getHandler());
        if (!roles)
            return true;
        const request = context.switchToHttp().getRequest();
        const { role } = request.tokenPayload;
        return roles.includes(role);
    }
};
UserRolesGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object])
], UserRolesGuard);
exports.UserRolesGuard = UserRolesGuard;


/***/ }),

/***/ "./apps/user/src/interceptor/access-log.interceptor.ts":
/*!*************************************************************!*\
  !*** ./apps/user/src/interceptor/access-log.interceptor.ts ***!
  \*************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AccessLogInterceptor = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const request_ip_1 = __webpack_require__(/*! request-ip */ "request-ip");
const operators_1 = __webpack_require__(/*! rxjs/operators */ "rxjs/operators");
let AccessLogInterceptor = class AccessLogInterceptor {
    constructor(logger = new common_1.Logger('ACCESS_LOG')) {
        this.logger = logger;
    }
    intercept(context, next) {
        const startTime = new Date();
        const ctx = context.switchToHttp();
        const request = ctx.getRequest();
        const response = ctx.getRequest();
        const { url, method } = request;
        const { statusCode } = response;
        const ip = (0, request_ip_1.getClientIp)(request);
        return next.handle().pipe((0, operators_1.tap)(() => {
            const msg = `${startTime.toISOString()} | ${ip} | ${method} | ${statusCode} | ${url} | ${Date.now() - startTime.getTime()}ms`;
            return this.logger.log(msg);
        }));
    }
};
AccessLogInterceptor = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [Object])
], AccessLogInterceptor);
exports.AccessLogInterceptor = AccessLogInterceptor;


/***/ }),

/***/ "./apps/user/src/interceptor/timeout.interceptor.ts":
/*!**********************************************************!*\
  !*** ./apps/user/src/interceptor/timeout.interceptor.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimeoutInterceptor = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const rxjs_1 = __webpack_require__(/*! rxjs */ "rxjs");
const operators_1 = __webpack_require__(/*! rxjs/operators */ "rxjs/operators");
let TimeoutInterceptor = class TimeoutInterceptor {
    intercept(context, next) {
        return next.handle().pipe((0, operators_1.timeout)(10000), (0, operators_1.catchError)(err => {
            if (err instanceof rxjs_1.TimeoutError) {
                return (0, rxjs_1.throwError)(() => new common_1.RequestTimeoutException());
            }
            return (0, rxjs_1.throwError)(() => err);
        }));
    }
};
TimeoutInterceptor = __decorate([
    (0, common_1.Injectable)()
], TimeoutInterceptor);
exports.TimeoutInterceptor = TimeoutInterceptor;


/***/ }),

/***/ "./apps/user/src/middlewares/logger.middleware.ts":
/*!********************************************************!*\
  !*** ./apps/user/src/middlewares/logger.middleware.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoggerMiddleware = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let LoggerMiddleware = class LoggerMiddleware {
    use(req, res, next) {
        console.log('Request...');
        next();
    }
};
LoggerMiddleware = __decorate([
    (0, common_1.Injectable)()
], LoggerMiddleware);
exports.LoggerMiddleware = LoggerMiddleware;


/***/ }),

/***/ "./apps/user/src/middlewares/validate-access-token.middleware.ts":
/*!***********************************************************************!*\
  !*** ./apps/user/src/middlewares/validate-access-token.middleware.ts ***!
  \***********************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidateAccessTokenMiddleware = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const jwt_extend_service_1 = __webpack_require__(/*! ../modules/auth/jwt-extend.service */ "./apps/user/src/modules/auth/jwt-extend.service.ts");
let ValidateAccessTokenMiddleware = class ValidateAccessTokenMiddleware {
    constructor(jwtExtendService) {
        this.jwtExtendService = jwtExtendService;
    }
    async use(req, res, next) {
        const authorization = req.header('Authorization') || '';
        const [, accessToken] = authorization.split(' ');
        const decode = this.jwtExtendService.verifyAccessToken(accessToken);
        req.tokenPayload = decode;
        next();
    }
};
ValidateAccessTokenMiddleware = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof jwt_extend_service_1.JwtExtendService !== "undefined" && jwt_extend_service_1.JwtExtendService) === "function" ? _a : Object])
], ValidateAccessTokenMiddleware);
exports.ValidateAccessTokenMiddleware = ValidateAccessTokenMiddleware;


/***/ }),

/***/ "./apps/user/src/modules/auth/auth.controller.ts":
/*!*******************************************************!*\
  !*** ./apps/user/src/modules/auth/auth.controller.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const express_1 = __webpack_require__(/*! express */ "express");
const request_ip_1 = __webpack_require__(/*! request-ip */ "request-ip");
const auth_dto_1 = __webpack_require__(/*! ./auth.dto */ "./apps/user/src/modules/auth/auth.dto.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/user/src/modules/auth/auth.service.ts");
const jwt_extend_service_1 = __webpack_require__(/*! ./jwt-extend.service */ "./apps/user/src/modules/auth/jwt-extend.service.ts");
let AuthController = class AuthController {
    constructor(authService, jwtExtendService) {
        this.authService = authService;
        this.jwtExtendService = jwtExtendService;
    }
    async register(registerDto, request) {
        const ip = (0, request_ip_1.getClientIp)(request);
        const employee = await this.authService.register(registerDto);
        const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromEmployee(employee);
        return { employee, accessToken, refreshToken };
    }
    async login(loginDto) {
        const employee = await this.authService.login(loginDto);
        const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromEmployee(employee);
        return { employee, accessToken, refreshToken };
    }
    findOne(id) {
    }
    update(id, updateAuthDto) {
    }
    remove(id) {
    }
};
__decorate([
    (0, common_1.Post)('register'),
    (0, swagger_1.ApiBearerAuth)('access-token'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof auth_dto_1.RegisterDto !== "undefined" && auth_dto_1.RegisterDto) === "function" ? _c : Object, typeof (_d = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _d : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_e = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _e : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('logout'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "findOne", null);
__decorate([
    (0, common_1.Post)('change-password'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_f = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _f : Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "update", null);
__decorate([
    (0, common_1.Post)('forgot-password'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "remove", null);
AuthController = __decorate([
    (0, swagger_1.ApiTags)('Auth'),
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof jwt_extend_service_1.JwtExtendService !== "undefined" && jwt_extend_service_1.JwtExtendService) === "function" ? _b : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),

/***/ "./apps/user/src/modules/auth/auth.dto.ts":
/*!************************************************!*\
  !*** ./apps/user/src/modules/auth/auth.dto.ts ***!
  \************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginDto = exports.RegisterDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const class_validator_custom_1 = __webpack_require__(/*! ../../common/class-validator.custom */ "./apps/user/src/common/class-validator.custom.ts");
class RegisterDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'example@gmail.com' }),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsGmail),
    __metadata("design:type", String)
], RegisterDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: '0987123456' }),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsPhone),
    __metadata("design:type", String)
], RegisterDto.prototype, "phone", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], RegisterDto.prototype, "password", void 0);
exports.RegisterDto = RegisterDto;
class LoginDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'example@gmail.com' }),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsGmail),
    __metadata("design:type", String)
], LoginDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Admin' }),
    __metadata("design:type", String)
], LoginDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 1 }),
    __metadata("design:type", Number)
], LoginDto.prototype, "clinicId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], LoginDto.prototype, "password", void 0);
exports.LoginDto = LoginDto;


/***/ }),

/***/ "./apps/user/src/modules/auth/auth.module.ts":
/*!***************************************************!*\
  !*** ./apps/user/src/modules/auth/auth.module.ts ***!
  \***************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const enviroments_1 = __webpack_require__(/*! ../../enviroments */ "./apps/user/src/enviroments.ts");
const clinic_entity_1 = __webpack_require__(/*! ../../typeorm/entities/clinic.entity */ "./apps/user/src/typeorm/entities/clinic.entity.ts");
const employee_entity_1 = __webpack_require__(/*! ../../typeorm/entities/employee.entity */ "./apps/user/src/typeorm/entities/employee.entity.ts");
const auth_controller_1 = __webpack_require__(/*! ./auth.controller */ "./apps/user/src/modules/auth/auth.controller.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/user/src/modules/auth/auth.service.ts");
const jwt_extend_service_1 = __webpack_require__(/*! ./jwt-extend.service */ "./apps/user/src/modules/auth/jwt-extend.service.ts");
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([clinic_entity_1.default, employee_entity_1.default]),
            config_1.ConfigModule.forRoot({ load: [enviroments_1.JwtConfig] }),
            jwt_1.JwtModule,
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, jwt_extend_service_1.JwtExtendService],
        exports: [jwt_extend_service_1.JwtExtendService],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ "./apps/user/src/modules/auth/auth.service.ts":
/*!****************************************************!*\
  !*** ./apps/user/src/modules/auth/auth.service.ts ***!
  \****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const utils_1 = __webpack_require__(/*! @libs/utils */ "./libs/utils/src/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const bcrypt = __webpack_require__(/*! bcrypt */ "bcrypt");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const constants_1 = __webpack_require__(/*! ../../common/constants */ "./apps/user/src/common/constants.ts");
const clinic_entity_1 = __webpack_require__(/*! ../../typeorm/entities/clinic.entity */ "./apps/user/src/typeorm/entities/clinic.entity.ts");
const employee_entity_1 = __webpack_require__(/*! ../../typeorm/entities/employee.entity */ "./apps/user/src/typeorm/entities/employee.entity.ts");
let AuthService = class AuthService {
    constructor(dataSource) {
        this.dataSource = dataSource;
    }
    async register(registerDto) {
        const { email, phone, password } = registerDto;
        const hashPassword = await bcrypt.hash(password, 5);
        const { employee } = await this.dataSource.transaction(async (manager) => {
            const findEmployee = await manager.findOne(employee_entity_1.default, {
                where: [
                    { email, role: constants_1.EUserRole.Owner },
                    { phone, role: constants_1.EUserRole.Owner },
                ],
            });
            if (findEmployee) {
                if (findEmployee.email === email && findEmployee.phone === phone) {
                    throw new common_1.HttpException(utils_1.ERegisterError.ExistEmailAndPhone, common_1.HttpStatus.BAD_REQUEST);
                }
                else if (findEmployee.email === email) {
                    throw new common_1.HttpException(utils_1.ERegisterError.ExistEmail, common_1.HttpStatus.BAD_REQUEST);
                }
                else if (findEmployee.phone === phone) {
                    throw new common_1.HttpException(utils_1.ERegisterError.ExistPhone, common_1.HttpStatus.BAD_REQUEST);
                }
            }
            const createClinic = manager.create(clinic_entity_1.default, {
                code: (0, utils_1.randomString)(5),
                level: 1,
            });
            const newClinic = await manager.save(createClinic);
            const createEmployee = manager.create(employee_entity_1.default, {
                clinicId: newClinic.id,
                email,
                phone,
                username: 'Admin',
                password: hashPassword,
                role: constants_1.EUserRole.Owner,
            });
            const newEmployee = await manager.save(createEmployee);
            return { clinic: newClinic, employee: newEmployee };
        });
        return employee;
    }
    async login(loginDto) {
        let employee;
        if (loginDto.email) {
            employee = await this.dataSource.manager.findOneBy(employee_entity_1.default, { email: loginDto.email });
        }
        else if (loginDto.username) {
            employee = await this.dataSource.manager.findOneBy(employee_entity_1.default, { username: loginDto.username });
        }
        if (!employee) {
            throw new common_1.HttpException(utils_1.ELoginError.UserDoesNotExist, common_1.HttpStatus.BAD_REQUEST);
        }
        const checkPassword = await bcrypt.compare(loginDto.password, employee.password);
        if (!checkPassword) {
            throw new common_1.HttpException(utils_1.ELoginError.WrongPassword, common_1.HttpStatus.BAD_GATEWAY);
        }
        return employee;
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_1.DataSource !== "undefined" && typeorm_1.DataSource) === "function" ? _a : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ }),

/***/ "./apps/user/src/modules/auth/jwt-extend.service.ts":
/*!**********************************************************!*\
  !*** ./apps/user/src/modules/auth/jwt-extend.service.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtExtendService = void 0;
const utils_1 = __webpack_require__(/*! @libs/utils */ "./libs/utils/src/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const enviroments_1 = __webpack_require__(/*! ../../enviroments */ "./apps/user/src/enviroments.ts");
let JwtExtendService = class JwtExtendService {
    constructor(jwtConfig, jwtService) {
        this.jwtConfig = jwtConfig;
        this.jwtService = jwtService;
    }
    createAccessToken(payload) {
        return this.jwtService.sign(payload, {
            secret: this.jwtConfig.accessKey,
            expiresIn: this.jwtConfig.accessTime,
        });
    }
    createRefreshToken(payload) {
        return this.jwtService.sign(payload, {
            secret: this.jwtConfig.refreshKey,
            expiresIn: this.jwtConfig.refreshTime,
        });
    }
    createTokenFromEmployee(employee) {
        const employeePaylod = {
            username: employee.username,
            role: employee.role,
            uid: employee.id,
            cid: employee.clinicId,
        };
        const accessToken = this.createAccessToken(employeePaylod);
        const refreshToken = this.createRefreshToken(employeePaylod);
        return { accessToken, refreshToken };
    }
    verifyAccessToken(accessToken) {
        try {
            return this.jwtService.verify(accessToken, { secret: this.jwtConfig.accessKey });
        }
        catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new common_1.HttpException(utils_1.ETokenError.Expired, common_1.HttpStatus.UNAUTHORIZED);
            }
            else if (error.name === 'JsonWebTokenError') {
                throw new common_1.HttpException(utils_1.ETokenError.Invalid, common_1.HttpStatus.UNAUTHORIZED);
            }
            throw new common_1.HttpException(utils_1.EError.Unknow, common_1.HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    verifyRefreshToken(refreshToken) {
        try {
            return this.jwtService.verify(refreshToken, { secret: this.jwtConfig.refreshKey });
        }
        catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new common_1.HttpException(utils_1.ETokenError.Expired, common_1.HttpStatus.UNAUTHORIZED);
            }
            else if (error.name === 'JsonWebTokenError') {
                throw new common_1.HttpException(utils_1.ETokenError.Invalid, common_1.HttpStatus.UNAUTHORIZED);
            }
            throw new common_1.HttpException(utils_1.EError.Unknow, common_1.HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
};
JwtExtendService = __decorate([
    __param(0, (0, common_1.Inject)(enviroments_1.JwtConfig.KEY)),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigType !== "undefined" && config_1.ConfigType) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], JwtExtendService);
exports.JwtExtendService = JwtExtendService;


/***/ }),

/***/ "./apps/user/src/modules/clinic/clinic.controller.ts":
/*!***********************************************************!*\
  !*** ./apps/user/src/modules/clinic/clinic.controller.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClinicController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const clinic_service_1 = __webpack_require__(/*! ./clinic.service */ "./apps/user/src/modules/clinic/clinic.service.ts");
const clinic_dto_1 = __webpack_require__(/*! ./clinic.dto */ "./apps/user/src/modules/clinic/clinic.dto.ts");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
let ClinicController = class ClinicController {
    constructor(clinicService) {
        this.clinicService = clinicService;
    }
    create(createClinicDto) {
        return '';
    }
    findAll() {
        return this.clinicService.findAll();
    }
    findOne(id) {
        return this.clinicService.findOne(+id);
    }
    remove(id) {
        return this.clinicService.remove(+id);
    }
};
__decorate([
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof clinic_dto_1.CreateClinicDto !== "undefined" && clinic_dto_1.CreateClinicDto) === "function" ? _b : Object]),
    __metadata("design:returntype", void 0)
], ClinicController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], ClinicController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], ClinicController.prototype, "findOne", null);
__decorate([
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], ClinicController.prototype, "remove", null);
ClinicController = __decorate([
    (0, swagger_1.ApiTags)('Clinic'),
    (0, swagger_1.ApiBearerAuth)('access-token'),
    (0, common_1.Controller)('clinic'),
    __metadata("design:paramtypes", [typeof (_a = typeof clinic_service_1.ClinicService !== "undefined" && clinic_service_1.ClinicService) === "function" ? _a : Object])
], ClinicController);
exports.ClinicController = ClinicController;


/***/ }),

/***/ "./apps/user/src/modules/clinic/clinic.dto.ts":
/*!****************************************************!*\
  !*** ./apps/user/src/modules/clinic/clinic.dto.ts ***!
  \****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateClinicDto = exports.CreateClinicDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class CreateClinicDto {
}
__decorate([
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], CreateClinicDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.Length)(10, 10),
    __metadata("design:type", String)
], CreateClinicDto.prototype, "phone", void 0);
__decorate([
    (0, class_validator_1.Length)(6),
    __metadata("design:type", String)
], CreateClinicDto.prototype, "password", void 0);
exports.CreateClinicDto = CreateClinicDto;
class UpdateClinicDto extends (0, swagger_1.PartialType)(CreateClinicDto) {
}
exports.UpdateClinicDto = UpdateClinicDto;


/***/ }),

/***/ "./apps/user/src/modules/clinic/clinic.module.ts":
/*!*******************************************************!*\
  !*** ./apps/user/src/modules/clinic/clinic.module.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClinicModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const clinic_service_1 = __webpack_require__(/*! ./clinic.service */ "./apps/user/src/modules/clinic/clinic.service.ts");
const clinic_controller_1 = __webpack_require__(/*! ./clinic.controller */ "./apps/user/src/modules/clinic/clinic.controller.ts");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const clinic_entity_1 = __webpack_require__(/*! ../../typeorm/entities/clinic.entity */ "./apps/user/src/typeorm/entities/clinic.entity.ts");
let ClinicModule = class ClinicModule {
};
ClinicModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([clinic_entity_1.default])],
        controllers: [clinic_controller_1.ClinicController],
        providers: [clinic_service_1.ClinicService],
        exports: [clinic_service_1.ClinicService],
    })
], ClinicModule);
exports.ClinicModule = ClinicModule;


/***/ }),

/***/ "./apps/user/src/modules/clinic/clinic.service.ts":
/*!********************************************************!*\
  !*** ./apps/user/src/modules/clinic/clinic.service.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClinicService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const clinic_entity_1 = __webpack_require__(/*! ../../typeorm/entities/clinic.entity */ "./apps/user/src/typeorm/entities/clinic.entity.ts");
let ClinicService = class ClinicService {
    constructor(clinicRepository, dataSource) {
        this.clinicRepository = clinicRepository;
        this.dataSource = dataSource;
    }
    findAll() {
        return `This action returns all clinic`;
    }
    findOne(id) {
        return `This action returns a #${id} clinic`;
    }
    update(id) {
        return `This action updates a #${id} clinic`;
    }
    remove(id) {
        return `This action removes a #${id} clinic`;
    }
};
ClinicService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(clinic_entity_1.default)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.DataSource !== "undefined" && typeorm_2.DataSource) === "function" ? _b : Object])
], ClinicService);
exports.ClinicService = ClinicService;


/***/ }),

/***/ "./apps/user/src/modules/employee/dto/create-employee.dto.ts":
/*!*******************************************************************!*\
  !*** ./apps/user/src/modules/employee/dto/create-employee.dto.ts ***!
  \*******************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateEmployeeDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
class CreateEmployeeDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'employee1' }),
    __metadata("design:type", String)
], CreateEmployeeDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    __metadata("design:type", String)
], CreateEmployeeDto.prototype, "password", void 0);
exports.CreateEmployeeDto = CreateEmployeeDto;


/***/ }),

/***/ "./apps/user/src/modules/employee/dto/update-employee.dto.ts":
/*!*******************************************************************!*\
  !*** ./apps/user/src/modules/employee/dto/update-employee.dto.ts ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateEmployeeDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const create_employee_dto_1 = __webpack_require__(/*! ./create-employee.dto */ "./apps/user/src/modules/employee/dto/create-employee.dto.ts");
class UpdateEmployeeDto extends (0, swagger_1.PartialType)(create_employee_dto_1.CreateEmployeeDto) {
}
exports.UpdateEmployeeDto = UpdateEmployeeDto;


/***/ }),

/***/ "./apps/user/src/modules/employee/employee.controller.ts":
/*!***************************************************************!*\
  !*** ./apps/user/src/modules/employee/employee.controller.ts ***!
  \***************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmployeeController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const constants_1 = __webpack_require__(/*! ../../common/constants */ "./apps/user/src/common/constants.ts");
const user_roles_guard_1 = __webpack_require__(/*! ../../guards/user-roles.guard */ "./apps/user/src/guards/user-roles.guard.ts");
const create_employee_dto_1 = __webpack_require__(/*! ./dto/create-employee.dto */ "./apps/user/src/modules/employee/dto/create-employee.dto.ts");
const update_employee_dto_1 = __webpack_require__(/*! ./dto/update-employee.dto */ "./apps/user/src/modules/employee/dto/update-employee.dto.ts");
const employee_service_1 = __webpack_require__(/*! ./employee.service */ "./apps/user/src/modules/employee/employee.service.ts");
let EmployeeController = class EmployeeController {
    constructor(employeeService) {
        this.employeeService = employeeService;
    }
    async create(createEmployeeDto, request) {
        createEmployeeDto.clinicId = request.tokenPayload.cid;
        return this.employeeService.create(createEmployeeDto);
    }
    findAll() {
        return this.employeeService.findAll();
    }
    findOne(id) {
        return this.employeeService.findOne(+id);
    }
    update(id, updateEmployeeDto) {
        return this.employeeService.update(+id, updateEmployeeDto);
    }
    remove(id) {
        return this.employeeService.remove(+id);
    }
};
__decorate([
    (0, common_1.Post)(),
    (0, user_roles_guard_1.UserRoles)('Owner', 'Admin'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof create_employee_dto_1.CreateEmployeeDto !== "undefined" && create_employee_dto_1.CreateEmployeeDto) === "function" ? _b : Object, typeof (_c = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _c : Object]),
    __metadata("design:returntype", Promise)
], EmployeeController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "findOne", null);
__decorate([
    (0, common_1.Patch)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_d = typeof update_employee_dto_1.UpdateEmployeeDto !== "undefined" && update_employee_dto_1.UpdateEmployeeDto) === "function" ? _d : Object]),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "remove", null);
EmployeeController = __decorate([
    (0, swagger_1.ApiTags)('Employee'),
    (0, swagger_1.ApiBearerAuth)('access-token'),
    (0, common_1.Controller)('employee'),
    __metadata("design:paramtypes", [typeof (_a = typeof employee_service_1.EmployeeService !== "undefined" && employee_service_1.EmployeeService) === "function" ? _a : Object])
], EmployeeController);
exports.EmployeeController = EmployeeController;


/***/ }),

/***/ "./apps/user/src/modules/employee/employee.module.ts":
/*!***********************************************************!*\
  !*** ./apps/user/src/modules/employee/employee.module.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmployeeModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const employee_service_1 = __webpack_require__(/*! ./employee.service */ "./apps/user/src/modules/employee/employee.service.ts");
const employee_controller_1 = __webpack_require__(/*! ./employee.controller */ "./apps/user/src/modules/employee/employee.controller.ts");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const employee_entity_1 = __webpack_require__(/*! ../../typeorm/entities/employee.entity */ "./apps/user/src/typeorm/entities/employee.entity.ts");
let EmployeeModule = class EmployeeModule {
};
EmployeeModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([employee_entity_1.default])],
        controllers: [employee_controller_1.EmployeeController],
        providers: [employee_service_1.EmployeeService],
    })
], EmployeeModule);
exports.EmployeeModule = EmployeeModule;


/***/ }),

/***/ "./apps/user/src/modules/employee/employee.service.ts":
/*!************************************************************!*\
  !*** ./apps/user/src/modules/employee/employee.service.ts ***!
  \************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmployeeService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const bcrypt = __webpack_require__(/*! bcrypt */ "bcrypt");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const employee_entity_1 = __webpack_require__(/*! ../../typeorm/entities/employee.entity */ "./apps/user/src/typeorm/entities/employee.entity.ts");
const utils_1 = __webpack_require__(/*! @libs/utils */ "./libs/utils/src/index.ts");
let EmployeeService = class EmployeeService {
    constructor(dataSource) {
        this.dataSource = dataSource;
    }
    async create(createEmployeeDto) {
        const { username, password, clinicId } = createEmployeeDto;
        const hashPassword = await bcrypt.hash(password, 5);
        const employee = await this.dataSource.transaction(async (manager) => {
            const findEmployee = await manager.findOne(employee_entity_1.default, { where: { username, clinicId } });
            if (findEmployee) {
                throw new common_1.HttpException(utils_1.EEmployeeError.UsernameExists, common_1.HttpStatus.BAD_GATEWAY);
            }
            const createEmployee = manager.create(employee_entity_1.default, {
                clinicId,
                username,
                password: hashPassword,
            });
            const newEmployee = await manager.save(createEmployee);
            return newEmployee;
        });
        return employee;
    }
    findAll() {
        return `This action returns all employee`;
    }
    findOne(id) {
        return `This action returns a #${id} employee`;
    }
    update(id, updateEmployeeDto) {
        return `This action updates a #${id} employee`;
    }
    remove(id) {
        return `This action removes a #${id} employee`;
    }
};
EmployeeService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_1.DataSource !== "undefined" && typeorm_1.DataSource) === "function" ? _a : Object])
], EmployeeService);
exports.EmployeeService = EmployeeService;


/***/ }),

/***/ "./apps/user/src/modules/medicine/dto/create-medicine.dto.ts":
/*!*******************************************************************!*\
  !*** ./apps/user/src/modules/medicine/dto/create-medicine.dto.ts ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateMedicineDto = void 0;
class CreateMedicineDto {
}
exports.CreateMedicineDto = CreateMedicineDto;


/***/ }),

/***/ "./apps/user/src/modules/medicine/dto/update-medicine.dto.ts":
/*!*******************************************************************!*\
  !*** ./apps/user/src/modules/medicine/dto/update-medicine.dto.ts ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateMedicineDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const create_medicine_dto_1 = __webpack_require__(/*! ./create-medicine.dto */ "./apps/user/src/modules/medicine/dto/create-medicine.dto.ts");
class UpdateMedicineDto extends (0, swagger_1.PartialType)(create_medicine_dto_1.CreateMedicineDto) {
}
exports.UpdateMedicineDto = UpdateMedicineDto;


/***/ }),

/***/ "./apps/user/src/modules/medicine/medicine.controller.ts":
/*!***************************************************************!*\
  !*** ./apps/user/src/modules/medicine/medicine.controller.ts ***!
  \***************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MedicineController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const create_medicine_dto_1 = __webpack_require__(/*! ./dto/create-medicine.dto */ "./apps/user/src/modules/medicine/dto/create-medicine.dto.ts");
const update_medicine_dto_1 = __webpack_require__(/*! ./dto/update-medicine.dto */ "./apps/user/src/modules/medicine/dto/update-medicine.dto.ts");
const medicine_service_1 = __webpack_require__(/*! ./medicine.service */ "./apps/user/src/modules/medicine/medicine.service.ts");
let MedicineController = class MedicineController {
    constructor(medicineService) {
        this.medicineService = medicineService;
    }
    create(createMedicineDto) {
        return this.medicineService.create(createMedicineDto);
    }
    findAll() {
        return this.medicineService.findAll();
    }
    findOne(id) {
        return this.medicineService.findOne(+id);
    }
    update(id, updateMedicineDto) {
        return this.medicineService.update(+id, updateMedicineDto);
    }
    remove(id) {
        return this.medicineService.remove(+id);
    }
};
__decorate([
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof create_medicine_dto_1.CreateMedicineDto !== "undefined" && create_medicine_dto_1.CreateMedicineDto) === "function" ? _b : Object]),
    __metadata("design:returntype", void 0)
], MedicineController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], MedicineController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], MedicineController.prototype, "findOne", null);
__decorate([
    (0, common_1.Patch)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_c = typeof update_medicine_dto_1.UpdateMedicineDto !== "undefined" && update_medicine_dto_1.UpdateMedicineDto) === "function" ? _c : Object]),
    __metadata("design:returntype", void 0)
], MedicineController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], MedicineController.prototype, "remove", null);
MedicineController = __decorate([
    (0, swagger_1.ApiTags)('Medicine'),
    (0, swagger_1.ApiBearerAuth)('access-token'),
    (0, common_1.Controller)('medicine'),
    __metadata("design:paramtypes", [typeof (_a = typeof medicine_service_1.MedicineService !== "undefined" && medicine_service_1.MedicineService) === "function" ? _a : Object])
], MedicineController);
exports.MedicineController = MedicineController;


/***/ }),

/***/ "./apps/user/src/modules/medicine/medicine.module.ts":
/*!***********************************************************!*\
  !*** ./apps/user/src/modules/medicine/medicine.module.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MedicineModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const medicine_service_1 = __webpack_require__(/*! ./medicine.service */ "./apps/user/src/modules/medicine/medicine.service.ts");
const medicine_controller_1 = __webpack_require__(/*! ./medicine.controller */ "./apps/user/src/modules/medicine/medicine.controller.ts");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const medicine_entity_1 = __webpack_require__(/*! ../../typeorm/entities/medicine.entity */ "./apps/user/src/typeorm/entities/medicine.entity.ts");
let MedicineModule = class MedicineModule {
};
MedicineModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([medicine_entity_1.default])],
        controllers: [medicine_controller_1.MedicineController],
        providers: [medicine_service_1.MedicineService],
    })
], MedicineModule);
exports.MedicineModule = MedicineModule;


/***/ }),

/***/ "./apps/user/src/modules/medicine/medicine.service.ts":
/*!************************************************************!*\
  !*** ./apps/user/src/modules/medicine/medicine.service.ts ***!
  \************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MedicineService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let MedicineService = class MedicineService {
    create(createMedicineDto) {
        return 'This action adds a new medicine';
    }
    findAll() {
        return `This action returns all medicine`;
    }
    findOne(id) {
        return `This action returns a #${id} medicine`;
    }
    update(id, updateMedicineDto) {
        return `This action updates a #${id} medicine`;
    }
    remove(id) {
        return `This action removes a #${id} medicine`;
    }
};
MedicineService = __decorate([
    (0, common_1.Injectable)()
], MedicineService);
exports.MedicineService = MedicineService;


/***/ }),

/***/ "./apps/user/src/typeorm/common/base.entity.ts":
/*!*****************************************************!*\
  !*** ./apps/user/src/typeorm/common/base.entity.ts ***!
  \*****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.BaseEntity = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
class BaseEntity {
}
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)({ name: 'id' }),
    __metadata("design:type", Number)
], BaseEntity.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'created_by', nullable: true }),
    __metadata("design:type", Number)
], BaseEntity.prototype, "createdBy", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'updated_by', nullable: true }),
    __metadata("design:type", Number)
], BaseEntity.prototype, "updatedBy", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'created_at' }),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], BaseEntity.prototype, "createdAt", void 0);
__decorate([
    (0, typeorm_1.UpdateDateColumn)({ name: 'updated_at' }),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], BaseEntity.prototype, "updatedAt", void 0);
__decorate([
    (0, typeorm_1.DeleteDateColumn)({ name: 'deleted_at' }),
    __metadata("design:type", typeof (_c = typeof Date !== "undefined" && Date) === "function" ? _c : Object)
], BaseEntity.prototype, "deletedAt", void 0);
__decorate([
    (0, typeorm_1.VersionColumn)(),
    __metadata("design:type", Number)
], BaseEntity.prototype, "version", void 0);
exports.BaseEntity = BaseEntity;


/***/ }),

/***/ "./apps/user/src/typeorm/entities/clinic.entity.ts":
/*!*********************************************************!*\
  !*** ./apps/user/src/typeorm/entities/clinic.entity.ts ***!
  \*********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../common/base.entity */ "./apps/user/src/typeorm/common/base.entity.ts");
let ClinicEntity = class ClinicEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ type: 'tinyint', default: 1 }),
    __metadata("design:type", Number)
], ClinicEntity.prototype, "level", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'code', nullable: true }),
    __metadata("design:type", String)
], ClinicEntity.prototype, "code", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], ClinicEntity.prototype, "clinicName", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], ClinicEntity.prototype, "address", void 0);
ClinicEntity = __decorate([
    (0, typeorm_1.Entity)('clinic')
], ClinicEntity);
exports["default"] = ClinicEntity;


/***/ }),

/***/ "./apps/user/src/typeorm/entities/employee.entity.ts":
/*!***********************************************************!*\
  !*** ./apps/user/src/typeorm/entities/employee.entity.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const constants_1 = __webpack_require__(/*! ../../common/constants */ "./apps/user/src/common/constants.ts");
const base_entity_1 = __webpack_require__(/*! ../common/base.entity */ "./apps/user/src/typeorm/common/base.entity.ts");
let EmployeeEntity = class EmployeeEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ name: 'clinic_id' }),
    __metadata("design:type", Number)
], EmployeeEntity.prototype, "clinicId", void 0);
__decorate([
    (0, typeorm_1.Column)({ unique: true, nullable: true }),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "email", void 0);
__decorate([
    (0, typeorm_1.Column)({ unique: true, nullable: true }),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "phone", void 0);
__decorate([
    (0, typeorm_1.Column)(),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "username", void 0);
__decorate([
    (0, typeorm_1.Column)(),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "password", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "address", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'enum', enum: constants_1.EUserRole, default: constants_1.EUserRole.User }),
    __metadata("design:type", typeof (_a = typeof constants_1.EUserRole !== "undefined" && constants_1.EUserRole) === "function" ? _a : Object)
], EmployeeEntity.prototype, "role", void 0);
EmployeeEntity = __decorate([
    (0, typeorm_1.Entity)('employee'),
    (0, typeorm_1.Index)(['clinicId', 'email']),
    (0, typeorm_1.Index)(['clinicId', 'username'])
], EmployeeEntity);
exports["default"] = EmployeeEntity;


/***/ }),

/***/ "./apps/user/src/typeorm/entities/medicine.entity.ts":
/*!***********************************************************!*\
  !*** ./apps/user/src/typeorm/entities/medicine.entity.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../common/base.entity */ "./apps/user/src/typeorm/common/base.entity.ts");
let MedicineEntity = class MedicineEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ name: 'clinic_id' }),
    __metadata("design:type", Number)
], MedicineEntity.prototype, "clinicId", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'brand_name', nullable: true }),
    __metadata("design:type", String)
], MedicineEntity.prototype, "brandName", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'chemical_name', nullable: true }),
    __metadata("design:type", String)
], MedicineEntity.prototype, "chemicalName", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'calculation_unit', nullable: true }),
    __metadata("design:type", String)
], MedicineEntity.prototype, "calculationUnit", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'image', nullable: true }),
    __metadata("design:type", String)
], MedicineEntity.prototype, "image", void 0);
MedicineEntity = __decorate([
    (0, typeorm_1.Entity)('medicine'),
    (0, typeorm_1.Index)(['clinicId', 'id'], { unique: true })
], MedicineEntity);
exports["default"] = MedicineEntity;


/***/ }),

/***/ "./libs/utils/src/exception-filters/exception.enum.ts":
/*!************************************************************!*\
  !*** ./libs/utils/src/exception-filters/exception.enum.ts ***!
  \************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EEmployeeError = exports.ETokenError = exports.ELoginError = exports.ERegisterError = exports.EValidateError = exports.EError = void 0;
var EError;
(function (EError) {
    EError["Unknow"] = "A00.UNKNOW";
})(EError = exports.EError || (exports.EError = {}));
var EValidateError;
(function (EValidateError) {
    EValidateError["Faild"] = "V00.VALIDATE_FAIL";
})(EValidateError = exports.EValidateError || (exports.EValidateError = {}));
var ERegisterError;
(function (ERegisterError) {
    ERegisterError["ExistEmailAndPhone"] = "R01.EMAIL_AND_PHONE_EXISTS";
    ERegisterError["ExistEmail"] = "R02.EMAIL_EXISTS";
    ERegisterError["ExistPhone"] = "R03.PHONE_EXISTS";
})(ERegisterError = exports.ERegisterError || (exports.ERegisterError = {}));
var ELoginError;
(function (ELoginError) {
    ELoginError["UserDoesNotExist"] = "L01.USER_DOES_NOT_EXIST";
    ELoginError["WrongPassword"] = "L02.WRONG_PASSWORD";
})(ELoginError = exports.ELoginError || (exports.ELoginError = {}));
var ETokenError;
(function (ETokenError) {
    ETokenError["Expired"] = "T01.EXPIRED";
    ETokenError["Invalid"] = "T02.INVALID";
})(ETokenError = exports.ETokenError || (exports.ETokenError = {}));
var EEmployeeError;
(function (EEmployeeError) {
    EEmployeeError["UsernameExists"] = "E01.Username_Exists";
})(EEmployeeError = exports.EEmployeeError || (exports.EEmployeeError = {}));


/***/ }),

/***/ "./libs/utils/src/exception-filters/http-exception.filter.ts":
/*!*******************************************************************!*\
  !*** ./libs/utils/src/exception-filters/http-exception.filter.ts ***!
  \*******************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpExceptionFilter = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let HttpExceptionFilter = class HttpExceptionFilter {
    catch(exception, host) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();
        const httpStatus = exception.getStatus();
        response.status(httpStatus).json({
            httpStatus,
            message: exception.getResponse(),
            timestamp: new Date().toISOString(),
            path: request.url,
        });
    }
};
HttpExceptionFilter = __decorate([
    (0, common_1.Catch)(common_1.HttpException)
], HttpExceptionFilter);
exports.HttpExceptionFilter = HttpExceptionFilter;


/***/ }),

/***/ "./libs/utils/src/exception-filters/unknow-exception.filter.ts":
/*!*********************************************************************!*\
  !*** ./libs/utils/src/exception-filters/unknow-exception.filter.ts ***!
  \*********************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UnknowExceptionFilter = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let UnknowExceptionFilter = class UnknowExceptionFilter {
    catch(exception, host) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();
        const httpStatus = common_1.HttpStatus.INTERNAL_SERVER_ERROR;
        response.status(httpStatus).json({
            httpStatus,
            message: exception.message,
            path: request.url,
            timestamp: new Date().toISOString(),
        });
    }
};
UnknowExceptionFilter = __decorate([
    (0, common_1.Catch)(Error)
], UnknowExceptionFilter);
exports.UnknowExceptionFilter = UnknowExceptionFilter;


/***/ }),

/***/ "./libs/utils/src/exception-filters/validation-exception.filter.ts":
/*!*************************************************************************!*\
  !*** ./libs/utils/src/exception-filters/validation-exception.filter.ts ***!
  \*************************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidationExceptionFilter = exports.ValidationException = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const exception_enum_1 = __webpack_require__(/*! ./exception.enum */ "./libs/utils/src/exception-filters/exception.enum.ts");
class ValidationException extends Error {
    constructor(validationErrors = []) {
        super(exception_enum_1.EValidateError.Faild);
        this.errors = validationErrors;
    }
    getMessage() {
        return this.message;
    }
    getErrors() {
        return this.errors;
    }
}
exports.ValidationException = ValidationException;
let ValidationExceptionFilter = class ValidationExceptionFilter {
    catch(exception, host) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();
        const httpStatus = common_1.HttpStatus.BAD_REQUEST;
        const message = exception.getMessage();
        const errors = exception.getErrors();
        response.status(httpStatus).json({
            httpStatus,
            message,
            errors,
            path: request.url,
            timestamp: new Date().toISOString(),
        });
    }
};
ValidationExceptionFilter = __decorate([
    (0, common_1.Catch)(ValidationException)
], ValidationExceptionFilter);
exports.ValidationExceptionFilter = ValidationExceptionFilter;


/***/ }),

/***/ "./libs/utils/src/helpers/string.helper.ts":
/*!*************************************************!*\
  !*** ./libs/utils/src/helpers/string.helper.ts ***!
  \*************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.formatNumber = exports.convertViToEn = exports.decript = exports.encript = exports.randomString = exports.randomId = void 0;
const _CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const generateCharset = (privateKey = 'Abc123', charset = _CHARSET) => {
    let tempString = charset;
    let result = '';
    for (let i = 0; i < _CHARSET.length; i += 1) {
        const kIndex = i % privateKey.length;
        const charCode = privateKey.charCodeAt(kIndex);
        const tIndex = charCode % tempString.length;
        result = tempString[tIndex] + result;
        tempString = tempString.substring(tIndex + 1) + tempString.substring(0, tIndex);
    }
    return result;
};
const randomId = () => {
    const now = new Date().getTime().toString(36);
    return now;
};
exports.randomId = randomId;
const randomString = (length = 10, characters = _CHARSET) => {
    let result = '';
    for (let i = 0; i < length; i += 1) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
};
exports.randomString = randomString;
const encript = (rootString, privateKey) => {
    const hash = generateCharset(privateKey);
    let result = '';
    for (let i = 0; i < rootString.length; i += 1) {
        const index = _CHARSET.indexOf(rootString[i]);
        if (index === -1) {
            result += rootString[i];
        }
        else {
            result += hash[index];
        }
    }
    return result;
};
exports.encript = encript;
const decript = (cipherText, privateKey) => {
    const hash = generateCharset(privateKey);
    let result = '';
    for (let i = 0; i < cipherText.length; i += 1) {
        const index = hash.indexOf(cipherText[i]);
        if (index === -1) {
            result += cipherText[i];
        }
        else {
            result += _CHARSET[index];
        }
    }
    return result;
};
exports.decript = decript;
const convertViToEn = (root) => root
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D');
exports.convertViToEn = convertViToEn;
const formatNumber = (number, fixed = 3, part = 3, sec = ',', dec = '.') => {
    const regex = '\\d(?=(\\d{' + part + '})+' + (fixed > 0 ? '\\D' : '$') + ')';
    return number
        .toFixed(fixed)
        .replace('.', dec)
        .replace(new RegExp(regex, 'g'), '$&' + sec);
};
exports.formatNumber = formatNumber;


/***/ }),

/***/ "./libs/utils/src/index.ts":
/*!*********************************!*\
  !*** ./libs/utils/src/index.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./helpers/string.helper */ "./libs/utils/src/helpers/string.helper.ts"), exports);
__exportStar(__webpack_require__(/*! ./exception-filters/exception.enum */ "./libs/utils/src/exception-filters/exception.enum.ts"), exports);
__exportStar(__webpack_require__(/*! ./exception-filters/http-exception.filter */ "./libs/utils/src/exception-filters/http-exception.filter.ts"), exports);
__exportStar(__webpack_require__(/*! ./exception-filters/unknow-exception.filter */ "./libs/utils/src/exception-filters/unknow-exception.filter.ts"), exports);
__exportStar(__webpack_require__(/*! ./exception-filters/validation-exception.filter */ "./libs/utils/src/exception-filters/validation-exception.filter.ts"), exports);


/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/swagger":
/*!**********************************!*\
  !*** external "@nestjs/swagger" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),

/***/ "@nestjs/typeorm":
/*!**********************************!*\
  !*** external "@nestjs/typeorm" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("@nestjs/typeorm");

/***/ }),

/***/ "bcrypt":
/*!*************************!*\
  !*** external "bcrypt" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),

/***/ "class-validator":
/*!**********************************!*\
  !*** external "class-validator" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),

/***/ "express":
/*!**************************!*\
  !*** external "express" ***!
  \**************************/
/***/ ((module) => {

module.exports = require("express");

/***/ }),

/***/ "express-rate-limit":
/*!*************************************!*\
  !*** external "express-rate-limit" ***!
  \*************************************/
/***/ ((module) => {

module.exports = require("express-rate-limit");

/***/ }),

/***/ "helmet":
/*!*************************!*\
  !*** external "helmet" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("helmet");

/***/ }),

/***/ "request-ip":
/*!*****************************!*\
  !*** external "request-ip" ***!
  \*****************************/
/***/ ((module) => {

module.exports = require("request-ip");

/***/ }),

/***/ "rxjs":
/*!***********************!*\
  !*** external "rxjs" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("rxjs");

/***/ }),

/***/ "rxjs/operators":
/*!*********************************!*\
  !*** external "rxjs/operators" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("rxjs/operators");

/***/ }),

/***/ "typeorm":
/*!**************************!*\
  !*** external "typeorm" ***!
  \**************************/
/***/ ((module) => {

module.exports = require("typeorm");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!*******************************!*\
  !*** ./apps/user/src/main.ts ***!
  \*******************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const utils_1 = __webpack_require__(/*! @libs/utils */ "./libs/utils/src/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const express_rate_limit_1 = __webpack_require__(/*! express-rate-limit */ "express-rate-limit");
const helmet_1 = __webpack_require__(/*! helmet */ "helmet");
const requestIp = __webpack_require__(/*! request-ip */ "request-ip");
const app_module_1 = __webpack_require__(/*! ./app.module */ "./apps/user/src/app.module.ts");
const swagger_1 = __webpack_require__(/*! ./common/swagger */ "./apps/user/src/common/swagger.ts");
const user_roles_guard_1 = __webpack_require__(/*! ./guards/user-roles.guard */ "./apps/user/src/guards/user-roles.guard.ts");
const access_log_interceptor_1 = __webpack_require__(/*! ./interceptor/access-log.interceptor */ "./apps/user/src/interceptor/access-log.interceptor.ts");
const timeout_interceptor_1 = __webpack_require__(/*! ./interceptor/timeout.interceptor */ "./apps/user/src/interceptor/timeout.interceptor.ts");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    const configService = app.get(config_1.ConfigService);
    const PORT = configService.get('SERVER_PORT');
    app.use((0, helmet_1.default)());
    app.use((0, express_rate_limit_1.default)({
        windowMs: 15 * 60 * 1000,
        max: 100,
    }));
    app.enableCors();
    app.use(requestIp.mw());
    app.useGlobalInterceptors(new access_log_interceptor_1.AccessLogInterceptor(), new timeout_interceptor_1.TimeoutInterceptor());
    app.useGlobalFilters(new utils_1.UnknowExceptionFilter(), new utils_1.HttpExceptionFilter(), new utils_1.ValidationExceptionFilter());
    app.useGlobalGuards(new user_roles_guard_1.UserRolesGuard(app.get(core_1.Reflector)));
    app.useGlobalPipes(new common_1.ValidationPipe({
        validationError: { target: false, value: true },
        skipMissingProperties: true,
        exceptionFactory: (errors = []) => new utils_1.ValidationException(errors),
    }));
    if (configService.get('NODE_ENV') !== 'production') {
        (0, swagger_1.setupSwagger)(app);
    }
    await app.listen(PORT);
}
bootstrap();

})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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cHBzL3VzZXIvc3JjL2FwcC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL2NvbW1vbi9jb25zdGFudHMudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9jb21tb24vc3dhZ2dlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL2Vudmlyb21lbnRzLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvZ3VhcmRzL3VzZXItcm9sZXMuZ3VhcmQudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9pbnRlcmNlcHRvci9hY2Nlc3MtbG9nLmludGVyY2VwdG9yLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvaW50ZXJjZXB0b3IvdGltZW91dC5pbnRlcmNlcHRvci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL21pZGRsZXdhcmVzL2xvZ2dlci5taWRkbGV3YXJlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbWlkZGxld2FyZXMvdmFsaWRhdGUtYWNjZXNzLXRva2VuLm1pZGRsZXdhcmUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbW9kdWxlcy9hdXRoL2F1dGguZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbW9kdWxlcy9hdXRoL2F1dGguc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL21vZHVsZXMvY2xpbmljL2NsaW5pYy5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9tb2R1bGVzL2VtcGxveWVlL2R0by9jcmVhdGUtZW1wbG95ZWUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbW9kdWxlcy9lbXBsb3llZS9kdG8vdXBkYXRlLWVtcGxveWVlLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvbW9kdWxlcy9tZWRpY2luZS9kdG8vY3JlYXRlLW1lZGljaW5lLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL21vZHVsZXMvbWVkaWNpbmUvZHRvL3VwZGF0ZS1tZWRpY2luZS5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL3VzZXIvc3JjL3R5cGVvcm0vY29tbW9uL2Jhc2UuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvdXNlci9zcmMvdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy90eXBlb3JtL2VudGl0aWVzL21lZGljaW5lLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9saWJzL3V0aWxzL3NyYy9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9saWJzL3V0aWxzL3NyYy9leGNlcHRpb24tZmlsdGVycy9odHRwLWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vbGlicy91dGlscy9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvdW5rbm93LWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vbGlicy91dGlscy9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvdmFsaWRhdGlvbi1leGNlcHRpb24uZmlsdGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2xpYnMvdXRpbHMvc3JjL2hlbHBlcnMvc3RyaW5nLmhlbHBlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9saWJzL3V0aWxzL3NyYy9pbmRleC50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbW1vblwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29uZmlnXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb3JlXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9qd3RcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL3N3YWdnZXJcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL3R5cGVvcm1cIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJiY3J5cHRcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJjbGFzcy12YWxpZGF0b3JcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJleHByZXNzXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiZXhwcmVzcy1yYXRlLWxpbWl0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiaGVsbWV0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwicmVxdWVzdC1pcFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInJ4anNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJyeGpzL29wZXJhdG9yc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInR5cGVvcm1cIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy91c2VyL3NyYy9tYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE1pZGRsZXdhcmVDb25zdW1lciwgTW9kdWxlLCBOZXN0TW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUsIENvbmZpZ1R5cGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IE15c3FsQ29uZmlnIH0gZnJvbSAnLi9lbnZpcm9tZW50cydcbmltcG9ydCB7IExvZ2dlck1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL2xvZ2dlci5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgVmFsaWRhdGVBY2Nlc3NUb2tlbk1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL3ZhbGlkYXRlLWFjY2Vzcy10b2tlbi5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlJ1xuaW1wb3J0IHsgQ2xpbmljTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlJ1xuaW1wb3J0IHsgRW1wbG95ZWVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlJ1xuaW1wb3J0IHsgTWVkaWNpbmVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1xuXHRcdENvbmZpZ01vZHVsZS5mb3JSb290KHtcblx0XHRcdGVudkZpbGVQYXRoOiBbJy5lbnYnLCBgLmVudi4ke3Byb2Nlc3MuZW52Lk5PREVfRU5WfWBdLFxuXHRcdFx0aXNHbG9iYWw6IHRydWUsXG5cdFx0fSksXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JSb290QXN5bmMoe1xuXHRcdFx0aW1wb3J0czogW0NvbmZpZ01vZHVsZS5mb3JSb290KHsgbG9hZDogW015c3FsQ29uZmlnXSB9KV0sXG5cdFx0XHRpbmplY3Q6IFtNeXNxbENvbmZpZy5LRVldLFxuXHRcdFx0dXNlRmFjdG9yeTogKG15c3FsQ29uZmlnOiBDb25maWdUeXBlPHR5cGVvZiBNeXNxbENvbmZpZz4pID0+IG15c3FsQ29uZmlnLFxuXHRcdFx0Ly8gaW5qZWN0OiBbQ29uZmlnU2VydmljZV0sXG5cdFx0XHQvLyB1c2VGYWN0b3J5OiAoY29uZmlnU2VydmljZTogQ29uZmlnU2VydmljZSkgPT4gY29uZmlnU2VydmljZS5nZXQoJ215c3FsJyksXG5cdFx0fSksXG5cdFx0QXV0aE1vZHVsZSxcblx0XHRDbGluaWNNb2R1bGUsXG5cdFx0RW1wbG95ZWVNb2R1bGUsXG5cdFx0TWVkaWNpbmVNb2R1bGUsXG5cdF0sXG59KVxuZXhwb3J0IGNsYXNzIEFwcE1vZHVsZSBpbXBsZW1lbnRzIE5lc3RNb2R1bGUge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2UpIHsgfVxuXHRjb25maWd1cmUoY29uc3VtZXI6IE1pZGRsZXdhcmVDb25zdW1lcikge1xuXHRcdGNvbnN1bWVyLmFwcGx5KExvZ2dlck1pZGRsZXdhcmUpLmZvclJvdXRlcygnKicpXG5cblx0XHRjb25zdW1lci5hcHBseShWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSlcblx0XHRcdC5leGNsdWRlKCdhdXRoLyguKiknKVxuXHRcdFx0LmZvclJvdXRlcygnKicpXG5cdH1cbn1cbiIsImltcG9ydCB7IFZhbGlkYXRvckNvbnN0cmFpbnQsIFZhbGlkYXRvckNvbnN0cmFpbnRJbnRlcmZhY2UsIFZhbGlkYXRpb25Bcmd1bWVudHMgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbkBWYWxpZGF0b3JDb25zdHJhaW50KHsgbmFtZTogJ2lzUGhvbmUnLCBhc3luYzogZmFsc2UgfSlcbmV4cG9ydCBjbGFzcyBJc1Bob25lIGltcGxlbWVudHMgVmFsaWRhdG9yQ29uc3RyYWludEludGVyZmFjZSB7XG5cdHZhbGlkYXRlKHRleHQ6IHN0cmluZywgYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAvKCgwOXwwM3wwN3wwOHwwNSkrKFswLTldezh9KVxcYikvZy50ZXN0KHRleHQpXG5cdH1cblxuXHRkZWZhdWx0TWVzc2FnZShhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0cmV0dXJuICckcHJvcGVydHkgbXVzdCBiZSByZWFsIG51bWJlcnBob25lICEnXG5cdH1cbn1cblxuQFZhbGlkYXRvckNvbnN0cmFpbnQoeyBuYW1lOiAnaXNHbWFpbCcsIGFzeW5jOiBmYWxzZSB9KVxuZXhwb3J0IGNsYXNzIElzR21haWwgaW1wbGVtZW50cyBWYWxpZGF0b3JDb25zdHJhaW50SW50ZXJmYWNlIHtcblx0dmFsaWRhdGUodGV4dDogc3RyaW5nLCBhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0cmV0dXJuIC9eKFthLXpBLVowLTldfFxcLnwtfF8pKyhAZ21haWwuY29tKSQvLnRlc3QodGV4dClcblx0fVxuXG5cdGRlZmF1bHRNZXNzYWdlKGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRyZXR1cm4gJyRwcm9wZXJ0eSBtdXN0IGJlIGEgZ21haWwgYWRkcmVzcyAhJ1xuXHR9XG59XG4iLCJpbXBvcnQgeyBSZXF1ZXN0IH0gZnJvbSAnZXhwcmVzcydcblxuZXhwb3J0IGVudW0gRVVzZXJSb2xlIHtcblx0T3duZXIgPSAnT3duZXInLFxuXHRBZG1pbiA9ICdBZG1pbicsXG5cdFVzZXIgPSAnVXNlcicsXG59XG5cbmV4cG9ydCB0eXBlIFRVc2VyUm9sZSA9IGtleW9mIHR5cGVvZiBFVXNlclJvbGVcblxuZXhwb3J0IGludGVyZmFjZSBJSnd0UGF5bG9hZCB7XG5cdHVzZXJuYW1lOiBzdHJpbmcsXG5cdHJvbGU6IFRVc2VyUm9sZSxcblx0dWlkOiBudW1iZXIsXG5cdGNpZDogbnVtYmVyXG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgUmVxdWVzdFRva2VuIGV4dGVuZHMgUmVxdWVzdCB7XG5cdHRva2VuUGF5bG9hZDogSUp3dFBheWxvYWRcbn1cbiIsImltcG9ydCB7IElOZXN0QXBwbGljYXRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFN3YWdnZXJNb2R1bGUsIERvY3VtZW50QnVpbGRlciB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcblxuZXhwb3J0IGNvbnN0IHNldHVwU3dhZ2dlciA9IChhcHA6IElOZXN0QXBwbGljYXRpb24pID0+IHtcblx0Y29uc3QgY29uZmlnID0gbmV3IERvY3VtZW50QnVpbGRlcigpXG5cdFx0LnNldFRpdGxlKCdTaW1wbGUgQVBJJylcblx0XHQuc2V0RGVzY3JpcHRpb24oJ01lZGlob21lIEFQSSB1c2UgU3dhZ2dlcicpXG5cdFx0LnNldFZlcnNpb24oJzEuMCcpXG5cdFx0LmFkZEJlYXJlckF1dGgoXG5cdFx0XHR7IHR5cGU6ICdodHRwJywgZGVzY3JpcHRpb246ICdBY2Nlc3MgdG9rZW4nIH0sXG5cdFx0XHQnYWNjZXNzLXRva2VuJ1xuXHRcdClcblx0XHQuYnVpbGQoKVxuXHRjb25zdCBkb2N1bWVudCA9IFN3YWdnZXJNb2R1bGUuY3JlYXRlRG9jdW1lbnQoYXBwLCBjb25maWcpXG5cdFN3YWdnZXJNb2R1bGUuc2V0dXAoJ2RvY3VtZW50JywgYXBwLCBkb2N1bWVudClcbn1cbiIsImltcG9ydCB7IHJlZ2lzdGVyQXMgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGVPcHRpb25zIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuXG5leHBvcnQgY29uc3QgSnd0Q29uZmlnID0gcmVnaXN0ZXJBcygnand0JywgKCkgPT4gKHtcblx0YWNjZXNzS2V5OiBwcm9jZXNzLmVudi5KV1RfQUNDRVNTX0tFWSxcblx0cmVmcmVzaEtleTogcHJvY2Vzcy5lbnYuSldUX1JFRlJFU0hfS0VZLFxuXHRhY2Nlc3NUaW1lOiBOdW1iZXIocHJvY2Vzcy5lbnYuSldUX0FDQ0VTU19USU1FKSxcblx0cmVmcmVzaFRpbWU6IE51bWJlcihwcm9jZXNzLmVudi5KV1RfUkVGUkVTSF9USU1FKSxcbn0pKVxuXG5leHBvcnQgY29uc3QgTXlzcWxDb25maWcgPSByZWdpc3RlckFzKCdteXNxbCcsICgpOiBUeXBlT3JtTW9kdWxlT3B0aW9ucyA9PiAoe1xuXHR0eXBlOiAnbXlzcWwnLFxuXHRob3N0OiBwcm9jZXNzLmVudi5NWVNRTF9IT1NULFxuXHRwb3J0OiBwYXJzZUludChwcm9jZXNzLmVudi5NWVNRTF9QT1JULCAxMCksXG5cdGRhdGFiYXNlOiBwcm9jZXNzLmVudi5NWVNRTF9EQVRBQkFTRSxcblx0dXNlcm5hbWU6IHByb2Nlc3MuZW52Lk1ZU1FMX1VTRVJOQU1FLFxuXHRwYXNzd29yZDogcHJvY2Vzcy5lbnYuTVlTUUxfUEFTU1dPUkQsXG5cdGF1dG9Mb2FkRW50aXRpZXM6IHRydWUsXG5cdGxvZ2dpbmc6IHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicsXG5cdHN5bmNocm9uaXplOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ2xvY2FsJyxcbn0pKVxuIiwiaW1wb3J0IHsgQ2FuQWN0aXZhdGUsIEV4ZWN1dGlvbkNvbnRleHQsIEluamVjdGFibGUsIFNldE1ldGFkYXRhIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZWZsZWN0b3IgfSBmcm9tICdAbmVzdGpzL2NvcmUnXG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcydcbmltcG9ydCB7IFJlcXVlc3RUb2tlbiwgVFVzZXJSb2xlIH0gZnJvbSAnLi4vY29tbW9uL2NvbnN0YW50cydcblxuZXhwb3J0IGNvbnN0IFVzZXJSb2xlcyA9ICguLi51c2VyUm9sZXM6IFRVc2VyUm9sZVtdKSA9PiBTZXRNZXRhZGF0YSgndXNlcl9yb2xlcycsIHVzZXJSb2xlcylcbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBVc2VyUm9sZXNHdWFyZCBpbXBsZW1lbnRzIENhbkFjdGl2YXRlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWZsZWN0b3I6IFJlZmxlY3RvcikgeyB9XG5cblx0Y2FuQWN0aXZhdGUoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCk6IGJvb2xlYW4gfCBQcm9taXNlPGJvb2xlYW4+IHwgT2JzZXJ2YWJsZTxib29sZWFuPiB7XG5cdFx0Y29uc3Qgcm9sZXMgPSB0aGlzLnJlZmxlY3Rvci5nZXQ8VFVzZXJSb2xlW10+KCd1c2VyX3JvbGVzJywgY29udGV4dC5nZXRIYW5kbGVyKCkpXG5cdFx0aWYgKCFyb2xlcykgcmV0dXJuIHRydWVcblxuXHRcdGNvbnN0IHJlcXVlc3Q6IFJlcXVlc3RUb2tlbiA9IGNvbnRleHQuc3dpdGNoVG9IdHRwKCkuZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgeyByb2xlIH0gPSByZXF1ZXN0LnRva2VuUGF5bG9hZFxuXHRcdHJldHVybiByb2xlcy5pbmNsdWRlcyhyb2xlKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDYWxsSGFuZGxlciwgRXhlY3V0aW9uQ29udGV4dCwgSW5qZWN0YWJsZSwgTmVzdEludGVyY2VwdG9yLCBMb2dnZXIgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IGdldENsaWVudElwIH0gZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJ1xuaW1wb3J0IHsgdGFwIH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBY2Nlc3NMb2dJbnRlcmNlcHRvciBpbXBsZW1lbnRzIE5lc3RJbnRlcmNlcHRvciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgbG9nZ2VyID0gbmV3IExvZ2dlcignQUNDRVNTX0xPRycpKSB7IH1cblxuXHRpbnRlcmNlcHQoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCwgbmV4dDogQ2FsbEhhbmRsZXIpOiBPYnNlcnZhYmxlPGFueT4ge1xuXHRcdGNvbnN0IHN0YXJ0VGltZSA9IG5ldyBEYXRlKClcblx0XHRjb25zdCBjdHggPSBjb250ZXh0LnN3aXRjaFRvSHR0cCgpXG5cdFx0Y29uc3QgcmVxdWVzdCA9IGN0eC5nZXRSZXF1ZXN0KClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXF1ZXN0KClcblxuXHRcdGNvbnN0IHsgdXJsLCBtZXRob2QgfSA9IHJlcXVlc3Rcblx0XHRjb25zdCB7IHN0YXR1c0NvZGUgfSA9IHJlc3BvbnNlXG5cdFx0Y29uc3QgaXAgPSBnZXRDbGllbnRJcChyZXF1ZXN0KVxuXG5cdFx0cmV0dXJuIG5leHQuaGFuZGxlKCkucGlwZSh0YXAoKCkgPT4ge1xuXHRcdFx0Y29uc3QgbXNnID0gYCR7c3RhcnRUaW1lLnRvSVNPU3RyaW5nKCl9IHwgJHtpcH0gfCAke21ldGhvZH0gfCAke3N0YXR1c0NvZGV9IHwgJHt1cmx9IHwgJHtEYXRlLm5vdygpIC0gc3RhcnRUaW1lLmdldFRpbWUoKX1tc2Bcblx0XHRcdHJldHVybiB0aGlzLmxvZ2dlci5sb2cobXNnKVxuXHRcdH0pKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZXN0SW50ZXJjZXB0b3IsIEV4ZWN1dGlvbkNvbnRleHQsIENhbGxIYW5kbGVyLCBSZXF1ZXN0VGltZW91dEV4Y2VwdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgdGhyb3dFcnJvciwgVGltZW91dEVycm9yIH0gZnJvbSAncnhqcydcbmltcG9ydCB7IGNhdGNoRXJyb3IsIHRpbWVvdXQgfSBmcm9tICdyeGpzL29wZXJhdG9ycydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFRpbWVvdXRJbnRlcmNlcHRvciBpbXBsZW1lbnRzIE5lc3RJbnRlcmNlcHRvciB7XG5cdGludGVyY2VwdChjb250ZXh0OiBFeGVjdXRpb25Db250ZXh0LCBuZXh0OiBDYWxsSGFuZGxlcik6IE9ic2VydmFibGU8YW55PiB7XG5cdFx0cmV0dXJuIG5leHQuaGFuZGxlKCkucGlwZShcblx0XHRcdHRpbWVvdXQoMTAwMDApLFxuXHRcdFx0Y2F0Y2hFcnJvcihlcnIgPT4ge1xuXHRcdFx0XHRpZiAoZXJyIGluc3RhbmNlb2YgVGltZW91dEVycm9yKSB7XG5cdFx0XHRcdFx0cmV0dXJuIHRocm93RXJyb3IoKCkgPT4gbmV3IFJlcXVlc3RUaW1lb3V0RXhjZXB0aW9uKCkpXG5cdFx0XHRcdH1cblx0XHRcdFx0cmV0dXJuIHRocm93RXJyb3IoKCkgPT4gZXJyKVxuXHRcdFx0fSlcblx0XHQpXG5cdH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUsIE5lc3RNaWRkbGV3YXJlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSwgTmV4dEZ1bmN0aW9uIH0gZnJvbSAnZXhwcmVzcydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIExvZ2dlck1pZGRsZXdhcmUgaW1wbGVtZW50cyBOZXN0TWlkZGxld2FyZSB7XG5cdHVzZShyZXE6IFJlcXVlc3QsIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikge1xuXHRcdGNvbnNvbGUubG9nKCdSZXF1ZXN0Li4uJylcblx0XHRuZXh0KClcblx0fVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmVzdE1pZGRsZXdhcmUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IE5leHRGdW5jdGlvbiwgUmVxdWVzdCwgUmVzcG9uc2UgfSBmcm9tICdleHByZXNzJ1xuaW1wb3J0IHsgSUp3dFBheWxvYWQsIFJlcXVlc3RUb2tlbiB9IGZyb20gJy4uL2NvbW1vbi9jb25zdGFudHMnXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi4vbW9kdWxlcy9hdXRoL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFZhbGlkYXRlQWNjZXNzVG9rZW5NaWRkbGV3YXJlIGltcGxlbWVudHMgTmVzdE1pZGRsZXdhcmUge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGp3dEV4dGVuZFNlcnZpY2U6IEp3dEV4dGVuZFNlcnZpY2UpIHsgfVxuXG5cdGFzeW5jIHVzZShyZXE6IFJlcXVlc3RUb2tlbiwgcmVzOiBSZXNwb25zZSwgbmV4dDogTmV4dEZ1bmN0aW9uKSB7XG5cdFx0Y29uc3QgYXV0aG9yaXphdGlvbiA9IHJlcS5oZWFkZXIoJ0F1dGhvcml6YXRpb24nKSB8fCAnJ1xuXHRcdGNvbnN0IFssIGFjY2Vzc1Rva2VuXSA9IGF1dGhvcml6YXRpb24uc3BsaXQoJyAnKVxuXHRcdGNvbnN0IGRlY29kZTogSUp3dFBheWxvYWQgPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UudmVyaWZ5QWNjZXNzVG9rZW4oYWNjZXNzVG9rZW4pXG5cdFx0cmVxLnRva2VuUGF5bG9hZCA9IGRlY29kZVxuXHRcdG5leHQoKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBQYXJhbSwgUG9zdCwgUmVxIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlCZWFyZXJBdXRoLCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdCB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBMb2dpbkR0bywgUmVnaXN0ZXJEdG8gfSBmcm9tICcuL2F1dGguZHRvJ1xuaW1wb3J0IHsgQXV0aFNlcnZpY2UgfSBmcm9tICcuL2F1dGguc2VydmljZSdcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ0F1dGgnKVxuQENvbnRyb2xsZXIoJ2F1dGgnKVxuZXhwb3J0IGNsYXNzIEF1dGhDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSByZWFkb25seSBhdXRoU2VydmljZTogQXV0aFNlcnZpY2UsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlXG5cdCkgeyB9XG5cblx0QFBvc3QoJ3JlZ2lzdGVyJylcblx0QEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5cdGFzeW5jIHJlZ2lzdGVyKEBCb2R5KCkgcmVnaXN0ZXJEdG86IFJlZ2lzdGVyRHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdCkge1xuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxdWVzdClcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UucmVnaXN0ZXIocmVnaXN0ZXJEdG8pXG5cdFx0Y29uc3QgeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0gPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UuY3JlYXRlVG9rZW5Gcm9tRW1wbG95ZWUoZW1wbG95ZWUpXG5cdFx0cmV0dXJuIHsgZW1wbG95ZWUsIGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfVxuXHR9XG5cblx0QFBvc3QoJ2xvZ2luJylcblx0YXN5bmMgbG9naW4oQEJvZHkoKSBsb2dpbkR0bzogTG9naW5EdG8pIHtcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UubG9naW4obG9naW5EdG8pXG5cdFx0Y29uc3QgeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0gPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UuY3JlYXRlVG9rZW5Gcm9tRW1wbG95ZWUoZW1wbG95ZWUpXG5cdFx0cmV0dXJuIHsgZW1wbG95ZWUsIGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfVxuXHR9XG5cblx0QFBvc3QoJ2xvZ291dCcpXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBQb3N0KCdjaGFuZ2UtcGFzc3dvcmQnKVxuXHR1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlQXV0aER0bzogTG9naW5EdG8pIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS51cGRhdGUoK2lkLCB1cGRhdGVBdXRoRHRvKVxuXHR9XG5cblx0QFBvc3QoJ2ZvcmdvdC1wYXNzd29yZCcpXG5cdHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdC8vIHJldHVybiB0aGlzLmF1dGhTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IEFwaVByb3BlcnR5LCBQYXJ0aWFsVHlwZSB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IE1pbkxlbmd0aCwgVmFsaWRhdGUgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5pbXBvcnQgeyBJc0dtYWlsLCBJc1Bob25lIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NsYXNzLXZhbGlkYXRvci5jdXN0b20nXG5cbmV4cG9ydCBjbGFzcyBSZWdpc3RlckR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdleGFtcGxlQGdtYWlsLmNvbScgfSlcblx0QFZhbGlkYXRlKElzR21haWwpXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnMDk4NzEyMzQ1NicgfSlcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnQWJjQDEyMzQ1NicgfSlcblx0QE1pbkxlbmd0aCg2KVxuXHRwYXNzd29yZDogc3RyaW5nXG59XG5cbmV4cG9ydCBjbGFzcyBMb2dpbkR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdleGFtcGxlQGdtYWlsLmNvbScgfSlcblx0QFZhbGlkYXRlKElzR21haWwpXG5cdGVtYWlsPzogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FkbWluJyB9KVxuXHR1c2VybmFtZT86IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6IDEgfSlcblx0Y2xpbmljSWQ/OiBudW1iZXJcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnQWJjQDEyMzQ1NicgfSlcblx0QE1pbkxlbmd0aCg2KVxuXHRwYXNzd29yZDogc3RyaW5nXG59XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IENvbmZpZ01vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgSnd0TW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9qd3QnXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IHsgSnd0Q29uZmlnIH0gZnJvbSAnLi4vLi4vZW52aXJvbWVudHMnXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCBFbXBsb3llZUVudGl0eSBmcm9tICcuLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEF1dGhDb250cm9sbGVyIH0gZnJvbSAnLi9hdXRoLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJy4vYXV0aC5zZXJ2aWNlJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4vand0LWV4dGVuZC5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1xuXHRcdFR5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbQ2xpbmljRW50aXR5LCBFbXBsb3llZUVudGl0eV0pLFxuXHRcdENvbmZpZ01vZHVsZS5mb3JSb290KHsgbG9hZDogW0p3dENvbmZpZ10gfSksXG5cdFx0Snd0TW9kdWxlLFxuXHRdLFxuXHRjb250cm9sbGVyczogW0F1dGhDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbQXV0aFNlcnZpY2UsIEp3dEV4dGVuZFNlcnZpY2VdLFxuXHRleHBvcnRzOiBbSnd0RXh0ZW5kU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIEF1dGhNb2R1bGUgeyB9XG4iLCJpbXBvcnQgeyBFTG9naW5FcnJvciwgRVJlZ2lzdGVyRXJyb3IsIHJhbmRvbVN0cmluZyB9IGZyb20gJ0BsaWJzL3V0aWxzJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiwgSHR0cFN0YXR1cywgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0ICogYXMgYmNyeXB0IGZyb20gJ2JjcnlwdCdcbmltcG9ydCB7IERhdGFTb3VyY2UgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgRVVzZXJSb2xlIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgTG9naW5EdG8sIFJlZ2lzdGVyRHRvIH0gZnJvbSAnLi9hdXRoLmR0bydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlKSB7IH1cblxuXHRhc3luYyByZWdpc3RlcihyZWdpc3RlckR0bzogUmVnaXN0ZXJEdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgeyBlbWFpbCwgcGhvbmUsIHBhc3N3b3JkIH0gPSByZWdpc3RlckR0b1xuXHRcdGNvbnN0IGhhc2hQYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5oYXNoKHBhc3N3b3JkLCA1KVxuXG5cdFx0Y29uc3QgeyBlbXBsb3llZSB9ID0gYXdhaXQgdGhpcy5kYXRhU291cmNlLnRyYW5zYWN0aW9uKGFzeW5jIChtYW5hZ2VyKSA9PiB7XG5cdFx0XHRjb25zdCBmaW5kRW1wbG95ZWUgPSBhd2FpdCBtYW5hZ2VyLmZpbmRPbmUoRW1wbG95ZWVFbnRpdHksIHtcblx0XHRcdFx0d2hlcmU6IFtcblx0XHRcdFx0XHR7IGVtYWlsLCByb2xlOiBFVXNlclJvbGUuT3duZXIgfSxcblx0XHRcdFx0XHR7IHBob25lLCByb2xlOiBFVXNlclJvbGUuT3duZXIgfSxcblx0XHRcdFx0XSxcblx0XHRcdH0pXG5cdFx0XHRpZiAoZmluZEVtcGxveWVlKSB7XG5cdFx0XHRcdGlmIChmaW5kRW1wbG95ZWUuZW1haWwgPT09IGVtYWlsICYmIGZpbmRFbXBsb3llZS5waG9uZSA9PT0gcGhvbmUpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsQW5kUGhvbmUsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZSBpZiAoZmluZEVtcGxveWVlLmVtYWlsID09PSBlbWFpbCkge1xuXHRcdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVSZWdpc3RlckVycm9yLkV4aXN0RW1haWwsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZSBpZiAoZmluZEVtcGxveWVlLnBob25lID09PSBwaG9uZSkge1xuXHRcdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVSZWdpc3RlckVycm9yLkV4aXN0UGhvbmUsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdH1cblxuXHRcdFx0Y29uc3QgY3JlYXRlQ2xpbmljID0gbWFuYWdlci5jcmVhdGUoQ2xpbmljRW50aXR5LCB7XG5cdFx0XHRcdGNvZGU6IHJhbmRvbVN0cmluZyg1KSxcblx0XHRcdFx0bGV2ZWw6IDEsXG5cdFx0XHR9KVxuXHRcdFx0Y29uc3QgbmV3Q2xpbmljID0gYXdhaXQgbWFuYWdlci5zYXZlKGNyZWF0ZUNsaW5pYylcblxuXHRcdFx0Y29uc3QgY3JlYXRlRW1wbG95ZWUgPSBtYW5hZ2VyLmNyZWF0ZShFbXBsb3llZUVudGl0eSwge1xuXHRcdFx0XHRjbGluaWNJZDogbmV3Q2xpbmljLmlkLFxuXHRcdFx0XHRlbWFpbCxcblx0XHRcdFx0cGhvbmUsXG5cdFx0XHRcdHVzZXJuYW1lOiAnQWRtaW4nLFxuXHRcdFx0XHRwYXNzd29yZDogaGFzaFBhc3N3b3JkLFxuXHRcdFx0XHRyb2xlOiBFVXNlclJvbGUuT3duZXIsXG5cdFx0XHR9KVxuXHRcdFx0Y29uc3QgbmV3RW1wbG95ZWUgPSBhd2FpdCBtYW5hZ2VyLnNhdmUoY3JlYXRlRW1wbG95ZWUpXG5cdFx0XHRyZXR1cm4geyBjbGluaWM6IG5ld0NsaW5pYywgZW1wbG95ZWU6IG5ld0VtcGxveWVlIH1cblx0XHR9KVxuXHRcdHJldHVybiBlbXBsb3llZVxuXHR9XG5cblx0YXN5bmMgbG9naW4obG9naW5EdG86IExvZ2luRHRvKTogUHJvbWlzZTxFbXBsb3llZUVudGl0eT4ge1xuXHRcdGxldCBlbXBsb3llZTogRW1wbG95ZWVFbnRpdHlcblx0XHRpZiAobG9naW5EdG8uZW1haWwpIHtcblx0XHRcdGVtcGxveWVlID0gYXdhaXQgdGhpcy5kYXRhU291cmNlLm1hbmFnZXIuZmluZE9uZUJ5KEVtcGxveWVlRW50aXR5LCB7IGVtYWlsOiBsb2dpbkR0by5lbWFpbCB9KVxuXHRcdH0gZWxzZSBpZiAobG9naW5EdG8udXNlcm5hbWUpIHtcblx0XHRcdGVtcGxveWVlID0gYXdhaXQgdGhpcy5kYXRhU291cmNlLm1hbmFnZXIuZmluZE9uZUJ5KEVtcGxveWVlRW50aXR5LCB7IHVzZXJuYW1lOiBsb2dpbkR0by51c2VybmFtZSB9KVxuXHRcdH1cblx0XHRpZiAoIWVtcGxveWVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFTG9naW5FcnJvci5Vc2VyRG9lc05vdEV4aXN0LCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdH1cblxuXHRcdGNvbnN0IGNoZWNrUGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuY29tcGFyZShsb2dpbkR0by5wYXNzd29yZCwgZW1wbG95ZWUucGFzc3dvcmQpXG5cdFx0aWYgKCFjaGVja1Bhc3N3b3JkKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFTG9naW5FcnJvci5Xcm9uZ1Bhc3N3b3JkLCBIdHRwU3RhdHVzLkJBRF9HQVRFV0FZKVxuXHRcdH1cblxuXHRcdHJldHVybiBlbXBsb3llZVxuXHR9XG59XG4iLCJpbXBvcnQgeyBFRXJyb3IsIEVUb2tlbkVycm9yIH0gZnJvbSAnQGxpYnMvdXRpbHMnXG5pbXBvcnQgeyBIdHRwRXhjZXB0aW9uLCBIdHRwU3RhdHVzLCBJbmplY3QgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IENvbmZpZ1R5cGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEp3dFNlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2p3dCdcbmltcG9ydCB7IElKd3RQYXlsb2FkIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IEp3dENvbmZpZyB9IGZyb20gJy4uLy4uL2Vudmlyb21lbnRzJ1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuXG5leHBvcnQgY2xhc3MgSnd0RXh0ZW5kU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdEBJbmplY3QoSnd0Q29uZmlnLktFWSkgcHJpdmF0ZSBqd3RDb25maWc6IENvbmZpZ1R5cGU8dHlwZW9mIEp3dENvbmZpZz4sXG5cdFx0cHJpdmF0ZSByZWFkb25seSBqd3RTZXJ2aWNlOiBKd3RTZXJ2aWNlXG5cdCkgeyB9XG5cblx0Y3JlYXRlQWNjZXNzVG9rZW4ocGF5bG9hZDogb2JqZWN0KSB7XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHBheWxvYWQsIHtcblx0XHRcdHNlY3JldDogdGhpcy5qd3RDb25maWcuYWNjZXNzS2V5LFxuXHRcdFx0ZXhwaXJlc0luOiB0aGlzLmp3dENvbmZpZy5hY2Nlc3NUaW1lLFxuXHRcdH0pXG5cdH1cblxuXHRjcmVhdGVSZWZyZXNoVG9rZW4ocGF5bG9hZDogb2JqZWN0KSB7XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHBheWxvYWQsIHtcblx0XHRcdHNlY3JldDogdGhpcy5qd3RDb25maWcucmVmcmVzaEtleSxcblx0XHRcdGV4cGlyZXNJbjogdGhpcy5qd3RDb25maWcucmVmcmVzaFRpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVRva2VuRnJvbUVtcGxveWVlKGVtcGxveWVlOiBFbXBsb3llZUVudGl0eSkge1xuXHRcdGNvbnN0IGVtcGxveWVlUGF5bG9kOiBJSnd0UGF5bG9hZCA9IHtcblx0XHRcdHVzZXJuYW1lOiBlbXBsb3llZS51c2VybmFtZSxcblx0XHRcdHJvbGU6IGVtcGxveWVlLnJvbGUsXG5cdFx0XHR1aWQ6IGVtcGxveWVlLmlkLFxuXHRcdFx0Y2lkOiBlbXBsb3llZS5jbGluaWNJZCxcblx0XHR9XG5cdFx0Y29uc3QgYWNjZXNzVG9rZW4gPSB0aGlzLmNyZWF0ZUFjY2Vzc1Rva2VuKGVtcGxveWVlUGF5bG9kKVxuXHRcdGNvbnN0IHJlZnJlc2hUb2tlbiA9IHRoaXMuY3JlYXRlUmVmcmVzaFRva2VuKGVtcGxveWVlUGF5bG9kKVxuXHRcdHJldHVybiB7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfVxuXHR9XG5cblx0dmVyaWZ5QWNjZXNzVG9rZW4oYWNjZXNzVG9rZW46IHN0cmluZykge1xuXHRcdHRyeSB7XG5cdFx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnZlcmlmeShhY2Nlc3NUb2tlbiwgeyBzZWNyZXQ6IHRoaXMuand0Q29uZmlnLmFjY2Vzc0tleSB9KVxuXHRcdH0gY2F0Y2ggKGVycm9yKSB7XG5cdFx0XHRpZiAoZXJyb3IubmFtZSA9PT0gJ1Rva2VuRXhwaXJlZEVycm9yJykge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5FeHBpcmVkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH0gZWxzZSBpZiAoZXJyb3IubmFtZSA9PT0gJ0pzb25XZWJUb2tlbkVycm9yJykge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5JbnZhbGlkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH1cblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVFcnJvci5Vbmtub3csIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxuXG5cdHZlcmlmeVJlZnJlc2hUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZykge1xuXHRcdHRyeSB7XG5cdFx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnZlcmlmeShyZWZyZXNoVG9rZW4sIHsgc2VjcmV0OiB0aGlzLmp3dENvbmZpZy5yZWZyZXNoS2V5IH0pXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vdywgSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1IpXG5cdFx0fVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDb250cm9sbGVyLCBHZXQsIFBvc3QsIEJvZHksIFBhdGNoLCBQYXJhbSwgRGVsZXRlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDbGluaWNTZXJ2aWNlIH0gZnJvbSAnLi9jbGluaWMuc2VydmljZSdcbmltcG9ydCB7IENyZWF0ZUNsaW5pY0R0bywgVXBkYXRlQ2xpbmljRHRvIH0gZnJvbSAnLi9jbGluaWMuZHRvJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcblxuQEFwaVRhZ3MoJ0NsaW5pYycpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBDb250cm9sbGVyKCdjbGluaWMnKVxuZXhwb3J0IGNsYXNzIENsaW5pY0NvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGNsaW5pY1NlcnZpY2U6IENsaW5pY1NlcnZpY2UpIHsgfVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlQ2xpbmljRHRvOiBDcmVhdGVDbGluaWNEdG8pIHtcblx0XHRyZXR1cm4gJydcblx0fVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMuY2xpbmljU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBEZWxldGUoJzppZCcpXG5cdHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0VtYWlsLCBMZW5ndGggfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVDbGluaWNEdG8ge1xuXHRASXNFbWFpbCgpXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRATGVuZ3RoKDEwLCAxMClcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBMZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlQ2xpbmljRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlQ2xpbmljRHRvKSB7IH1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5pbXBvcnQgeyBDbGluaWNDb250cm9sbGVyIH0gZnJvbSAnLi9jbGluaWMuY29udHJvbGxlcidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW0NsaW5pY0VudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtDbGluaWNDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbQ2xpbmljU2VydmljZV0sXG5cdGV4cG9ydHM6IFtDbGluaWNTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQ2xpbmljTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCB7IERhdGFTb3VyY2UsIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuLi8uLi90eXBlb3JtL2VudGl0aWVzL2NsaW5pYy5lbnRpdHknXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDbGluaWNTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0QEluamVjdFJlcG9zaXRvcnkoQ2xpbmljRW50aXR5KSBwcml2YXRlIGNsaW5pY1JlcG9zaXRvcnk6IFJlcG9zaXRvcnk8Q2xpbmljRW50aXR5Pixcblx0XHRwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2Vcblx0KSB7IH1cblxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhbGwgY2xpbmljYFxuXHR9XG5cblx0ZmluZE9uZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxuXG5cdHVwZGF0ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiB1cGRhdGVzIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxuXG5cdHJlbW92ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZW1vdmVzIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHkgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVFbXBsb3llZUR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdlbXBsb3llZTEnIH0pXG5cdHVzZXJuYW1lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnQWJjQDEyMzQ1NicgfSlcblx0cGFzc3dvcmQ6IHN0cmluZ1xuXG5cdGNsaW5pY0lkOiBudW1iZXJcbn1cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2NyZWF0ZS1lbXBsb3llZS5kdG8nXG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVFbXBsb3llZUR0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZUVtcGxveWVlRHRvKSB7fVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgRGVsZXRlLCBHZXQsIFBhcmFtLCBQYXRjaCwgUG9zdCwgUmVxIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlCZWFyZXJBdXRoLCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IFVzZXJSb2xlcyB9IGZyb20gJy4uLy4uL2d1YXJkcy91c2VyLXJvbGVzLmd1YXJkJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtZW1wbG95ZWUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtZW1wbG95ZWUuZHRvJ1xuaW1wb3J0IHsgRW1wbG95ZWVTZXJ2aWNlIH0gZnJvbSAnLi9lbXBsb3llZS5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnRW1wbG95ZWUnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignZW1wbG95ZWUnKVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgZW1wbG95ZWVTZXJ2aWNlOiBFbXBsb3llZVNlcnZpY2UpIHsgfVxuXG5cdEBQb3N0KClcblx0QFVzZXJSb2xlcygnT3duZXInLCAnQWRtaW4nKVxuXHRhc3luYyBjcmVhdGUoQEJvZHkoKSBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjcmVhdGVFbXBsb3llZUR0by5jbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5jcmVhdGUoY3JlYXRlRW1wbG95ZWVEdG8pXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5lbXBsb3llZVNlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLmZpbmRPbmUoK2lkKVxuXHR9XG5cblx0QFBhdGNoKCc6aWQnKVxuXHR1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlRW1wbG95ZWVEdG86IFVwZGF0ZUVtcGxveWVlRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0QERlbGV0ZSgnOmlkJylcblx0cmVtb3ZlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgRW1wbG95ZWVTZXJ2aWNlIH0gZnJvbSAnLi9lbXBsb3llZS5zZXJ2aWNlJ1xuaW1wb3J0IHsgRW1wbG95ZWVDb250cm9sbGVyIH0gZnJvbSAnLi9lbXBsb3llZS5jb250cm9sbGVyJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBFbXBsb3llZUVudGl0eSBmcm9tICcuLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW0VtcGxveWVlRW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW0VtcGxveWVlQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0VtcGxveWVlU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgSHR0cFN0YXR1cywgSHR0cEV4Y2VwdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtZW1wbG95ZWUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtZW1wbG95ZWUuZHRvJ1xuaW1wb3J0ICogYXMgYmNyeXB0IGZyb20gJ2JjcnlwdCdcbmltcG9ydCB7IERhdGFTb3VyY2UgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgRUVtcGxveWVlRXJyb3IgfSBmcm9tICdAbGlicy91dGlscydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgZGF0YVNvdXJjZTogRGF0YVNvdXJjZSkgeyB9XG5cblx0YXN5bmMgY3JlYXRlKGNyZWF0ZUVtcGxveWVlRHRvOiBDcmVhdGVFbXBsb3llZUR0bykge1xuXHRcdGNvbnN0IHsgdXNlcm5hbWUsIHBhc3N3b3JkLCBjbGluaWNJZCB9ID0gY3JlYXRlRW1wbG95ZWVEdG9cblx0XHRjb25zdCBoYXNoUGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaChwYXNzd29yZCwgNSlcblxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5kYXRhU291cmNlLnRyYW5zYWN0aW9uKGFzeW5jIChtYW5hZ2VyKSA9PiB7XG5cdFx0XHRjb25zdCBmaW5kRW1wbG95ZWUgPSBhd2FpdCBtYW5hZ2VyLmZpbmRPbmUoRW1wbG95ZWVFbnRpdHksIHsgd2hlcmU6IHsgdXNlcm5hbWUsIGNsaW5pY0lkIH0gfSlcblx0XHRcdGlmIChmaW5kRW1wbG95ZWUpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVtcGxveWVlRXJyb3IuVXNlcm5hbWVFeGlzdHMsIEh0dHBTdGF0dXMuQkFEX0dBVEVXQVkpXG5cdFx0XHR9XG5cdFx0XHRjb25zdCBjcmVhdGVFbXBsb3llZSA9IG1hbmFnZXIuY3JlYXRlKEVtcGxveWVlRW50aXR5LCB7XG5cdFx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0XHR1c2VybmFtZSxcblx0XHRcdFx0cGFzc3dvcmQ6IGhhc2hQYXNzd29yZCxcblx0XHRcdH0pXG5cdFx0XHRjb25zdCBuZXdFbXBsb3llZSA9IGF3YWl0IG1hbmFnZXIuc2F2ZShjcmVhdGVFbXBsb3llZSlcblx0XHRcdHJldHVybiBuZXdFbXBsb3llZVxuXHRcdH0pXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhbGwgZW1wbG95ZWVgXG5cdH1cblxuXHRmaW5kT25lKGlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYSAjJHtpZH0gZW1wbG95ZWVgXG5cdH1cblxuXHR1cGRhdGUoaWQ6IG51bWJlciwgdXBkYXRlRW1wbG95ZWVEdG86IFVwZGF0ZUVtcGxveWVlRHRvKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiB1cGRhdGVzIGEgIyR7aWR9IGVtcGxveWVlYFxuXHR9XG5cblx0cmVtb3ZlKGlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJlbW92ZXMgYSAjJHtpZH0gZW1wbG95ZWVgXG5cdH1cbn1cbiIsImV4cG9ydCBjbGFzcyBDcmVhdGVNZWRpY2luZUR0byB7fVxuIiwiaW1wb3J0IHsgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBDcmVhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vY3JlYXRlLW1lZGljaW5lLmR0bydcblxuZXhwb3J0IGNsYXNzIFVwZGF0ZU1lZGljaW5lRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlTWVkaWNpbmVEdG8pIHt9XG4iLCJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBEZWxldGUsIEdldCwgUGFyYW0sIFBhdGNoLCBQb3N0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlCZWFyZXJBdXRoLCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgTWVkaWNpbmVTZXJ2aWNlIH0gZnJvbSAnLi9tZWRpY2luZS5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnTWVkaWNpbmUnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignbWVkaWNpbmUnKVxuZXhwb3J0IGNsYXNzIE1lZGljaW5lQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgbWVkaWNpbmVTZXJ2aWNlOiBNZWRpY2luZVNlcnZpY2UpIHsgfVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlTWVkaWNpbmVEdG86IENyZWF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLmNyZWF0ZShjcmVhdGVNZWRpY2luZUR0bylcblx0fVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5maW5kQWxsKClcblx0fVxuXG5cdEBHZXQoJzppZCcpXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRAUGF0Y2goJzppZCcpXG5cdHVwZGF0ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQEJvZHkoKSB1cGRhdGVNZWRpY2luZUR0bzogVXBkYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UudXBkYXRlKCtpZCwgdXBkYXRlTWVkaWNpbmVEdG8pXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBNZWRpY2luZVNlcnZpY2UgfSBmcm9tICcuL21lZGljaW5lLnNlcnZpY2UnXG5pbXBvcnQgeyBNZWRpY2luZUNvbnRyb2xsZXIgfSBmcm9tICcuL21lZGljaW5lLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IE1lZGljaW5lRW50aXR5IGZyb20gJy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvbWVkaWNpbmUuZW50aXR5J1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1R5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbTWVkaWNpbmVFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbTWVkaWNpbmVDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbTWVkaWNpbmVTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgTWVkaWNpbmVNb2R1bGUgeyB9XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDcmVhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL2NyZWF0ZS1tZWRpY2luZS5kdG8nXG5pbXBvcnQgeyBVcGRhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL3VwZGF0ZS1tZWRpY2luZS5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBNZWRpY2luZVNlcnZpY2Uge1xuXHRjcmVhdGUoY3JlYXRlTWVkaWNpbmVEdG86IENyZWF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuICdUaGlzIGFjdGlvbiBhZGRzIGEgbmV3IG1lZGljaW5lJ1xuXHR9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIG1lZGljaW5lYFxuXHR9XG5cblx0ZmluZE9uZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGEgIyR7aWR9IG1lZGljaW5lYFxuXHR9XG5cblx0dXBkYXRlKGlkOiBudW1iZXIsIHVwZGF0ZU1lZGljaW5lRHRvOiBVcGRhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxuXG5cdHJlbW92ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZW1vdmVzIGEgIyR7aWR9IG1lZGljaW5lYFxuXHR9XG59XG4iLCJpbXBvcnQge1xuXHRQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLCBDb2x1bW4sXG5cdENyZWF0ZURhdGVDb2x1bW4sIFVwZGF0ZURhdGVDb2x1bW4sIERlbGV0ZURhdGVDb2x1bW4sIFZlcnNpb25Db2x1bW4sXG59IGZyb20gJ3R5cGVvcm0nXG5cbmV4cG9ydCBjbGFzcyBCYXNlRW50aXR5IHtcblx0QFByaW1hcnlHZW5lcmF0ZWRDb2x1bW4oeyBuYW1lOiAnaWQnIH0pXG5cdGlkOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2NyZWF0ZWRfYnknLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRjcmVhdGVkQnk6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAndXBkYXRlZF9ieScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdHVwZGF0ZWRCeTogbnVtYmVyXG5cblx0QENyZWF0ZURhdGVDb2x1bW4oeyBuYW1lOiAnY3JlYXRlZF9hdCcgfSlcblx0Y3JlYXRlZEF0OiBEYXRlXG5cblx0QFVwZGF0ZURhdGVDb2x1bW4oeyBuYW1lOiAndXBkYXRlZF9hdCcgfSlcblx0dXBkYXRlZEF0OiBEYXRlXG5cblx0QERlbGV0ZURhdGVDb2x1bW4oeyBuYW1lOiAnZGVsZXRlZF9hdCcgfSlcblx0ZGVsZXRlZEF0OiBEYXRlXG5cblx0QFZlcnNpb25Db2x1bW4oKVxuXHR2ZXJzaW9uOiBudW1iZXJcbn1cbiIsImltcG9ydCB7IENvbHVtbiwgRW50aXR5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHkgfSBmcm9tICcuLi9jb21tb24vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ2NsaW5pYycpXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBDbGluaWNFbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IHR5cGU6ICd0aW55aW50JywgZGVmYXVsdDogMSB9KVxuXHRsZXZlbDogbnVtYmVyXG5cblx0QENvbHVtbih7IG5hbWU6ICdjb2RlJywgbnVsbGFibGU6IHRydWUgfSlcblx0Y29kZTogc3RyaW5nXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGNsaW5pY05hbWU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRhZGRyZXNzOiBzdHJpbmdcbn1cbiIsImltcG9ydCB7IENvbHVtbiwgRW50aXR5LCBJbmRleCB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBFVXNlclJvbGUgfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2NvbW1vbi9iYXNlLmVudGl0eSdcblxuQEVudGl0eSgnZW1wbG95ZWUnKVxuQEluZGV4KFsnY2xpbmljSWQnLCAnZW1haWwnXSlcbkBJbmRleChbJ2NsaW5pY0lkJywgJ3VzZXJuYW1lJ10pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBFbXBsb3llZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyB1bmlxdWU6IHRydWUsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdW5pcXVlOiB0cnVlLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QENvbHVtbigpXG5cdHVzZXJuYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKClcblx0cGFzc3dvcmQ6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRhZGRyZXNzOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ2VudW0nLCBlbnVtOiBFVXNlclJvbGUsIGRlZmF1bHQ6IEVVc2VyUm9sZS5Vc2VyIH0pXG5cdHJvbGU6IEVVc2VyUm9sZVxufVxuIiwiaW1wb3J0IHsgRW50aXR5LCBDb2x1bW4sIEluZGV4IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHkgfSBmcm9tICcuLi9jb21tb24vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ21lZGljaW5lJylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ2lkJ10sIHsgdW5pcXVlOiB0cnVlIH0pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNZWRpY2luZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnYnJhbmRfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGJyYW5kTmFtZTogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdMOqbiBiaeG7h3QgZMaw4bujY1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnY2hlbWljYWxfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGNoZW1pY2FsTmFtZTogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdMOqbiBn4buRY1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnY2FsY3VsYXRpb25fdW5pdCcsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGNhbGN1bGF0aW9uVW5pdDogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgLy8gxJHGoW4gduG7iyB0w61uaDogbOG7jSwg4buRbmcsIHbhu4lcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2ltYWdlJywgbnVsbGFibGU6IHRydWUgfSlcblx0aW1hZ2U6IHN0cmluZ1xufVxuIiwiZXhwb3J0IGVudW0gRUVycm9yIHtcblx0VW5rbm93ID0gJ0EwMC5VTktOT1cnXG59XG5cbmV4cG9ydCBlbnVtIEVWYWxpZGF0ZUVycm9yIHtcblx0RmFpbGQgPSAnVjAwLlZBTElEQVRFX0ZBSUwnXG59XG5cbmV4cG9ydCBlbnVtIEVSZWdpc3RlckVycm9yIHtcblx0RXhpc3RFbWFpbEFuZFBob25lID0gJ1IwMS5FTUFJTF9BTkRfUEhPTkVfRVhJU1RTJyxcblx0RXhpc3RFbWFpbCA9ICdSMDIuRU1BSUxfRVhJU1RTJyxcblx0RXhpc3RQaG9uZSA9ICdSMDMuUEhPTkVfRVhJU1RTJyxcbn1cblxuZXhwb3J0IGVudW0gRUxvZ2luRXJyb3Ige1xuXHRVc2VyRG9lc05vdEV4aXN0ID0gJ0wwMS5VU0VSX0RPRVNfTk9UX0VYSVNUJyxcblx0V3JvbmdQYXNzd29yZCA9ICdMMDIuV1JPTkdfUEFTU1dPUkQnXG59XG5cbmV4cG9ydCBlbnVtIEVUb2tlbkVycm9yIHtcblx0RXhwaXJlZCA9ICdUMDEuRVhQSVJFRCcsXG5cdEludmFsaWQgPSAnVDAyLklOVkFMSUQnXG59XG5cbmV4cG9ydCBlbnVtIEVFbXBsb3llZUVycm9yIHtcblx0VXNlcm5hbWVFeGlzdHMgPSAnRTAxLlVzZXJuYW1lX0V4aXN0cydcbn1cbiIsImltcG9ydCB7IEV4Y2VwdGlvbkZpbHRlciwgQ2F0Y2gsIEFyZ3VtZW50c0hvc3QsIEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcblxuQENhdGNoKEh0dHBFeGNlcHRpb24pXG5leHBvcnQgY2xhc3MgSHR0cEV4Y2VwdGlvbkZpbHRlciBpbXBsZW1lbnRzIEV4Y2VwdGlvbkZpbHRlciB7XG5cdGNhdGNoKGV4Y2VwdGlvbjogSHR0cEV4Y2VwdGlvbiwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IGV4Y2VwdGlvbi5nZXRTdGF0dXMoKVxuXG5cdFx0cmVzcG9uc2Uuc3RhdHVzKGh0dHBTdGF0dXMpLmpzb24oe1xuXHRcdFx0aHR0cFN0YXR1cyxcblx0XHRcdG1lc3NhZ2U6IGV4Y2VwdGlvbi5nZXRSZXNwb25zZSgpLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0XHRwYXRoOiByZXF1ZXN0LnVybCxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcmd1bWVudHNIb3N0LCBDYXRjaCwgRXhjZXB0aW9uRmlsdGVyLCBIdHRwU3RhdHVzIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5cbkBDYXRjaChFcnJvcilcbmV4cG9ydCBjbGFzcyBVbmtub3dFeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjYXRjaChleGNlcHRpb246IEVycm9yLCBob3N0OiBBcmd1bWVudHNIb3N0KSB7XG5cdFx0Y29uc3QgY3R4ID0gaG9zdC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlc3BvbnNlID0gY3R4LmdldFJlc3BvbnNlPFJlc3BvbnNlPigpXG5cdFx0Y29uc3QgcmVxdWVzdCA9IGN0eC5nZXRSZXF1ZXN0PFJlcXVlc3Q+KClcblx0XHRjb25zdCBodHRwU3RhdHVzID0gSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1JcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlOiBleGNlcHRpb24ubWVzc2FnZSxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXJndW1lbnRzSG9zdCwgQ2F0Y2gsIEV4Y2VwdGlvbkZpbHRlciwgSHR0cFN0YXR1cywgVmFsaWRhdGlvbkVycm9yIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBFVmFsaWRhdGVFcnJvciB9IGZyb20gJy4vZXhjZXB0aW9uLmVudW0nXG5cbmV4cG9ydCBjbGFzcyBWYWxpZGF0aW9uRXhjZXB0aW9uIGV4dGVuZHMgRXJyb3Ige1xuXHRwcml2YXRlIHJlYWRvbmx5IGVycm9yczogVmFsaWRhdGlvbkVycm9yW11cblx0Y29uc3RydWN0b3IodmFsaWRhdGlvbkVycm9yczogVmFsaWRhdGlvbkVycm9yW10gPSBbXSkge1xuXHRcdHN1cGVyKEVWYWxpZGF0ZUVycm9yLkZhaWxkKVxuXHRcdHRoaXMuZXJyb3JzID0gdmFsaWRhdGlvbkVycm9yc1xuXHR9XG5cdGdldE1lc3NhZ2UoKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVzc2FnZVxuXHR9XG5cdGdldEVycm9ycygpIHtcblx0XHRyZXR1cm4gdGhpcy5lcnJvcnNcblx0fVxufVxuXG5AQ2F0Y2goVmFsaWRhdGlvbkV4Y2VwdGlvbilcbmV4cG9ydCBjbGFzcyBWYWxpZGF0aW9uRXhjZXB0aW9uRmlsdGVyIGltcGxlbWVudHMgRXhjZXB0aW9uRmlsdGVyIHtcblx0Y2F0Y2goZXhjZXB0aW9uOiBWYWxpZGF0aW9uRXhjZXB0aW9uLCBob3N0OiBBcmd1bWVudHNIb3N0KSB7XG5cdFx0Y29uc3QgY3R4ID0gaG9zdC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlc3BvbnNlID0gY3R4LmdldFJlc3BvbnNlPFJlc3BvbnNlPigpXG5cdFx0Y29uc3QgcmVxdWVzdCA9IGN0eC5nZXRSZXF1ZXN0PFJlcXVlc3Q+KClcblx0XHRjb25zdCBodHRwU3RhdHVzID0gSHR0cFN0YXR1cy5CQURfUkVRVUVTVFxuXHRcdGNvbnN0IG1lc3NhZ2UgPSBleGNlcHRpb24uZ2V0TWVzc2FnZSgpXG5cdFx0Y29uc3QgZXJyb3JzID0gZXhjZXB0aW9uLmdldEVycm9ycygpXG5cblx0XHRyZXNwb25zZS5zdGF0dXMoaHR0cFN0YXR1cykuanNvbih7XG5cdFx0XHRodHRwU3RhdHVzLFxuXHRcdFx0bWVzc2FnZSxcblx0XHRcdGVycm9ycyxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiXG5jb25zdCBfQ0hBUlNFVCA9ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSdcblxuY29uc3QgZ2VuZXJhdGVDaGFyc2V0ID0gKHByaXZhdGVLZXkgPSAnQWJjMTIzJywgY2hhcnNldCA9IF9DSEFSU0VUKTogc3RyaW5nID0+IHtcblx0bGV0IHRlbXBTdHJpbmcgPSBjaGFyc2V0XG5cdGxldCByZXN1bHQgPSAnJ1xuXHRmb3IgKGxldCBpID0gMDsgaSA8IF9DSEFSU0VULmxlbmd0aDsgaSArPSAxKSB7XG5cdFx0Y29uc3Qga0luZGV4ID0gaSAlIHByaXZhdGVLZXkubGVuZ3RoXG5cdFx0Y29uc3QgY2hhckNvZGUgPSBwcml2YXRlS2V5LmNoYXJDb2RlQXQoa0luZGV4KVxuXHRcdGNvbnN0IHRJbmRleCA9IGNoYXJDb2RlICUgdGVtcFN0cmluZy5sZW5ndGhcblxuXHRcdHJlc3VsdCA9IHRlbXBTdHJpbmdbdEluZGV4XSArIHJlc3VsdFxuXHRcdHRlbXBTdHJpbmcgPSB0ZW1wU3RyaW5nLnN1YnN0cmluZyh0SW5kZXggKyAxKSArIHRlbXBTdHJpbmcuc3Vic3RyaW5nKDAsIHRJbmRleClcblx0fVxuXHRyZXR1cm4gcmVzdWx0XG59XG5cbmV4cG9ydCBjb25zdCByYW5kb21JZCA9ICgpOiBzdHJpbmcgPT4ge1xuXHRjb25zdCBub3cgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKS50b1N0cmluZygzNikgLy8gbDB1MmlmZ3UgLSAuLi4gLSAuLi4gLSB0b2RvXG5cdHJldHVybiBub3dcbn1cblxuZXhwb3J0IGNvbnN0IHJhbmRvbVN0cmluZyA9IChsZW5ndGggPSAxMCwgY2hhcmFjdGVycyA9IF9DSEFSU0VUKTogc3RyaW5nID0+IHtcblx0bGV0IHJlc3VsdCA9ICcnXG5cdGZvciAobGV0IGkgPSAwOyBpIDwgbGVuZ3RoOyBpICs9IDEpIHtcblx0XHRyZXN1bHQgKz0gY2hhcmFjdGVycy5jaGFyQXQoTWF0aC5mbG9vcihNYXRoLnJhbmRvbSgpICogY2hhcmFjdGVycy5sZW5ndGgpKVxuXHR9XG5cdHJldHVybiByZXN1bHRcbn1cblxuZXhwb3J0IGNvbnN0IGVuY3JpcHQgPSAocm9vdFN0cmluZzogc3RyaW5nLCBwcml2YXRlS2V5Pzogc3RyaW5nKTogc3RyaW5nID0+IHtcblx0Y29uc3QgaGFzaCA9IGdlbmVyYXRlQ2hhcnNldChwcml2YXRlS2V5KVxuXHRsZXQgcmVzdWx0ID0gJydcblx0Zm9yIChsZXQgaSA9IDA7IGkgPCByb290U3RyaW5nLmxlbmd0aDsgaSArPSAxKSB7XG5cdFx0Y29uc3QgaW5kZXggPSBfQ0hBUlNFVC5pbmRleE9mKHJvb3RTdHJpbmdbaV0pXG5cdFx0aWYgKGluZGV4ID09PSAtMSkge1xuXHRcdFx0cmVzdWx0ICs9IHJvb3RTdHJpbmdbaV1cblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzdWx0ICs9IGhhc2hbaW5kZXhdXG5cdFx0fVxuXHR9XG5cdHJldHVybiByZXN1bHRcbn1cblxuZXhwb3J0IGNvbnN0IGRlY3JpcHQgPSAoY2lwaGVyVGV4dDogc3RyaW5nLCBwcml2YXRlS2V5Pzogc3RyaW5nKTogc3RyaW5nID0+IHtcblx0Y29uc3QgaGFzaCA9IGdlbmVyYXRlQ2hhcnNldChwcml2YXRlS2V5KVxuXHRsZXQgcmVzdWx0ID0gJydcblx0Zm9yIChsZXQgaSA9IDA7IGkgPCBjaXBoZXJUZXh0Lmxlbmd0aDsgaSArPSAxKSB7XG5cdFx0Y29uc3QgaW5kZXggPSBoYXNoLmluZGV4T2YoY2lwaGVyVGV4dFtpXSlcblx0XHRpZiAoaW5kZXggPT09IC0xKSB7XG5cdFx0XHRyZXN1bHQgKz0gY2lwaGVyVGV4dFtpXVxuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXN1bHQgKz0gX0NIQVJTRVRbaW5kZXhdXG5cdFx0fVxuXHR9XG5cdHJldHVybiByZXN1bHRcbn1cblxuZXhwb3J0IGNvbnN0IGNvbnZlcnRWaVRvRW4gPSAocm9vdDogc3RyaW5nKTogc3RyaW5nID0+XG5cdHJvb3Rcblx0XHQubm9ybWFsaXplKCdORkQnKVxuXHRcdC5yZXBsYWNlKC9bXFx1MDMwMC1cXHUwMzZmXS9nLCAnJylcblx0XHQucmVwbGFjZSgvxJEvZywgJ2QnKVxuXHRcdC5yZXBsYWNlKC/EkC9nLCAnRCcpXG5cbmV4cG9ydCBjb25zdCBmb3JtYXROdW1iZXIgPSAobnVtYmVyOiBudW1iZXIsIGZpeGVkID0gMywgcGFydCA9IDMsIHNlYyA9ICcsJywgZGVjID0gJy4nKSA9PiB7XG5cdGNvbnN0IHJlZ2V4ID0gJ1xcXFxkKD89KFxcXFxkeycgKyBwYXJ0ICsgJ30pKycgKyAoZml4ZWQgPiAwID8gJ1xcXFxEJyA6ICckJykgKyAnKSdcblx0cmV0dXJuIG51bWJlclxuXHRcdC50b0ZpeGVkKGZpeGVkKVxuXHRcdC5yZXBsYWNlKCcuJywgZGVjKVxuXHRcdC5yZXBsYWNlKG5ldyBSZWdFeHAocmVnZXgsICdnJyksICckJicgKyBzZWMpXG59XG4iLCJleHBvcnQgKiBmcm9tICcuL2hlbHBlcnMvc3RyaW5nLmhlbHBlcidcblxuZXhwb3J0ICogZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcbmV4cG9ydCAqIGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvaHR0cC1leGNlcHRpb24uZmlsdGVyJ1xuZXhwb3J0ICogZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy91bmtub3ctZXhjZXB0aW9uLmZpbHRlcidcbmV4cG9ydCAqIGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvdmFsaWRhdGlvbi1leGNlcHRpb24uZmlsdGVyJ1xuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvand0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvc3dhZ2dlclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3R5cGVvcm1cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiYmNyeXB0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImNsYXNzLXZhbGlkYXRvclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJleHByZXNzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImV4cHJlc3MtcmF0ZS1saW1pdFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJoZWxtZXRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwicmVxdWVzdC1pcFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJyeGpzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInJ4anMvb3BlcmF0b3JzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInR5cGVvcm1cIik7IiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXS5jYWxsKG1vZHVsZS5leHBvcnRzLCBtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb25GaWx0ZXIsIFVua25vd0V4Y2VwdGlvbkZpbHRlciwgVmFsaWRhdGlvbkV4Y2VwdGlvbiwgVmFsaWRhdGlvbkV4Y2VwdGlvbkZpbHRlciB9IGZyb20gJ0BsaWJzL3V0aWxzJ1xuaW1wb3J0IHsgVmFsaWRhdGlvbkVycm9yLCBWYWxpZGF0aW9uUGlwZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnU2VydmljZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgTmVzdEZhY3RvcnksIFJlZmxlY3RvciB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCByYXRlTGltaXQgZnJvbSAnZXhwcmVzcy1yYXRlLWxpbWl0J1xuaW1wb3J0IGhlbG1ldCBmcm9tICdoZWxtZXQnXG5pbXBvcnQgKiBhcyByZXF1ZXN0SXAgZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IEFwcE1vZHVsZSB9IGZyb20gJy4vYXBwLm1vZHVsZSdcbmltcG9ydCB7IHNldHVwU3dhZ2dlciB9IGZyb20gJy4vY29tbW9uL3N3YWdnZXInXG5pbXBvcnQgeyBVc2VyUm9sZXNHdWFyZCB9IGZyb20gJy4vZ3VhcmRzL3VzZXItcm9sZXMuZ3VhcmQnXG5pbXBvcnQgeyBBY2Nlc3NMb2dJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvYWNjZXNzLWxvZy5pbnRlcmNlcHRvcidcbmltcG9ydCB7IFRpbWVvdXRJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvdGltZW91dC5pbnRlcmNlcHRvcidcblxuYXN5bmMgZnVuY3Rpb24gYm9vdHN0cmFwKCkge1xuXHRjb25zdCBhcHAgPSBhd2FpdCBOZXN0RmFjdG9yeS5jcmVhdGUoQXBwTW9kdWxlKVxuXG5cdGNvbnN0IGNvbmZpZ1NlcnZpY2UgPSBhcHAuZ2V0KENvbmZpZ1NlcnZpY2UpXG5cdGNvbnN0IFBPUlQgPSBjb25maWdTZXJ2aWNlLmdldCgnU0VSVkVSX1BPUlQnKVxuXG5cdGFwcC51c2UoaGVsbWV0KCkpXG5cdGFwcC51c2UocmF0ZUxpbWl0KHtcblx0XHR3aW5kb3dNczogMTUgKiA2MCAqIDEwMDAsIC8vIDE1IG1pbnV0ZXNcblx0XHRtYXg6IDEwMCwgLy8gbGltaXQgZWFjaCBJUCB0byAxMDAgcmVxdWVzdHMgcGVyIHdpbmRvd01zXG5cdH0pKVxuXHRhcHAuZW5hYmxlQ29ycygpXG5cblx0YXBwLnVzZShyZXF1ZXN0SXAubXcoKSlcblxuXHRhcHAudXNlR2xvYmFsSW50ZXJjZXB0b3JzKFxuXHRcdG5ldyBBY2Nlc3NMb2dJbnRlcmNlcHRvcigpLFxuXHRcdG5ldyBUaW1lb3V0SW50ZXJjZXB0b3IoKVxuXHQpXG5cdGFwcC51c2VHbG9iYWxGaWx0ZXJzKFxuXHRcdG5ldyBVbmtub3dFeGNlcHRpb25GaWx0ZXIoKSxcblx0XHRuZXcgSHR0cEV4Y2VwdGlvbkZpbHRlcigpLFxuXHRcdG5ldyBWYWxpZGF0aW9uRXhjZXB0aW9uRmlsdGVyKClcblx0KVxuXG5cdGFwcC51c2VHbG9iYWxHdWFyZHMobmV3IFVzZXJSb2xlc0d1YXJkKGFwcC5nZXQoUmVmbGVjdG9yKSkpXG5cblx0YXBwLnVzZUdsb2JhbFBpcGVzKG5ldyBWYWxpZGF0aW9uUGlwZSh7XG5cdFx0dmFsaWRhdGlvbkVycm9yOiB7IHRhcmdldDogZmFsc2UsIHZhbHVlOiB0cnVlIH0sXG5cdFx0c2tpcE1pc3NpbmdQcm9wZXJ0aWVzOiB0cnVlLFxuXHRcdGV4Y2VwdGlvbkZhY3Rvcnk6IChlcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdID0gW10pID0+IG5ldyBWYWxpZGF0aW9uRXhjZXB0aW9uKGVycm9ycyksXG5cdH0pKVxuXG5cdGlmIChjb25maWdTZXJ2aWNlLmdldCgnTk9ERV9FTlYnKSAhPT0gJ3Byb2R1Y3Rpb24nKSB7XG5cdFx0c2V0dXBTd2FnZ2VyKGFwcClcblx0fVxuXG5cdGF3YWl0IGFwcC5saXN0ZW4oUE9SVClcbn1cbmJvb3RzdHJhcCgpXG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=