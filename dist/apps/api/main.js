/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./apps/api/src/app.module.ts":
/*!************************************!*\
  !*** ./apps/api/src/app.module.ts ***!
  \************************************/
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
const environments_1 = __webpack_require__(/*! ./environments */ "./apps/api/src/environments.ts");
const logger_middleware_1 = __webpack_require__(/*! ./middlewares/logger.middleware */ "./apps/api/src/middlewares/logger.middleware.ts");
const validate_access_token_middleware_1 = __webpack_require__(/*! ./middlewares/validate-access-token.middleware */ "./apps/api/src/middlewares/validate-access-token.middleware.ts");
const auth_module_1 = __webpack_require__(/*! ./modules/auth/auth.module */ "./apps/api/src/modules/auth/auth.module.ts");
const clinic_module_1 = __webpack_require__(/*! ./modules/clinic/clinic.module */ "./apps/api/src/modules/clinic/clinic.module.ts");
const employee_module_1 = __webpack_require__(/*! ./modules/employee/employee.module */ "./apps/api/src/modules/employee/employee.module.ts");
const medicine_module_1 = __webpack_require__(/*! ./modules/medicine/medicine.module */ "./apps/api/src/modules/medicine/medicine.module.ts");
const patient_module_1 = __webpack_require__(/*! ./modules/patient/patient.module */ "./apps/api/src/modules/patient/patient.module.ts");
let AppModule = class AppModule {
    constructor(dataSource) {
        this.dataSource = dataSource;
    }
    configure(consumer) {
        consumer.apply(logger_middleware_1.LoggerMiddleware).forRoutes('*');
        consumer.apply(validate_access_token_middleware_1.ValidateAccessTokenMiddleware)
            .exclude('auth/(.*)', '/')
            .forRoutes('*');
    }
};
AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                envFilePath: [`.env.${process.env.NODE_ENV || 'local'}`, '.env'],
                isGlobal: true,
            }),
            typeorm_1.TypeOrmModule.forRootAsync({
                imports: [config_1.ConfigModule.forFeature(environments_1.MariadbConfig)],
                inject: [environments_1.MariadbConfig.KEY],
                useFactory: (mariadbConfig) => mariadbConfig,
            }),
            auth_module_1.AuthModule,
            clinic_module_1.ClinicModule,
            medicine_module_1.MedicineModule,
            employee_module_1.EmployeeModule,
            patient_module_1.PatientModule,
        ],
    }),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.DataSource !== "undefined" && typeorm_2.DataSource) === "function" ? _a : Object])
], AppModule);
exports.AppModule = AppModule;


/***/ }),

/***/ "./apps/api/src/common/class-validator.custom.ts":
/*!*******************************************************!*\
  !*** ./apps/api/src/common/class-validator.custom.ts ***!
  \*******************************************************/
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

/***/ "./apps/api/src/common/constants.ts":
/*!******************************************!*\
  !*** ./apps/api/src/common/constants.ts ***!
  \******************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./apps/api/src/common/swagger.ts":
/*!****************************************!*\
  !*** ./apps/api/src/common/swagger.ts ***!
  \****************************************/
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

/***/ "./apps/api/src/environments.ts":
/*!**************************************!*\
  !*** ./apps/api/src/environments.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MariadbConfig = exports.JwtConfig = void 0;
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
exports.JwtConfig = (0, config_1.registerAs)('jwt', () => ({
    accessKey: process.env.JWT_ACCESS_KEY,
    refreshKey: process.env.JWT_REFRESH_KEY,
    accessTime: Number(process.env.JWT_ACCESS_TIME),
    refreshTime: Number(process.env.JWT_REFRESH_TIME),
}));
exports.MariadbConfig = (0, config_1.registerAs)('mariadb', () => ({
    type: 'mariadb',
    host: process.env.MARIADB_HOST,
    port: parseInt(process.env.MARIADB_PORT, 10),
    database: process.env.MARIADB_DATABASE,
    username: process.env.MARIADB_USERNAME,
    password: process.env.MARIADB_PASSWORD,
    autoLoadEntities: true,
    logging: process.env.NODE_ENV !== 'production',
    synchronize: process.env.NODE_ENV === 'local',
}));


/***/ }),

/***/ "./apps/api/src/exception-filters/exception.enum.ts":
/*!**********************************************************!*\
  !*** ./apps/api/src/exception-filters/exception.enum.ts ***!
  \**********************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EEmployeeError = exports.ETokenError = exports.ELoginError = exports.ERegisterError = exports.EValidateError = exports.EError = void 0;
var EError;
(function (EError) {
    EError["Unknown"] = "A00.UNKNOWN";
})(EError = exports.EError || (exports.EError = {}));
var EValidateError;
(function (EValidateError) {
    EValidateError["Failed"] = "V00.VALIDATE_FAILED";
})(EValidateError = exports.EValidateError || (exports.EValidateError = {}));
var ERegisterError;
(function (ERegisterError) {
    ERegisterError["ExistEmailAndPhone"] = "R01.EXIST_EMAIL_AND_PHONE";
    ERegisterError["ExistEmail"] = "R02.EXIST_EMAIL";
    ERegisterError["ExistPhone"] = "R03.EXIST_PHONE";
    ERegisterError["ExistUsername"] = "R04.EXIST_USERNAME";
})(ERegisterError = exports.ERegisterError || (exports.ERegisterError = {}));
var ELoginError;
(function (ELoginError) {
    ELoginError["EmployeeDoesNotExist"] = "L01.EMPLOYEE_DOES_NOT_EXIST";
    ELoginError["WrongPassword"] = "L02.WRONG_PASSWORD";
})(ELoginError = exports.ELoginError || (exports.ELoginError = {}));
var ETokenError;
(function (ETokenError) {
    ETokenError["Expired"] = "T01.EXPIRED";
    ETokenError["Invalid"] = "T02.INVALID";
})(ETokenError = exports.ETokenError || (exports.ETokenError = {}));
var EEmployeeError;
(function (EEmployeeError) {
    EEmployeeError["UsernameExists"] = "U01.USERNAME_EXISTS";
    EEmployeeError["NotExists"] = "U02.EMPLOYEE_DOES_NOT_EXIST";
})(EEmployeeError = exports.EEmployeeError || (exports.EEmployeeError = {}));


/***/ }),

/***/ "./apps/api/src/exception-filters/http-exception.filter.ts":
/*!*****************************************************************!*\
  !*** ./apps/api/src/exception-filters/http-exception.filter.ts ***!
  \*****************************************************************/
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
            path: request.url,
            timestamp: new Date().toISOString(),
        });
    }
};
HttpExceptionFilter = __decorate([
    (0, common_1.Catch)(common_1.HttpException)
], HttpExceptionFilter);
exports.HttpExceptionFilter = HttpExceptionFilter;


/***/ }),

/***/ "./apps/api/src/exception-filters/unknown-exception.filter.ts":
/*!********************************************************************!*\
  !*** ./apps/api/src/exception-filters/unknown-exception.filter.ts ***!
  \********************************************************************/
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
exports.UnknownExceptionFilter = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let UnknownExceptionFilter = class UnknownExceptionFilter {
    constructor(logger = new common_1.Logger('SERVER_ERROR')) {
        this.logger = logger;
    }
    catch(exception, host) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse();
        const request = ctx.getRequest();
        const httpStatus = common_1.HttpStatus.INTERNAL_SERVER_ERROR;
        this.logger.error(exception.stack);
        response.status(httpStatus).json({
            httpStatus,
            message: exception.message,
            path: request.url,
            timestamp: new Date().toISOString(),
        });
    }
};
UnknownExceptionFilter = __decorate([
    (0, common_1.Catch)(Error),
    __metadata("design:paramtypes", [Object])
], UnknownExceptionFilter);
exports.UnknownExceptionFilter = UnknownExceptionFilter;


/***/ }),

/***/ "./apps/api/src/exception-filters/validation-exception.filter.ts":
/*!***********************************************************************!*\
  !*** ./apps/api/src/exception-filters/validation-exception.filter.ts ***!
  \***********************************************************************/
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
const exception_enum_1 = __webpack_require__(/*! ./exception.enum */ "./apps/api/src/exception-filters/exception.enum.ts");
class ValidationException extends Error {
    constructor(validationErrors = []) {
        super(exception_enum_1.EValidateError.Failed);
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
        const httpStatus = common_1.HttpStatus.UNPROCESSABLE_ENTITY;
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

/***/ "./apps/api/src/guards/user-roles.guard.ts":
/*!*************************************************!*\
  !*** ./apps/api/src/guards/user-roles.guard.ts ***!
  \*************************************************/
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

/***/ "./apps/api/src/interceptor/access-log.interceptor.ts":
/*!************************************************************!*\
  !*** ./apps/api/src/interceptor/access-log.interceptor.ts ***!
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

/***/ "./apps/api/src/interceptor/timeout.interceptor.ts":
/*!*********************************************************!*\
  !*** ./apps/api/src/interceptor/timeout.interceptor.ts ***!
  \*********************************************************/
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

/***/ "./apps/api/src/middlewares/logger.middleware.ts":
/*!*******************************************************!*\
  !*** ./apps/api/src/middlewares/logger.middleware.ts ***!
  \*******************************************************/
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

/***/ "./apps/api/src/middlewares/validate-access-token.middleware.ts":
/*!**********************************************************************!*\
  !*** ./apps/api/src/middlewares/validate-access-token.middleware.ts ***!
  \**********************************************************************/
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
const jwt_extend_service_1 = __webpack_require__(/*! ../modules/auth/jwt-extend.service */ "./apps/api/src/modules/auth/jwt-extend.service.ts");
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

/***/ "./apps/api/src/modules/auth/auth.controller.ts":
/*!******************************************************!*\
  !*** ./apps/api/src/modules/auth/auth.controller.ts ***!
  \******************************************************/
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
var _a, _b, _c, _d, _e, _f, _g;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const express_1 = __webpack_require__(/*! express */ "express");
const request_ip_1 = __webpack_require__(/*! request-ip */ "request-ip");
const auth_dto_1 = __webpack_require__(/*! ./auth.dto */ "./apps/api/src/modules/auth/auth.dto.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/api/src/modules/auth/auth.service.ts");
const jwt_extend_service_1 = __webpack_require__(/*! ./jwt-extend.service */ "./apps/api/src/modules/auth/jwt-extend.service.ts");
let AuthController = class AuthController {
    constructor(authService, jwtExtendService) {
        this.authService = authService;
        this.jwtExtendService = jwtExtendService;
    }
    async register(registerDto, request) {
        const ip = (0, request_ip_1.getClientIp)(request);
        const employee = await this.authService.register(registerDto);
        const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee);
        return { accessToken, refreshToken };
    }
    async login(loginDto) {
        const employee = await this.authService.login(loginDto);
        const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee);
        return { accessToken, refreshToken };
    }
    logout(id) {
    }
    changePassword(id, updateAuthDto) {
    }
    forgotPassword(id) {
    }
    async grantAccessToken(refreshTokenDto) {
        const accessToken = await this.authService.grantAccessToken(refreshTokenDto.refreshToken);
        return { accessToken };
    }
};
__decorate([
    (0, common_1.Post)('register'),
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
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_1.Post)('change-password'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_f = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _f : Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "changePassword", null);
__decorate([
    (0, common_1.Post)('forgot-password'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "forgotPassword", null);
__decorate([
    (0, common_1.Post)('refresh-token'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_g = typeof auth_dto_1.RefreshTokenDto !== "undefined" && auth_dto_1.RefreshTokenDto) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "grantAccessToken", null);
AuthController = __decorate([
    (0, swagger_1.ApiTags)('Auth'),
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof jwt_extend_service_1.JwtExtendService !== "undefined" && jwt_extend_service_1.JwtExtendService) === "function" ? _b : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),

/***/ "./apps/api/src/modules/auth/auth.dto.ts":
/*!***********************************************!*\
  !*** ./apps/api/src/modules/auth/auth.dto.ts ***!
  \***********************************************/
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
exports.RefreshTokenDto = exports.LoginDto = exports.RegisterDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const class_validator_custom_1 = __webpack_require__(/*! ../../common/class-validator.custom */ "./apps/api/src/common/class-validator.custom.ts");
class RegisterDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'example-clinic@gmail.com' }),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsGmail),
    __metadata("design:type", String)
], RegisterDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: '0986021190' }),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsPhone),
    __metadata("design:type", String)
], RegisterDto.prototype, "phone", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'admin' }),
    (0, class_validator_1.IsDefined)(),
    __metadata("design:type", String)
], RegisterDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], RegisterDto.prototype, "password", void 0);
exports.RegisterDto = RegisterDto;
class LoginDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ example: '0986021190' }),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.Length)(10, 10),
    __metadata("design:type", String)
], LoginDto.prototype, "cPhone", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'admin' }),
    (0, class_validator_1.IsDefined)(),
    __metadata("design:type", String)
], LoginDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], LoginDto.prototype, "password", void 0);
exports.LoginDto = LoginDto;
class RefreshTokenDto {
}
__decorate([
    (0, swagger_1.ApiProperty)(),
    (0, class_validator_1.IsDefined)(),
    __metadata("design:type", String)
], RefreshTokenDto.prototype, "refreshToken", void 0);
exports.RefreshTokenDto = RefreshTokenDto;


/***/ }),

/***/ "./apps/api/src/modules/auth/auth.module.ts":
/*!**************************************************!*\
  !*** ./apps/api/src/modules/auth/auth.module.ts ***!
  \**************************************************/
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
const clinic_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/clinic.entity */ "./typeorm/entities/clinic.entity.ts");
const employee_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/employee.entity */ "./typeorm/entities/employee.entity.ts");
const environments_1 = __webpack_require__(/*! ../../environments */ "./apps/api/src/environments.ts");
const auth_controller_1 = __webpack_require__(/*! ./auth.controller */ "./apps/api/src/modules/auth/auth.controller.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/api/src/modules/auth/auth.service.ts");
const jwt_extend_service_1 = __webpack_require__(/*! ./jwt-extend.service */ "./apps/api/src/modules/auth/jwt-extend.service.ts");
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([clinic_entity_1.default, employee_entity_1.default]),
            config_1.ConfigModule.forFeature(environments_1.JwtConfig),
            jwt_1.JwtModule,
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, jwt_extend_service_1.JwtExtendService],
        exports: [jwt_extend_service_1.JwtExtendService],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ "./apps/api/src/modules/auth/auth.service.ts":
/*!***************************************************!*\
  !*** ./apps/api/src/modules/auth/auth.service.ts ***!
  \***************************************************/
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
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const bcrypt = __webpack_require__(/*! bcrypt */ "bcrypt");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const clinic_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/clinic.entity */ "./typeorm/entities/clinic.entity.ts");
const employee_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/employee.entity */ "./typeorm/entities/employee.entity.ts");
const exception_enum_1 = __webpack_require__(/*! ../../exception-filters/exception.enum */ "./apps/api/src/exception-filters/exception.enum.ts");
const jwt_extend_service_1 = __webpack_require__(/*! ./jwt-extend.service */ "./apps/api/src/modules/auth/jwt-extend.service.ts");
let AuthService = class AuthService {
    constructor(dataSource, jwtExtendService) {
        this.dataSource = dataSource;
        this.jwtExtendService = jwtExtendService;
    }
    async register(registerDto) {
        const { email, phone, username, password } = registerDto;
        const hashPassword = await bcrypt.hash(password, 5);
        const employee = await this.dataSource.transaction(async (manager) => {
            const findClinic = await manager.findOne(clinic_entity_1.default, { where: [{ email }, { phone }] });
            if (findClinic) {
                if (findClinic.email === email && findClinic.phone === phone) {
                    throw new common_1.HttpException(exception_enum_1.ERegisterError.ExistEmailAndPhone, common_1.HttpStatus.BAD_REQUEST);
                }
                else if (findClinic.email === email) {
                    throw new common_1.HttpException(exception_enum_1.ERegisterError.ExistEmail, common_1.HttpStatus.BAD_REQUEST);
                }
                else if (findClinic.phone === phone) {
                    throw new common_1.HttpException(exception_enum_1.ERegisterError.ExistPhone, common_1.HttpStatus.BAD_REQUEST);
                }
            }
            const snapClinic = manager.create(clinic_entity_1.default, {
                phone,
                email,
                level: 1,
            });
            const newClinic = await manager.save(snapClinic);
            const snapEmployee = manager.create(employee_entity_1.default, {
                clinicId: newClinic.id,
                username,
                password: hashPassword,
                role: employee_entity_1.EEmployeeRole.Owner,
            });
            const newEmployee = await manager.save(snapEmployee);
            newEmployee.clinic = newClinic;
            return newEmployee;
        });
        return employee;
    }
    async login(loginDto) {
        const employee = await this.dataSource.getRepository(employee_entity_1.default)
            .createQueryBuilder('employee')
            .leftJoinAndSelect('employee.clinic', 'clinic')
            .where('username = :username', { username: loginDto.username })
            .andWhere('clinic.phone = :cPhone', { cPhone: loginDto.cPhone })
            .getOne();
        if (!employee) {
            throw new common_1.HttpException(exception_enum_1.ELoginError.EmployeeDoesNotExist, common_1.HttpStatus.BAD_REQUEST);
        }
        const checkPassword = await bcrypt.compare(loginDto.password, employee.password);
        if (!checkPassword) {
            throw new common_1.HttpException(exception_enum_1.ELoginError.WrongPassword, common_1.HttpStatus.BAD_GATEWAY);
        }
        return employee;
    }
    async grantAccessToken(refreshToken) {
        const { uid } = this.jwtExtendService.verifyRefreshToken(refreshToken);
        const employee = await this.dataSource.getRepository(employee_entity_1.default)
            .createQueryBuilder('employee')
            .leftJoinAndSelect('employee.clinic', 'clinic')
            .where('employee.id = :id', { id: uid })
            .getOne();
        const accessToken = this.jwtExtendService.createAccessToken(employee);
        return accessToken;
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_1.DataSource !== "undefined" && typeorm_1.DataSource) === "function" ? _a : Object, typeof (_b = typeof jwt_extend_service_1.JwtExtendService !== "undefined" && jwt_extend_service_1.JwtExtendService) === "function" ? _b : Object])
], AuthService);
exports.AuthService = AuthService;


/***/ }),

/***/ "./apps/api/src/modules/auth/jwt-extend.service.ts":
/*!*********************************************************!*\
  !*** ./apps/api/src/modules/auth/jwt-extend.service.ts ***!
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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtExtendService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const environments_1 = __webpack_require__(/*! ../../environments */ "./apps/api/src/environments.ts");
const exception_enum_1 = __webpack_require__(/*! ../../exception-filters/exception.enum */ "./apps/api/src/exception-filters/exception.enum.ts");
let JwtExtendService = class JwtExtendService {
    constructor(jwtConfig, jwtService) {
        this.jwtConfig = jwtConfig;
        this.jwtService = jwtService;
    }
    createAccessToken(user) {
        const userPayload = {
            cPhone: user.clinic.phone,
            cid: user.clinic.id,
            uid: user.id,
            username: user.username,
            role: user.role,
        };
        return this.jwtService.sign(userPayload, {
            secret: this.jwtConfig.accessKey,
            expiresIn: this.jwtConfig.accessTime,
        });
    }
    createRefreshToken(uid) {
        return this.jwtService.sign({ uid }, {
            secret: this.jwtConfig.refreshKey,
            expiresIn: this.jwtConfig.refreshTime,
        });
    }
    createTokenFromUser(user) {
        const accessToken = this.createAccessToken(user);
        const refreshToken = this.createRefreshToken(user.id);
        return { accessToken, refreshToken };
    }
    verifyAccessToken(accessToken) {
        try {
            return this.jwtService.verify(accessToken, { secret: this.jwtConfig.accessKey });
        }
        catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new common_1.HttpException(exception_enum_1.ETokenError.Expired, common_1.HttpStatus.UNAUTHORIZED);
            }
            else if (error.name === 'JsonWebTokenError') {
                throw new common_1.HttpException(exception_enum_1.ETokenError.Invalid, common_1.HttpStatus.UNAUTHORIZED);
            }
            throw new common_1.HttpException(exception_enum_1.EError.Unknown, common_1.HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    verifyRefreshToken(refreshToken) {
        try {
            return this.jwtService.verify(refreshToken, { secret: this.jwtConfig.refreshKey });
        }
        catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new common_1.HttpException(exception_enum_1.ETokenError.Expired, common_1.HttpStatus.FORBIDDEN);
            }
            else if (error.name === 'JsonWebTokenError') {
                throw new common_1.HttpException(exception_enum_1.ETokenError.Invalid, common_1.HttpStatus.FORBIDDEN);
            }
            throw new common_1.HttpException(exception_enum_1.EError.Unknown, common_1.HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
};
JwtExtendService = __decorate([
    __param(0, (0, common_1.Inject)(environments_1.JwtConfig.KEY)),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigType !== "undefined" && config_1.ConfigType) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object])
], JwtExtendService);
exports.JwtExtendService = JwtExtendService;


/***/ }),

/***/ "./apps/api/src/modules/clinic/clinic.controller.ts":
/*!**********************************************************!*\
  !*** ./apps/api/src/modules/clinic/clinic.controller.ts ***!
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
exports.ClinicController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const clinic_service_1 = __webpack_require__(/*! ./clinic.service */ "./apps/api/src/modules/clinic/clinic.service.ts");
const clinic_dto_1 = __webpack_require__(/*! ./clinic.dto */ "./apps/api/src/modules/clinic/clinic.dto.ts");
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

/***/ "./apps/api/src/modules/clinic/clinic.dto.ts":
/*!***************************************************!*\
  !*** ./apps/api/src/modules/clinic/clinic.dto.ts ***!
  \***************************************************/
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

/***/ "./apps/api/src/modules/clinic/clinic.module.ts":
/*!******************************************************!*\
  !*** ./apps/api/src/modules/clinic/clinic.module.ts ***!
  \******************************************************/
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
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const clinic_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/clinic.entity */ "./typeorm/entities/clinic.entity.ts");
const clinic_controller_1 = __webpack_require__(/*! ./clinic.controller */ "./apps/api/src/modules/clinic/clinic.controller.ts");
const clinic_service_1 = __webpack_require__(/*! ./clinic.service */ "./apps/api/src/modules/clinic/clinic.service.ts");
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

/***/ "./apps/api/src/modules/clinic/clinic.service.ts":
/*!*******************************************************!*\
  !*** ./apps/api/src/modules/clinic/clinic.service.ts ***!
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
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClinicService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const clinic_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/clinic.entity */ "./typeorm/entities/clinic.entity.ts");
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

/***/ "./apps/api/src/modules/employee/employee.controller.ts":
/*!**************************************************************!*\
  !*** ./apps/api/src/modules/employee/employee.controller.ts ***!
  \**************************************************************/
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
var _a, _b, _c, _d, _e, _f, _g, _h, _j;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmployeeController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const decorators_1 = __webpack_require__(/*! @nestjs/common/decorators */ "@nestjs/common/decorators");
const serializer_1 = __webpack_require__(/*! @nestjs/common/serializer */ "@nestjs/common/serializer");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const constants_1 = __webpack_require__(/*! ../../common/constants */ "./apps/api/src/common/constants.ts");
const employee_dto_1 = __webpack_require__(/*! ./employee.dto */ "./apps/api/src/modules/employee/employee.dto.ts");
const employee_service_1 = __webpack_require__(/*! ./employee.service */ "./apps/api/src/modules/employee/employee.service.ts");
let EmployeeController = class EmployeeController {
    constructor(employeeService) {
        this.employeeService = employeeService;
    }
    findAll(request) {
        const clinicId = request.tokenPayload.cid;
        return this.employeeService.findAll(clinicId);
    }
    create(createEmployeeDto, request) {
        const clinicId = request.tokenPayload.cid;
        return this.employeeService.create(clinicId, createEmployeeDto);
    }
    findOne(id, request) {
        const clinicId = request.tokenPayload.cid;
        return this.employeeService.findOne(clinicId, +id);
    }
    async update(id, request, updateEmployeeDto) {
        const clinicId = request.tokenPayload.cid;
        await this.employeeService.update(clinicId, +id, updateEmployeeDto);
        return { message: 'success' };
    }
    async remove(id, request) {
        const clinicId = request.tokenPayload.cid;
        await this.employeeService.remove(clinicId, +id);
        return { message: 'success' };
    }
    async restore(id, request) {
        const clinicId = request.tokenPayload.cid;
        await this.employeeService.restore(clinicId, +id);
        return { message: 'success' };
    }
};
__decorate([
    (0, common_1.Get)(),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _b : Object]),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "findAll", null);
__decorate([
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof employee_dto_1.CreateEmployeeDto !== "undefined" && employee_dto_1.CreateEmployeeDto) === "function" ? _c : Object, typeof (_d = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _d : Object]),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_e = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _e : Object]),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "findOne", null);
__decorate([
    (0, common_1.Patch)('update/:id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_f = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _f : Object, typeof (_g = typeof employee_dto_1.UpdateEmployeeDto !== "undefined" && employee_dto_1.UpdateEmployeeDto) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], EmployeeController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)('remove/:id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_h = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _h : Object]),
    __metadata("design:returntype", Promise)
], EmployeeController.prototype, "remove", null);
__decorate([
    (0, common_1.Patch)('restore/:id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_j = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _j : Object]),
    __metadata("design:returntype", Promise)
], EmployeeController.prototype, "restore", null);
EmployeeController = __decorate([
    (0, swagger_1.ApiTags)('Employee'),
    (0, swagger_1.ApiBearerAuth)('access-token'),
    (0, decorators_1.UseInterceptors)(serializer_1.ClassSerializerInterceptor),
    (0, common_1.Controller)('employee'),
    __metadata("design:paramtypes", [typeof (_a = typeof employee_service_1.EmployeeService !== "undefined" && employee_service_1.EmployeeService) === "function" ? _a : Object])
], EmployeeController);
exports.EmployeeController = EmployeeController;


/***/ }),

/***/ "./apps/api/src/modules/employee/employee.dto.ts":
/*!*******************************************************!*\
  !*** ./apps/api/src/modules/employee/employee.dto.ts ***!
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
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateEmployeeDto = exports.CreateEmployeeDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class CreateEmployeeDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'nhatduong2019' }),
    (0, class_validator_1.IsDefined)(),
    __metadata("design:type", String)
], CreateEmployeeDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], CreateEmployeeDto.prototype, "password", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Ngô Nhật Dương' }),
    __metadata("design:type", String)
], CreateEmployeeDto.prototype, "fullName", void 0);
exports.CreateEmployeeDto = CreateEmployeeDto;
class UpdateEmployeeDto extends (0, swagger_1.PartialType)(CreateEmployeeDto) {
}
exports.UpdateEmployeeDto = UpdateEmployeeDto;


/***/ }),

/***/ "./apps/api/src/modules/employee/employee.module.ts":
/*!**********************************************************!*\
  !*** ./apps/api/src/modules/employee/employee.module.ts ***!
  \**********************************************************/
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
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const employee_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/employee.entity */ "./typeorm/entities/employee.entity.ts");
const employee_controller_1 = __webpack_require__(/*! ./employee.controller */ "./apps/api/src/modules/employee/employee.controller.ts");
const employee_service_1 = __webpack_require__(/*! ./employee.service */ "./apps/api/src/modules/employee/employee.service.ts");
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

/***/ "./apps/api/src/modules/employee/employee.service.ts":
/*!***********************************************************!*\
  !*** ./apps/api/src/modules/employee/employee.service.ts ***!
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
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmployeeService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const enums_1 = __webpack_require__(/*! @nestjs/common/enums */ "@nestjs/common/enums");
const exceptions_1 = __webpack_require__(/*! @nestjs/common/exceptions */ "@nestjs/common/exceptions");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const bcrypt = __webpack_require__(/*! bcrypt */ "bcrypt");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const employee_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/employee.entity */ "./typeorm/entities/employee.entity.ts");
const exception_enum_1 = __webpack_require__(/*! ../../exception-filters/exception.enum */ "./apps/api/src/exception-filters/exception.enum.ts");
let EmployeeService = class EmployeeService {
    constructor(employeeRepository) {
        this.employeeRepository = employeeRepository;
    }
    async findAll(clinicId) {
        return await this.employeeRepository.find({ where: { clinicId } });
    }
    async create(clinicId, createEmployeeDto) {
        const findEmployee = await this.employeeRepository.findOneBy({
            clinicId,
            username: createEmployeeDto.username,
        });
        if (findEmployee) {
            throw new exceptions_1.HttpException(exception_enum_1.ERegisterError.ExistUsername, enums_1.HttpStatus.BAD_REQUEST);
        }
        const snapEmployee = (0, class_transformer_1.plainToClass)(employee_entity_1.default, createEmployeeDto);
        snapEmployee.password = await bcrypt.hash(createEmployeeDto.password, 5);
        snapEmployee.role = employee_entity_1.EEmployeeRole.User;
        return await this.employeeRepository.save(createEmployeeDto);
    }
    async findOne(clinicId, id) {
        return await this.employeeRepository.findOneBy({ clinicId, id });
    }
    async update(clinicId, id, updateEmployeeDto) {
        const findEmployee = await this.employeeRepository.findOneBy({ clinicId, id });
        if (!findEmployee) {
            throw new exceptions_1.HttpException(exception_enum_1.EEmployeeError.NotExists, enums_1.HttpStatus.BAD_REQUEST);
        }
        return await this.employeeRepository.update({ clinicId, id }, updateEmployeeDto);
    }
    async remove(clinicId, employeeId) {
        return await this.employeeRepository.softDelete({
            clinicId,
            id: employeeId,
        });
    }
    async restore(clinicId, employeeId) {
        return await this.employeeRepository.restore({
            clinicId,
            id: employeeId,
        });
    }
};
EmployeeService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(employee_entity_1.default)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object])
], EmployeeService);
exports.EmployeeService = EmployeeService;


/***/ }),

/***/ "./apps/api/src/modules/medicine/dto/create-medicine.dto.ts":
/*!******************************************************************!*\
  !*** ./apps/api/src/modules/medicine/dto/create-medicine.dto.ts ***!
  \******************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateMedicineDto = void 0;
class CreateMedicineDto {
}
exports.CreateMedicineDto = CreateMedicineDto;


/***/ }),

/***/ "./apps/api/src/modules/medicine/dto/update-medicine.dto.ts":
/*!******************************************************************!*\
  !*** ./apps/api/src/modules/medicine/dto/update-medicine.dto.ts ***!
  \******************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateMedicineDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const create_medicine_dto_1 = __webpack_require__(/*! ./create-medicine.dto */ "./apps/api/src/modules/medicine/dto/create-medicine.dto.ts");
class UpdateMedicineDto extends (0, swagger_1.PartialType)(create_medicine_dto_1.CreateMedicineDto) {
}
exports.UpdateMedicineDto = UpdateMedicineDto;


/***/ }),

/***/ "./apps/api/src/modules/medicine/medicine.controller.ts":
/*!**************************************************************!*\
  !*** ./apps/api/src/modules/medicine/medicine.controller.ts ***!
  \**************************************************************/
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
const create_medicine_dto_1 = __webpack_require__(/*! ./dto/create-medicine.dto */ "./apps/api/src/modules/medicine/dto/create-medicine.dto.ts");
const update_medicine_dto_1 = __webpack_require__(/*! ./dto/update-medicine.dto */ "./apps/api/src/modules/medicine/dto/update-medicine.dto.ts");
const medicine_service_1 = __webpack_require__(/*! ./medicine.service */ "./apps/api/src/modules/medicine/medicine.service.ts");
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

/***/ "./apps/api/src/modules/medicine/medicine.module.ts":
/*!**********************************************************!*\
  !*** ./apps/api/src/modules/medicine/medicine.module.ts ***!
  \**********************************************************/
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
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const medicine_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/medicine.entity */ "./typeorm/entities/medicine.entity.ts");
const medicine_controller_1 = __webpack_require__(/*! ./medicine.controller */ "./apps/api/src/modules/medicine/medicine.controller.ts");
const medicine_service_1 = __webpack_require__(/*! ./medicine.service */ "./apps/api/src/modules/medicine/medicine.service.ts");
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

/***/ "./apps/api/src/modules/medicine/medicine.service.ts":
/*!***********************************************************!*\
  !*** ./apps/api/src/modules/medicine/medicine.service.ts ***!
  \***********************************************************/
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

/***/ "./apps/api/src/modules/patient/dto/create-patient.dto.ts":
/*!****************************************************************!*\
  !*** ./apps/api/src/modules/patient/dto/create-patient.dto.ts ***!
  \****************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreatePatientDto = void 0;
class CreatePatientDto {
}
exports.CreatePatientDto = CreatePatientDto;


/***/ }),

/***/ "./apps/api/src/modules/patient/dto/update-patient.dto.ts":
/*!****************************************************************!*\
  !*** ./apps/api/src/modules/patient/dto/update-patient.dto.ts ***!
  \****************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdatePatientDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const create_patient_dto_1 = __webpack_require__(/*! ./create-patient.dto */ "./apps/api/src/modules/patient/dto/create-patient.dto.ts");
class UpdatePatientDto extends (0, swagger_1.PartialType)(create_patient_dto_1.CreatePatientDto) {
}
exports.UpdatePatientDto = UpdatePatientDto;


/***/ }),

/***/ "./apps/api/src/modules/patient/patient.controller.ts":
/*!************************************************************!*\
  !*** ./apps/api/src/modules/patient/patient.controller.ts ***!
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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PatientController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const patient_service_1 = __webpack_require__(/*! ./patient.service */ "./apps/api/src/modules/patient/patient.service.ts");
const create_patient_dto_1 = __webpack_require__(/*! ./dto/create-patient.dto */ "./apps/api/src/modules/patient/dto/create-patient.dto.ts");
const update_patient_dto_1 = __webpack_require__(/*! ./dto/update-patient.dto */ "./apps/api/src/modules/patient/dto/update-patient.dto.ts");
let PatientController = class PatientController {
    constructor(patientService) {
        this.patientService = patientService;
    }
    create(createPatientDto) {
        return this.patientService.create(createPatientDto);
    }
    findAll() {
        return this.patientService.findAll();
    }
    findOne(id) {
        return this.patientService.findOne(+id);
    }
    update(id, updatePatientDto) {
        return this.patientService.update(+id, updatePatientDto);
    }
    remove(id) {
        return this.patientService.remove(+id);
    }
};
__decorate([
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof create_patient_dto_1.CreatePatientDto !== "undefined" && create_patient_dto_1.CreatePatientDto) === "function" ? _b : Object]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "findOne", null);
__decorate([
    (0, common_1.Patch)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_c = typeof update_patient_dto_1.UpdatePatientDto !== "undefined" && update_patient_dto_1.UpdatePatientDto) === "function" ? _c : Object]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "remove", null);
PatientController = __decorate([
    (0, common_1.Controller)('patient'),
    __metadata("design:paramtypes", [typeof (_a = typeof patient_service_1.PatientService !== "undefined" && patient_service_1.PatientService) === "function" ? _a : Object])
], PatientController);
exports.PatientController = PatientController;


/***/ }),

/***/ "./apps/api/src/modules/patient/patient.module.ts":
/*!********************************************************!*\
  !*** ./apps/api/src/modules/patient/patient.module.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PatientModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const patient_service_1 = __webpack_require__(/*! ./patient.service */ "./apps/api/src/modules/patient/patient.service.ts");
const patient_controller_1 = __webpack_require__(/*! ./patient.controller */ "./apps/api/src/modules/patient/patient.controller.ts");
let PatientModule = class PatientModule {
};
PatientModule = __decorate([
    (0, common_1.Module)({
        controllers: [patient_controller_1.PatientController],
        providers: [patient_service_1.PatientService]
    })
], PatientModule);
exports.PatientModule = PatientModule;


/***/ }),

/***/ "./apps/api/src/modules/patient/patient.service.ts":
/*!*********************************************************!*\
  !*** ./apps/api/src/modules/patient/patient.service.ts ***!
  \*********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PatientService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let PatientService = class PatientService {
    create(createPatientDto) {
        return 'This action adds a new patient';
    }
    findAll() {
        return `This action returns all patient`;
    }
    findOne(id) {
        return `This action returns a #${id} patient`;
    }
    update(id, updatePatientDto) {
        return `This action updates a #${id} patient`;
    }
    remove(id) {
        return `This action removes a #${id} patient`;
    }
};
PatientService = __decorate([
    (0, common_1.Injectable)()
], PatientService);
exports.PatientService = PatientService;


/***/ }),

/***/ "./typeorm/base.entity.ts":
/*!********************************!*\
  !*** ./typeorm/base.entity.ts ***!
  \********************************/
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
exports.BaseEntity = BaseEntity;


/***/ }),

/***/ "./typeorm/entities/clinic.entity.ts":
/*!*******************************************!*\
  !*** ./typeorm/entities/clinic.entity.ts ***!
  \*******************************************/
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
const base_entity_1 = __webpack_require__(/*! ../base.entity */ "./typeorm/base.entity.ts");
let ClinicEntity = class ClinicEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ unique: true, length: 10, nullable: false }),
    __metadata("design:type", String)
], ClinicEntity.prototype, "phone", void 0);
__decorate([
    (0, typeorm_1.Column)({ unique: true, nullable: false }),
    __metadata("design:type", String)
], ClinicEntity.prototype, "email", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'tinyint', default: 1 }),
    __metadata("design:type", Number)
], ClinicEntity.prototype, "level", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], ClinicEntity.prototype, "name", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], ClinicEntity.prototype, "address", void 0);
ClinicEntity = __decorate([
    (0, typeorm_1.Entity)('clinic')
], ClinicEntity);
exports["default"] = ClinicEntity;


/***/ }),

/***/ "./typeorm/entities/employee.entity.ts":
/*!*********************************************!*\
  !*** ./typeorm/entities/employee.entity.ts ***!
  \*********************************************/
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
exports.EEmployeeRole = void 0;
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../base.entity */ "./typeorm/base.entity.ts");
const clinic_entity_1 = __webpack_require__(/*! ./clinic.entity */ "./typeorm/entities/clinic.entity.ts");
var EEmployeeRole;
(function (EEmployeeRole) {
    EEmployeeRole["Owner"] = "Owner";
    EEmployeeRole["Admin"] = "Admin";
    EEmployeeRole["User"] = "User";
})(EEmployeeRole = exports.EEmployeeRole || (exports.EEmployeeRole = {}));
let EmployeeEntity = class EmployeeEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ name: 'clinic_id' }),
    __metadata("design:type", Number)
], EmployeeEntity.prototype, "clinicId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(type => clinic_entity_1.default),
    (0, typeorm_1.JoinColumn)({ name: 'clinic_id', referencedColumnName: 'id' }),
    __metadata("design:type", typeof (_a = typeof clinic_entity_1.default !== "undefined" && clinic_entity_1.default) === "function" ? _a : Object)
], EmployeeEntity.prototype, "clinic", void 0);
__decorate([
    (0, typeorm_1.Column)({ length: 10, nullable: true }),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "phone", void 0);
__decorate([
    (0, typeorm_1.Column)(),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "username", void 0);
__decorate([
    (0, typeorm_1.Column)(),
    (0, class_transformer_1.Exclude)(),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "password", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'enum', enum: EEmployeeRole, default: EEmployeeRole.User }),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "role", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'full_name', nullable: true }),
    __metadata("design:type", String)
], EmployeeEntity.prototype, "fullName", void 0);
EmployeeEntity = __decorate([
    (0, typeorm_1.Entity)('employee'),
    (0, typeorm_1.Index)(['clinicId', 'username'], { unique: true })
], EmployeeEntity);
exports["default"] = EmployeeEntity;


/***/ }),

/***/ "./typeorm/entities/medicine.entity.ts":
/*!*********************************************!*\
  !*** ./typeorm/entities/medicine.entity.ts ***!
  \*********************************************/
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
const base_entity_1 = __webpack_require__(/*! ../base.entity */ "./typeorm/base.entity.ts");
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

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/common/decorators":
/*!********************************************!*\
  !*** external "@nestjs/common/decorators" ***!
  \********************************************/
/***/ ((module) => {

module.exports = require("@nestjs/common/decorators");

/***/ }),

/***/ "@nestjs/common/enums":
/*!***************************************!*\
  !*** external "@nestjs/common/enums" ***!
  \***************************************/
/***/ ((module) => {

module.exports = require("@nestjs/common/enums");

/***/ }),

/***/ "@nestjs/common/exceptions":
/*!********************************************!*\
  !*** external "@nestjs/common/exceptions" ***!
  \********************************************/
/***/ ((module) => {

module.exports = require("@nestjs/common/exceptions");

/***/ }),

/***/ "@nestjs/common/serializer":
/*!********************************************!*\
  !*** external "@nestjs/common/serializer" ***!
  \********************************************/
/***/ ((module) => {

module.exports = require("@nestjs/common/serializer");

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

/***/ "class-transformer":
/*!************************************!*\
  !*** external "class-transformer" ***!
  \************************************/
/***/ ((module) => {

module.exports = require("class-transformer");

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
/*!******************************!*\
  !*** ./apps/api/src/main.ts ***!
  \******************************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const express_rate_limit_1 = __webpack_require__(/*! express-rate-limit */ "express-rate-limit");
const helmet_1 = __webpack_require__(/*! helmet */ "helmet");
const requestIp = __webpack_require__(/*! request-ip */ "request-ip");
const app_module_1 = __webpack_require__(/*! ./app.module */ "./apps/api/src/app.module.ts");
const swagger_1 = __webpack_require__(/*! ./common/swagger */ "./apps/api/src/common/swagger.ts");
const http_exception_filter_1 = __webpack_require__(/*! ./exception-filters/http-exception.filter */ "./apps/api/src/exception-filters/http-exception.filter.ts");
const unknown_exception_filter_1 = __webpack_require__(/*! ./exception-filters/unknown-exception.filter */ "./apps/api/src/exception-filters/unknown-exception.filter.ts");
const validation_exception_filter_1 = __webpack_require__(/*! ./exception-filters/validation-exception.filter */ "./apps/api/src/exception-filters/validation-exception.filter.ts");
const user_roles_guard_1 = __webpack_require__(/*! ./guards/user-roles.guard */ "./apps/api/src/guards/user-roles.guard.ts");
const access_log_interceptor_1 = __webpack_require__(/*! ./interceptor/access-log.interceptor */ "./apps/api/src/interceptor/access-log.interceptor.ts");
const timeout_interceptor_1 = __webpack_require__(/*! ./interceptor/timeout.interceptor */ "./apps/api/src/interceptor/timeout.interceptor.ts");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    const configService = app.get(config_1.ConfigService);
    const PORT = configService.get('NESTJS_PORT');
    const HOST = configService.get('NESTJS_HOST') || 'localhost';
    app.use((0, helmet_1.default)());
    app.use((0, express_rate_limit_1.default)({
        windowMs: 60 * 1000,
        max: 100,
    }));
    app.enableCors();
    app.use(requestIp.mw());
    app.useGlobalInterceptors(new access_log_interceptor_1.AccessLogInterceptor(), new timeout_interceptor_1.TimeoutInterceptor());
    app.useGlobalFilters(new unknown_exception_filter_1.UnknownExceptionFilter(), new http_exception_filter_1.HttpExceptionFilter(), new validation_exception_filter_1.ValidationExceptionFilter());
    app.useGlobalGuards(new user_roles_guard_1.UserRolesGuard(app.get(core_1.Reflector)));
    app.useGlobalPipes(new common_1.ValidationPipe({
        validationError: { target: false, value: true },
        skipMissingProperties: true,
        exceptionFactory: (errors = []) => new validation_exception_filter_1.ValidationException(errors),
    }));
    if (configService.get('NODE_ENV') !== 'production') {
        (0, swagger_1.setupSwagger)(app);
    }
    await app.listen(PORT, () => {
        console.log(`🚀 Server document: http://${HOST}:${PORT}/document`);
    });
}
bootstrap();

})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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OEJBQThCLElBQUksSUFBSSxJQUFJLFdBQVcsQ0FBQztJQUNuRSxDQUFDLENBQUM7QUFDSCxDQUFDO0FBQ0QsU0FBUyxFQUFFIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2FwcC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2NvbW1vbi9jbGFzcy12YWxpZGF0b3IuY3VzdG9tLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9jb21tb24vc3dhZ2dlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZW52aXJvbm1lbnRzLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvaHR0cC1leGNlcHRpb24uZmlsdGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy91bmtub3duLWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2V4Y2VwdGlvbi1maWx0ZXJzL3ZhbGlkYXRpb24tZXhjZXB0aW9uLmZpbHRlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZ3VhcmRzL3VzZXItcm9sZXMuZ3VhcmQudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2ludGVyY2VwdG9yL2FjY2Vzcy1sb2cuaW50ZXJjZXB0b3IudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2ludGVyY2VwdG9yL3RpbWVvdXQuaW50ZXJjZXB0b3IudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21pZGRsZXdhcmVzL2xvZ2dlci5taWRkbGV3YXJlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9taWRkbGV3YXJlcy92YWxpZGF0ZS1hY2Nlc3MtdG9rZW4ubWlkZGxld2FyZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGguY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGguZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvY2xpbmljL2NsaW5pYy5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9kdG8vY3JlYXRlLW1lZGljaW5lLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9kdG8vdXBkYXRlLW1lZGljaW5lLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9tZWRpY2luZS5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9tZWRpY2luZS5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL3BhdGllbnQvZHRvL2NyZWF0ZS1wYXRpZW50LmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L2R0by91cGRhdGUtcGF0aWVudC5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50Lm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L3BhdGllbnQuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2Jhc2UuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2VudGl0aWVzL21lZGljaW5lLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbW1vblwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL2RlY29yYXRvcnNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbW1vbi9lbnVtc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbW1vbi9zZXJpYWxpemVyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb25maWdcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvcmVcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2p3dFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvc3dhZ2dlclwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvdHlwZW9ybVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImJjcnlwdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImNsYXNzLXRyYW5zZm9ybWVyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiY2xhc3MtdmFsaWRhdG9yXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiZXhwcmVzc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImV4cHJlc3MtcmF0ZS1saW1pdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImhlbG1ldFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInJlcXVlc3QtaXBcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJyeGpzXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwicnhqcy9vcGVyYXRvcnNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJ0eXBlb3JtXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE1pZGRsZXdhcmVDb25zdW1lciwgTW9kdWxlLCBOZXN0TW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUsIENvbmZpZ1R5cGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IE1hcmlhZGJDb25maWcgfSBmcm9tICcuL2Vudmlyb25tZW50cydcbmltcG9ydCB7IExvZ2dlck1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL2xvZ2dlci5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgVmFsaWRhdGVBY2Nlc3NUb2tlbk1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL3ZhbGlkYXRlLWFjY2Vzcy10b2tlbi5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlJ1xuaW1wb3J0IHsgQ2xpbmljTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlJ1xuaW1wb3J0IHsgRW1wbG95ZWVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlJ1xuaW1wb3J0IHsgTWVkaWNpbmVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlJ1xuaW1wb3J0IHsgUGF0aWVudE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9wYXRpZW50L3BhdGllbnQubW9kdWxlJztcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtcblx0XHRDb25maWdNb2R1bGUuZm9yUm9vdCh7XG5cdFx0XHRlbnZGaWxlUGF0aDogW2AuZW52LiR7cHJvY2Vzcy5lbnYuTk9ERV9FTlYgfHwgJ2xvY2FsJ31gLCAnLmVudiddLFxuXHRcdFx0aXNHbG9iYWw6IHRydWUsXG5cdFx0fSksXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JSb290QXN5bmMoe1xuXHRcdFx0aW1wb3J0czogW0NvbmZpZ01vZHVsZS5mb3JGZWF0dXJlKE1hcmlhZGJDb25maWcpXSxcblx0XHRcdGluamVjdDogW01hcmlhZGJDb25maWcuS0VZXSxcblx0XHRcdHVzZUZhY3Rvcnk6IChtYXJpYWRiQ29uZmlnOiBDb25maWdUeXBlPHR5cGVvZiBNYXJpYWRiQ29uZmlnPikgPT4gbWFyaWFkYkNvbmZpZyxcblx0XHRcdC8vIGluamVjdDogW0NvbmZpZ1NlcnZpY2VdLFxuXHRcdFx0Ly8gdXNlRmFjdG9yeTogKGNvbmZpZ1NlcnZpY2U6IENvbmZpZ1NlcnZpY2UpID0+IGNvbmZpZ1NlcnZpY2UuZ2V0KCdteXNxbCcpLFxuXHRcdH0pLFxuXHRcdEF1dGhNb2R1bGUsXG5cdFx0Q2xpbmljTW9kdWxlLFxuXHRcdE1lZGljaW5lTW9kdWxlLFxuXHRcdEVtcGxveWVlTW9kdWxlLFxuXHRcdFBhdGllbnRNb2R1bGUsXG5cdF0sXG59KVxuZXhwb3J0IGNsYXNzIEFwcE1vZHVsZSBpbXBsZW1lbnRzIE5lc3RNb2R1bGUge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2UpIHsgfVxuXHRjb25maWd1cmUoY29uc3VtZXI6IE1pZGRsZXdhcmVDb25zdW1lcikge1xuXHRcdGNvbnN1bWVyLmFwcGx5KExvZ2dlck1pZGRsZXdhcmUpLmZvclJvdXRlcygnKicpXG5cblx0XHRjb25zdW1lci5hcHBseShWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSlcblx0XHRcdC5leGNsdWRlKCdhdXRoLyguKiknLCAnLycpXG5cdFx0XHQuZm9yUm91dGVzKCcqJylcblx0fVxufVxuIiwiaW1wb3J0IHsgVmFsaWRhdG9yQ29uc3RyYWludCwgVmFsaWRhdG9yQ29uc3RyYWludEludGVyZmFjZSwgVmFsaWRhdGlvbkFyZ3VtZW50cyB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcblxuQFZhbGlkYXRvckNvbnN0cmFpbnQoeyBuYW1lOiAnaXNQaG9uZScsIGFzeW5jOiBmYWxzZSB9KVxuZXhwb3J0IGNsYXNzIElzUGhvbmUgaW1wbGVtZW50cyBWYWxpZGF0b3JDb25zdHJhaW50SW50ZXJmYWNlIHtcblx0dmFsaWRhdGUodGV4dDogc3RyaW5nLCBhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0cmV0dXJuIC8oKDA5fDAzfDA3fDA4fDA1KSsoWzAtOV17OH0pXFxiKS9nLnRlc3QodGV4dClcblx0fVxuXG5cdGRlZmF1bHRNZXNzYWdlKGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRyZXR1cm4gJyRwcm9wZXJ0eSBtdXN0IGJlIHJlYWwgbnVtYmVycGhvbmUgISdcblx0fVxufVxuXG5AVmFsaWRhdG9yQ29uc3RyYWludCh7IG5hbWU6ICdpc0dtYWlsJywgYXN5bmM6IGZhbHNlIH0pXG5leHBvcnQgY2xhc3MgSXNHbWFpbCBpbXBsZW1lbnRzIFZhbGlkYXRvckNvbnN0cmFpbnRJbnRlcmZhY2Uge1xuXHR2YWxpZGF0ZSh0ZXh0OiBzdHJpbmcsIGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRyZXR1cm4gL14oW2EtekEtWjAtOV18XFwufC18XykrKEBnbWFpbC5jb20pJC8udGVzdCh0ZXh0KVxuXHR9XG5cblx0ZGVmYXVsdE1lc3NhZ2UoYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAnJHByb3BlcnR5IG11c3QgYmUgYSBnbWFpbCBhZGRyZXNzICEnXG5cdH1cbn1cbiIsImltcG9ydCB7IElOZXN0QXBwbGljYXRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFN3YWdnZXJNb2R1bGUsIERvY3VtZW50QnVpbGRlciB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcblxuZXhwb3J0IGNvbnN0IHNldHVwU3dhZ2dlciA9IChhcHA6IElOZXN0QXBwbGljYXRpb24pID0+IHtcblx0Y29uc3QgY29uZmlnID0gbmV3IERvY3VtZW50QnVpbGRlcigpXG5cdFx0LnNldFRpdGxlKCdTaW1wbGUgQVBJJylcblx0XHQuc2V0RGVzY3JpcHRpb24oJ01lZGlob21lIEFQSSB1c2UgU3dhZ2dlcicpXG5cdFx0LnNldFZlcnNpb24oJzEuMCcpXG5cdFx0LmFkZEJlYXJlckF1dGgoXG5cdFx0XHR7IHR5cGU6ICdodHRwJywgZGVzY3JpcHRpb246ICdBY2Nlc3MgdG9rZW4nIH0sXG5cdFx0XHQnYWNjZXNzLXRva2VuJ1xuXHRcdClcblx0XHQuYnVpbGQoKVxuXHRjb25zdCBkb2N1bWVudCA9IFN3YWdnZXJNb2R1bGUuY3JlYXRlRG9jdW1lbnQoYXBwLCBjb25maWcpXG5cdFN3YWdnZXJNb2R1bGUuc2V0dXAoJ2RvY3VtZW50JywgYXBwLCBkb2N1bWVudClcbn1cbiIsImltcG9ydCB7IHJlZ2lzdGVyQXMgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGVPcHRpb25zIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuXG5leHBvcnQgY29uc3QgSnd0Q29uZmlnID0gcmVnaXN0ZXJBcygnand0JywgKCkgPT4gKHtcblx0YWNjZXNzS2V5OiBwcm9jZXNzLmVudi5KV1RfQUNDRVNTX0tFWSxcblx0cmVmcmVzaEtleTogcHJvY2Vzcy5lbnYuSldUX1JFRlJFU0hfS0VZLFxuXHRhY2Nlc3NUaW1lOiBOdW1iZXIocHJvY2Vzcy5lbnYuSldUX0FDQ0VTU19USU1FKSxcblx0cmVmcmVzaFRpbWU6IE51bWJlcihwcm9jZXNzLmVudi5KV1RfUkVGUkVTSF9USU1FKSxcbn0pKVxuXG5leHBvcnQgY29uc3QgTWFyaWFkYkNvbmZpZyA9IHJlZ2lzdGVyQXMoJ21hcmlhZGInLCAoKTogVHlwZU9ybU1vZHVsZU9wdGlvbnMgPT4gKHtcblx0dHlwZTogJ21hcmlhZGInLFxuXHRob3N0OiBwcm9jZXNzLmVudi5NQVJJQURCX0hPU1QsXG5cdHBvcnQ6IHBhcnNlSW50KHByb2Nlc3MuZW52Lk1BUklBREJfUE9SVCwgMTApLFxuXHRkYXRhYmFzZTogcHJvY2Vzcy5lbnYuTUFSSUFEQl9EQVRBQkFTRSxcblx0dXNlcm5hbWU6IHByb2Nlc3MuZW52Lk1BUklBREJfVVNFUk5BTUUsXG5cdHBhc3N3b3JkOiBwcm9jZXNzLmVudi5NQVJJQURCX1BBU1NXT1JELFxuXHRhdXRvTG9hZEVudGl0aWVzOiB0cnVlLFxuXHRsb2dnaW5nOiBwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nLFxuXHRzeW5jaHJvbml6ZTogcHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdsb2NhbCcsXG59KSlcbiIsImV4cG9ydCBlbnVtIEVFcnJvciB7XG5cdFVua25vd24gPSAnQTAwLlVOS05PV04nXG59XG5cbmV4cG9ydCBlbnVtIEVWYWxpZGF0ZUVycm9yIHtcblx0RmFpbGVkID0gJ1YwMC5WQUxJREFURV9GQUlMRUQnXG59XG5cbmV4cG9ydCBlbnVtIEVSZWdpc3RlckVycm9yIHtcblx0RXhpc3RFbWFpbEFuZFBob25lID0gJ1IwMS5FWElTVF9FTUFJTF9BTkRfUEhPTkUnLFxuXHRFeGlzdEVtYWlsID0gJ1IwMi5FWElTVF9FTUFJTCcsXG5cdEV4aXN0UGhvbmUgPSAnUjAzLkVYSVNUX1BIT05FJyxcblx0RXhpc3RVc2VybmFtZSA9ICdSMDQuRVhJU1RfVVNFUk5BTUUnXG59XG5cbmV4cG9ydCBlbnVtIEVMb2dpbkVycm9yIHtcblx0RW1wbG95ZWVEb2VzTm90RXhpc3QgPSAnTDAxLkVNUExPWUVFX0RPRVNfTk9UX0VYSVNUJyxcblx0V3JvbmdQYXNzd29yZCA9ICdMMDIuV1JPTkdfUEFTU1dPUkQnXG59XG5cbmV4cG9ydCBlbnVtIEVUb2tlbkVycm9yIHtcblx0RXhwaXJlZCA9ICdUMDEuRVhQSVJFRCcsXG5cdEludmFsaWQgPSAnVDAyLklOVkFMSUQnXG59XG5cbmV4cG9ydCBlbnVtIEVFbXBsb3llZUVycm9yIHtcblx0VXNlcm5hbWVFeGlzdHMgPSAnVTAxLlVTRVJOQU1FX0VYSVNUUycsXG5cdE5vdEV4aXN0cyA9ICdVMDIuRU1QTE9ZRUVfRE9FU19OT1RfRVhJU1QnXG59XG4iLCJpbXBvcnQgeyBFeGNlcHRpb25GaWx0ZXIsIENhdGNoLCBBcmd1bWVudHNIb3N0LCBIdHRwRXhjZXB0aW9uIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5cbkBDYXRjaChIdHRwRXhjZXB0aW9uKVxuZXhwb3J0IGNsYXNzIEh0dHBFeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjYXRjaChleGNlcHRpb246IEh0dHBFeGNlcHRpb24sIGhvc3Q6IEFyZ3VtZW50c0hvc3QpIHtcblx0XHRjb25zdCBjdHggPSBob3N0LnN3aXRjaFRvSHR0cCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVzcG9uc2U8UmVzcG9uc2U+KClcblx0XHRjb25zdCByZXF1ZXN0ID0gY3R4LmdldFJlcXVlc3Q8UmVxdWVzdD4oKVxuXHRcdGNvbnN0IGh0dHBTdGF0dXMgPSBleGNlcHRpb24uZ2V0U3RhdHVzKClcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlOiBleGNlcHRpb24uZ2V0UmVzcG9uc2UoKSxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXJndW1lbnRzSG9zdCwgQ2F0Y2gsIEV4Y2VwdGlvbkZpbHRlciwgSHR0cFN0YXR1cywgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5cbkBDYXRjaChFcnJvcilcbmV4cG9ydCBjbGFzcyBVbmtub3duRXhjZXB0aW9uRmlsdGVyIGltcGxlbWVudHMgRXhjZXB0aW9uRmlsdGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBsb2dnZXIgPSBuZXcgTG9nZ2VyKCdTRVJWRVJfRVJST1InKSkgeyB9XG5cblx0Y2F0Y2goZXhjZXB0aW9uOiBFcnJvciwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SXG5cblx0XHR0aGlzLmxvZ2dlci5lcnJvcihleGNlcHRpb24uc3RhY2spXG5cblx0XHRyZXNwb25zZS5zdGF0dXMoaHR0cFN0YXR1cykuanNvbih7XG5cdFx0XHRodHRwU3RhdHVzLFxuXHRcdFx0bWVzc2FnZTogZXhjZXB0aW9uLm1lc3NhZ2UsXG5cdFx0XHRwYXRoOiByZXF1ZXN0LnVybCxcblx0XHRcdHRpbWVzdGFtcDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IEFyZ3VtZW50c0hvc3QsIENhdGNoLCBFeGNlcHRpb25GaWx0ZXIsIEh0dHBTdGF0dXMsIFZhbGlkYXRpb25FcnJvciB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UgfSBmcm9tICdleHByZXNzJ1xuaW1wb3J0IHsgRVZhbGlkYXRlRXJyb3IgfSBmcm9tICcuL2V4Y2VwdGlvbi5lbnVtJ1xuXG5leHBvcnQgY2xhc3MgVmFsaWRhdGlvbkV4Y2VwdGlvbiBleHRlbmRzIEVycm9yIHtcblx0cHJpdmF0ZSByZWFkb25seSBlcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdXG5cdGNvbnN0cnVjdG9yKHZhbGlkYXRpb25FcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdID0gW10pIHtcblx0XHRzdXBlcihFVmFsaWRhdGVFcnJvci5GYWlsZWQpXG5cdFx0dGhpcy5lcnJvcnMgPSB2YWxpZGF0aW9uRXJyb3JzXG5cdH1cblx0Z2V0TWVzc2FnZSgpIHtcblx0XHRyZXR1cm4gdGhpcy5tZXNzYWdlXG5cdH1cblx0Z2V0RXJyb3JzKCkge1xuXHRcdHJldHVybiB0aGlzLmVycm9yc1xuXHR9XG59XG5cbkBDYXRjaChWYWxpZGF0aW9uRXhjZXB0aW9uKVxuZXhwb3J0IGNsYXNzIFZhbGlkYXRpb25FeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjYXRjaChleGNlcHRpb246IFZhbGlkYXRpb25FeGNlcHRpb24sIGhvc3Q6IEFyZ3VtZW50c0hvc3QpIHtcblx0XHRjb25zdCBjdHggPSBob3N0LnN3aXRjaFRvSHR0cCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVzcG9uc2U8UmVzcG9uc2U+KClcblx0XHRjb25zdCByZXF1ZXN0ID0gY3R4LmdldFJlcXVlc3Q8UmVxdWVzdD4oKVxuXHRcdGNvbnN0IGh0dHBTdGF0dXMgPSBIdHRwU3RhdHVzLlVOUFJPQ0VTU0FCTEVfRU5USVRZXG5cdFx0Y29uc3QgbWVzc2FnZSA9IGV4Y2VwdGlvbi5nZXRNZXNzYWdlKClcblx0XHRjb25zdCBlcnJvcnMgPSBleGNlcHRpb24uZ2V0RXJyb3JzKClcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlLFxuXHRcdFx0ZXJyb3JzLFxuXHRcdFx0cGF0aDogcmVxdWVzdC51cmwsXG5cdFx0XHR0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDYW5BY3RpdmF0ZSwgRXhlY3V0aW9uQ29udGV4dCwgSW5qZWN0YWJsZSwgU2V0TWV0YWRhdGEgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlZmxlY3RvciB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCB7IE9ic2VydmFibGUgfSBmcm9tICdyeGpzJ1xuaW1wb3J0IHsgVEVtcGxveWVlUm9sZSB9IGZyb20gJ3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vY29tbW9uL2NvbnN0YW50cydcblxuZXhwb3J0IGNvbnN0IFVzZXJSb2xlcyA9ICguLi51c2VyUm9sZXM6IFRFbXBsb3llZVJvbGVbXSkgPT4gU2V0TWV0YWRhdGEoJ3VzZXJfcm9sZXMnLCB1c2VyUm9sZXMpXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgVXNlclJvbGVzR3VhcmQgaW1wbGVtZW50cyBDYW5BY3RpdmF0ZSB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVmbGVjdG9yOiBSZWZsZWN0b3IpIHsgfVxuXG5cdGNhbkFjdGl2YXRlKGNvbnRleHQ6IEV4ZWN1dGlvbkNvbnRleHQpOiBib29sZWFuIHwgUHJvbWlzZTxib29sZWFuPiB8IE9ic2VydmFibGU8Ym9vbGVhbj4ge1xuXHRcdGNvbnN0IHJvbGVzID0gdGhpcy5yZWZsZWN0b3IuZ2V0PFRFbXBsb3llZVJvbGVbXT4oJ3VzZXJfcm9sZXMnLCBjb250ZXh0LmdldEhhbmRsZXIoKSlcblx0XHRpZiAoIXJvbGVzKSByZXR1cm4gdHJ1ZVxuXG5cdFx0Y29uc3QgcmVxdWVzdDogUmVxdWVzdFRva2VuID0gY29udGV4dC5zd2l0Y2hUb0h0dHAoKS5nZXRSZXF1ZXN0KClcblx0XHRjb25zdCB7IHJvbGUgfSA9IHJlcXVlc3QudG9rZW5QYXlsb2FkXG5cdFx0cmV0dXJuIHJvbGVzLmluY2x1ZGVzKHJvbGUpXG5cdH1cbn1cbiIsImltcG9ydCB7IENhbGxIYW5kbGVyLCBFeGVjdXRpb25Db250ZXh0LCBJbmplY3RhYmxlLCBOZXN0SW50ZXJjZXB0b3IsIExvZ2dlciB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgZ2V0Q2xpZW50SXAgfSBmcm9tICdyZXF1ZXN0LWlwJ1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyB0YXAgfSBmcm9tICdyeGpzL29wZXJhdG9ycydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEFjY2Vzc0xvZ0ludGVyY2VwdG9yIGltcGxlbWVudHMgTmVzdEludGVyY2VwdG9yIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBsb2dnZXIgPSBuZXcgTG9nZ2VyKCdBQ0NFU1NfTE9HJykpIHsgfVxuXG5cdGludGVyY2VwdChjb250ZXh0OiBFeGVjdXRpb25Db250ZXh0LCBuZXh0OiBDYWxsSGFuZGxlcik6IE9ic2VydmFibGU8YW55PiB7XG5cdFx0Y29uc3Qgc3RhcnRUaW1lID0gbmV3IERhdGUoKVxuXHRcdGNvbnN0IGN0eCA9IGNvbnRleHQuc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXF1ZXN0ID0gY3R4LmdldFJlcXVlc3QoKVxuXHRcdGNvbnN0IHJlc3BvbnNlID0gY3R4LmdldFJlcXVlc3QoKVxuXG5cdFx0Y29uc3QgeyB1cmwsIG1ldGhvZCB9ID0gcmVxdWVzdFxuXHRcdGNvbnN0IHsgc3RhdHVzQ29kZSB9ID0gcmVzcG9uc2Vcblx0XHRjb25zdCBpcCA9IGdldENsaWVudElwKHJlcXVlc3QpXG5cblx0XHRyZXR1cm4gbmV4dC5oYW5kbGUoKS5waXBlKHRhcCgoKSA9PiB7XG5cdFx0XHRjb25zdCBtc2cgPSBgJHtzdGFydFRpbWUudG9JU09TdHJpbmcoKX0gfCAke2lwfSB8ICR7bWV0aG9kfSB8ICR7c3RhdHVzQ29kZX0gfCAke3VybH0gfCAke0RhdGUubm93KCkgLSBzdGFydFRpbWUuZ2V0VGltZSgpfW1zYFxuXHRcdFx0cmV0dXJuIHRoaXMubG9nZ2VyLmxvZyhtc2cpXG5cdFx0fSkpXG5cdH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUsIE5lc3RJbnRlcmNlcHRvciwgRXhlY3V0aW9uQ29udGV4dCwgQ2FsbEhhbmRsZXIsIFJlcXVlc3RUaW1lb3V0RXhjZXB0aW9uIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBPYnNlcnZhYmxlLCB0aHJvd0Vycm9yLCBUaW1lb3V0RXJyb3IgfSBmcm9tICdyeGpzJ1xuaW1wb3J0IHsgY2F0Y2hFcnJvciwgdGltZW91dCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgVGltZW91dEludGVyY2VwdG9yIGltcGxlbWVudHMgTmVzdEludGVyY2VwdG9yIHtcblx0aW50ZXJjZXB0KGNvbnRleHQ6IEV4ZWN1dGlvbkNvbnRleHQsIG5leHQ6IENhbGxIYW5kbGVyKTogT2JzZXJ2YWJsZTxhbnk+IHtcblx0XHRyZXR1cm4gbmV4dC5oYW5kbGUoKS5waXBlKFxuXHRcdFx0dGltZW91dCgxMDAwMCksXG5cdFx0XHRjYXRjaEVycm9yKGVyciA9PiB7XG5cdFx0XHRcdGlmIChlcnIgaW5zdGFuY2VvZiBUaW1lb3V0RXJyb3IpIHtcblx0XHRcdFx0XHRyZXR1cm4gdGhyb3dFcnJvcigoKSA9PiBuZXcgUmVxdWVzdFRpbWVvdXRFeGNlcHRpb24oKSlcblx0XHRcdFx0fVxuXHRcdFx0XHRyZXR1cm4gdGhyb3dFcnJvcigoKSA9PiBlcnIpXG5cdFx0XHR9KVxuXHRcdClcblx0fVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmVzdE1pZGRsZXdhcmUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlLCBOZXh0RnVuY3Rpb24gfSBmcm9tICdleHByZXNzJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTG9nZ2VyTWlkZGxld2FyZSBpbXBsZW1lbnRzIE5lc3RNaWRkbGV3YXJlIHtcblx0dXNlKHJlcTogUmVxdWVzdCwgcmVzOiBSZXNwb25zZSwgbmV4dDogTmV4dEZ1bmN0aW9uKSB7XG5cdFx0Y29uc29sZS5sb2coJ1JlcXVlc3QuLi4nKVxuXHRcdG5leHQoKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZXN0TWlkZGxld2FyZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgTmV4dEZ1bmN0aW9uLCBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBJSnd0UGF5bG9hZCwgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuLi9tb2R1bGVzL2F1dGgvand0LWV4dGVuZC5zZXJ2aWNlJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgVmFsaWRhdGVBY2Nlc3NUb2tlbk1pZGRsZXdhcmUgaW1wbGVtZW50cyBOZXN0TWlkZGxld2FyZSB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgand0RXh0ZW5kU2VydmljZTogSnd0RXh0ZW5kU2VydmljZSkgeyB9XG5cblx0YXN5bmMgdXNlKHJlcTogUmVxdWVzdFRva2VuLCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pIHtcblx0XHRjb25zdCBhdXRob3JpemF0aW9uID0gcmVxLmhlYWRlcignQXV0aG9yaXphdGlvbicpIHx8ICcnXG5cdFx0Y29uc3QgWywgYWNjZXNzVG9rZW5dID0gYXV0aG9yaXphdGlvbi5zcGxpdCgnICcpXG5cdFx0Y29uc3QgZGVjb2RlOiBJSnd0UGF5bG9hZCA9IHRoaXMuand0RXh0ZW5kU2VydmljZS52ZXJpZnlBY2Nlc3NUb2tlbihhY2Nlc3NUb2tlbilcblx0XHRyZXEudG9rZW5QYXlsb2FkID0gZGVjb2RlXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIFBhcmFtLCBQb3N0LCBSZXEgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBSZXF1ZXN0IH0gZnJvbSAnZXhwcmVzcydcbmltcG9ydCB7IGdldENsaWVudElwIH0gZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IExvZ2luRHRvLCBSZWZyZXNoVG9rZW5EdG8sIFJlZ2lzdGVyRHRvIH0gZnJvbSAnLi9hdXRoLmR0bydcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBBcGlUYWdzKCdBdXRoJylcbkBDb250cm9sbGVyKCdhdXRoJylcbmV4cG9ydCBjbGFzcyBBdXRoQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgYXV0aFNlcnZpY2U6IEF1dGhTZXJ2aWNlLFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgand0RXh0ZW5kU2VydmljZTogSnd0RXh0ZW5kU2VydmljZVxuXHQpIHsgfVxuXG5cdEBQb3N0KCdyZWdpc3RlcicpXG5cdGFzeW5jIHJlZ2lzdGVyKEBCb2R5KCkgcmVnaXN0ZXJEdG86IFJlZ2lzdGVyRHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdCkge1xuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxdWVzdClcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UucmVnaXN0ZXIocmVnaXN0ZXJEdG8pXG5cdFx0Y29uc3QgeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0gPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UuY3JlYXRlVG9rZW5Gcm9tVXNlcihlbXBsb3llZSlcblx0XHRyZXR1cm4geyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH1cblx0fVxuXG5cdEBQb3N0KCdsb2dpbicpXG5cdGFzeW5jIGxvZ2luKEBCb2R5KCkgbG9naW5EdG86IExvZ2luRHRvKSB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmF1dGhTZXJ2aWNlLmxvZ2luKGxvZ2luRHRvKVxuXHRcdGNvbnN0IHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9ID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLmNyZWF0ZVRva2VuRnJvbVVzZXIoZW1wbG95ZWUpXG5cdFx0cmV0dXJuIHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9XG5cdH1cblxuXHRAUG9zdCgnbG9nb3V0Jylcblx0bG9nb3V0KEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0Ly8gcmV0dXJuIHRoaXMuYXV0aFNlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRAUG9zdCgnY2hhbmdlLXBhc3N3b3JkJylcblx0Y2hhbmdlUGFzc3dvcmQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlQXV0aER0bzogTG9naW5EdG8pIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS51cGRhdGUoK2lkLCB1cGRhdGVBdXRoRHRvKVxuXHR9XG5cblx0QFBvc3QoJ2ZvcmdvdC1wYXNzd29yZCcpXG5cdGZvcmdvdFBhc3N3b3JkKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0Ly8gcmV0dXJuIHRoaXMuYXV0aFNlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxuXG5cdEBQb3N0KCdyZWZyZXNoLXRva2VuJylcblx0YXN5bmMgZ3JhbnRBY2Nlc3NUb2tlbihAQm9keSgpIHJlZnJlc2hUb2tlbkR0bzogUmVmcmVzaFRva2VuRHRvKSB7XG5cdFx0Y29uc3QgYWNjZXNzVG9rZW4gPSBhd2FpdCB0aGlzLmF1dGhTZXJ2aWNlLmdyYW50QWNjZXNzVG9rZW4ocmVmcmVzaFRva2VuRHRvLnJlZnJlc2hUb2tlbilcblx0XHRyZXR1cm4geyBhY2Nlc3NUb2tlbiB9XG5cdH1cbn1cbiIsImltcG9ydCB7IEFwaVByb3BlcnR5IH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNEZWZpbmVkLCBMZW5ndGgsIE1pbkxlbmd0aCwgVmFsaWRhdGUgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5pbXBvcnQgeyBJc0dtYWlsLCBJc1Bob25lIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NsYXNzLXZhbGlkYXRvci5jdXN0b20nXG5cbmV4cG9ydCBjbGFzcyBSZWdpc3RlckR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdleGFtcGxlLWNsaW5pY0BnbWFpbC5jb20nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRAVmFsaWRhdGUoSXNHbWFpbClcblx0ZW1haWw6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICcwOTg2MDIxMTkwJyB9KVxuXHRASXNEZWZpbmVkKClcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnYWRtaW4nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIExvZ2luRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJzA5ODYwMjExOTAnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATGVuZ3RoKDEwLCAxMClcblx0Y1Bob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnYWRtaW4nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFJlZnJlc2hUb2tlbkR0byB7XG5cdEBBcGlQcm9wZXJ0eSgpXG5cdEBJc0RlZmluZWQoKVxuXHRyZWZyZXNoVG9rZW46IHN0cmluZ1xufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEp3dE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvand0J1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgSnd0Q29uZmlnIH0gZnJvbSAnLi4vLi4vZW52aXJvbm1lbnRzJ1xuaW1wb3J0IHsgQXV0aENvbnRyb2xsZXIgfSBmcm9tICcuL2F1dGguY29udHJvbGxlcidcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHksIEVtcGxveWVlRW50aXR5XSksXG5cdFx0Q29uZmlnTW9kdWxlLmZvckZlYXR1cmUoSnd0Q29uZmlnKSxcblx0XHRKd3RNb2R1bGUsXG5cdF0sXG5cdGNvbnRyb2xsZXJzOiBbQXV0aENvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtBdXRoU2VydmljZSwgSnd0RXh0ZW5kU2VydmljZV0sXG5cdGV4cG9ydHM6IFtKd3RFeHRlbmRTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb24sIEh0dHBTdGF0dXMsIEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVFbXBsb3llZVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVMb2dpbkVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgTG9naW5EdG8sIFJlZ2lzdGVyRHRvIH0gZnJvbSAnLi9hdXRoLmR0bydcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlLFxuXHRcdHByaXZhdGUgand0RXh0ZW5kU2VydmljZTogSnd0RXh0ZW5kU2VydmljZVxuXHQpIHsgfVxuXG5cdGFzeW5jIHJlZ2lzdGVyKHJlZ2lzdGVyRHRvOiBSZWdpc3RlckR0byk6IFByb21pc2U8RW1wbG95ZWVFbnRpdHk+IHtcblx0XHRjb25zdCB7IGVtYWlsLCBwaG9uZSwgdXNlcm5hbWUsIHBhc3N3b3JkIH0gPSByZWdpc3RlckR0b1xuXHRcdGNvbnN0IGhhc2hQYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5oYXNoKHBhc3N3b3JkLCA1KVxuXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UudHJhbnNhY3Rpb24oYXN5bmMgKG1hbmFnZXIpID0+IHtcblx0XHRcdGNvbnN0IGZpbmRDbGluaWMgPSBhd2FpdCBtYW5hZ2VyLmZpbmRPbmUoQ2xpbmljRW50aXR5LCB7IHdoZXJlOiBbeyBlbWFpbCB9LCB7IHBob25lIH1dIH0pXG5cdFx0XHRpZiAoZmluZENsaW5pYykge1xuXHRcdFx0XHRpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwgJiYgZmluZENsaW5pYy5waG9uZSA9PT0gcGhvbmUpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsQW5kUGhvbmUsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZSBpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2UgaWYgKGZpbmRDbGluaWMucGhvbmUgPT09IHBob25lKSB7XG5cdFx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RQaG9uZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdFx0Y29uc3Qgc25hcENsaW5pYyA9IG1hbmFnZXIuY3JlYXRlKENsaW5pY0VudGl0eSwge1xuXHRcdFx0XHRwaG9uZSxcblx0XHRcdFx0ZW1haWwsXG5cdFx0XHRcdGxldmVsOiAxLFxuXHRcdFx0fSlcblx0XHRcdGNvbnN0IG5ld0NsaW5pYyA9IGF3YWl0IG1hbmFnZXIuc2F2ZShzbmFwQ2xpbmljKVxuXG5cdFx0XHRjb25zdCBzbmFwRW1wbG95ZWUgPSBtYW5hZ2VyLmNyZWF0ZShFbXBsb3llZUVudGl0eSwge1xuXHRcdFx0XHRjbGluaWNJZDogbmV3Q2xpbmljLmlkLFxuXHRcdFx0XHR1c2VybmFtZSxcblx0XHRcdFx0cGFzc3dvcmQ6IGhhc2hQYXNzd29yZCxcblx0XHRcdFx0cm9sZTogRUVtcGxveWVlUm9sZS5Pd25lcixcblx0XHRcdH0pXG5cblx0XHRcdGNvbnN0IG5ld0VtcGxveWVlID0gYXdhaXQgbWFuYWdlci5zYXZlKHNuYXBFbXBsb3llZSlcblx0XHRcdG5ld0VtcGxveWVlLmNsaW5pYyA9IG5ld0NsaW5pY1xuXG5cdFx0XHRyZXR1cm4gbmV3RW1wbG95ZWVcblx0XHR9KVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBsb2dpbihsb2dpbkR0bzogTG9naW5EdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UuZ2V0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSlcblx0XHRcdC5jcmVhdGVRdWVyeUJ1aWxkZXIoJ2VtcGxveWVlJylcblx0XHRcdC5sZWZ0Sm9pbkFuZFNlbGVjdCgnZW1wbG95ZWUuY2xpbmljJywgJ2NsaW5pYycpXG5cdFx0XHQud2hlcmUoJ3VzZXJuYW1lID0gOnVzZXJuYW1lJywgeyB1c2VybmFtZTogbG9naW5EdG8udXNlcm5hbWUgfSlcblx0XHRcdC5hbmRXaGVyZSgnY2xpbmljLnBob25lID0gOmNQaG9uZScsIHsgY1Bob25lOiBsb2dpbkR0by5jUGhvbmUgfSlcblx0XHRcdC5nZXRPbmUoKVxuXG5cdFx0aWYgKCFlbXBsb3llZSkge1xuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuRW1wbG95ZWVEb2VzTm90RXhpc3QsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0fVxuXG5cdFx0Y29uc3QgY2hlY2tQYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5jb21wYXJlKGxvZ2luRHRvLnBhc3N3b3JkLCBlbXBsb3llZS5wYXNzd29yZClcblx0XHRpZiAoIWNoZWNrUGFzc3dvcmQpIHtcblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVMb2dpbkVycm9yLldyb25nUGFzc3dvcmQsIEh0dHBTdGF0dXMuQkFEX0dBVEVXQVkpXG5cdFx0fVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBncmFudEFjY2Vzc1Rva2VuKHJlZnJlc2hUb2tlbjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcblx0XHRjb25zdCB7IHVpZCB9ID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeVJlZnJlc2hUb2tlbihyZWZyZXNoVG9rZW4pXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UuZ2V0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSlcblx0XHRcdC5jcmVhdGVRdWVyeUJ1aWxkZXIoJ2VtcGxveWVlJylcblx0XHRcdC5sZWZ0Sm9pbkFuZFNlbGVjdCgnZW1wbG95ZWUuY2xpbmljJywgJ2NsaW5pYycpXG5cdFx0XHQud2hlcmUoJ2VtcGxveWVlLmlkID0gOmlkJywgeyBpZDogdWlkIH0pXG5cdFx0XHQuZ2V0T25lKClcblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVBY2Nlc3NUb2tlbihlbXBsb3llZSlcblx0XHRyZXR1cm4gYWNjZXNzVG9rZW5cblx0fVxufVxuIiwiaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiwgSHR0cFN0YXR1cywgSW5qZWN0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdUeXBlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnXG5pbXBvcnQgeyBKd3RTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9qd3QnXG5pbXBvcnQgVXNlckVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IElKd3RQYXlsb2FkIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IEp3dENvbmZpZyB9IGZyb20gJy4uLy4uL2Vudmlyb25tZW50cydcbmltcG9ydCB7IEVFcnJvciwgRVRva2VuRXJyb3IgfSBmcm9tICcuLi8uLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcblxuZXhwb3J0IGNsYXNzIEp3dEV4dGVuZFNlcnZpY2Uge1xuXHRjb25zdHJ1Y3Rvcihcblx0XHRASW5qZWN0KEp3dENvbmZpZy5LRVkpIHByaXZhdGUgand0Q29uZmlnOiBDb25maWdUeXBlPHR5cGVvZiBKd3RDb25maWc+LFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgand0U2VydmljZTogSnd0U2VydmljZVxuXHQpIHsgfVxuXG5cdGNyZWF0ZUFjY2Vzc1Rva2VuKHVzZXI6IFVzZXJFbnRpdHkpOiBzdHJpbmcge1xuXHRcdGNvbnN0IHVzZXJQYXlsb2FkOiBJSnd0UGF5bG9hZCA9IHtcblx0XHRcdGNQaG9uZTogdXNlci5jbGluaWMucGhvbmUsXG5cdFx0XHRjaWQ6IHVzZXIuY2xpbmljLmlkLFxuXHRcdFx0dWlkOiB1c2VyLmlkLFxuXHRcdFx0dXNlcm5hbWU6IHVzZXIudXNlcm5hbWUsXG5cdFx0XHRyb2xlOiB1c2VyLnJvbGUsXG5cdFx0fVxuXHRcdHJldHVybiB0aGlzLmp3dFNlcnZpY2Uuc2lnbih1c2VyUGF5bG9hZCwge1xuXHRcdFx0c2VjcmV0OiB0aGlzLmp3dENvbmZpZy5hY2Nlc3NLZXksXG5cdFx0XHRleHBpcmVzSW46IHRoaXMuand0Q29uZmlnLmFjY2Vzc1RpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVJlZnJlc2hUb2tlbih1aWQ6IG51bWJlcik6IHN0cmluZyB7XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHsgdWlkIH0sIHtcblx0XHRcdHNlY3JldDogdGhpcy5qd3RDb25maWcucmVmcmVzaEtleSxcblx0XHRcdGV4cGlyZXNJbjogdGhpcy5qd3RDb25maWcucmVmcmVzaFRpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVRva2VuRnJvbVVzZXIodXNlcjogVXNlckVudGl0eSkge1xuXHRcdGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5jcmVhdGVBY2Nlc3NUb2tlbih1c2VyKVxuXHRcdGNvbnN0IHJlZnJlc2hUb2tlbiA9IHRoaXMuY3JlYXRlUmVmcmVzaFRva2VuKHVzZXIuaWQpXG5cdFx0cmV0dXJuIHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9XG5cdH1cblxuXHR2ZXJpZnlBY2Nlc3NUb2tlbihhY2Nlc3NUb2tlbjogc3RyaW5nKTogSUp3dFBheWxvYWQge1xuXHRcdHRyeSB7XG5cdFx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnZlcmlmeShhY2Nlc3NUb2tlbiwgeyBzZWNyZXQ6IHRoaXMuand0Q29uZmlnLmFjY2Vzc0tleSB9KVxuXHRcdH0gY2F0Y2ggKGVycm9yKSB7XG5cdFx0XHRpZiAoZXJyb3IubmFtZSA9PT0gJ1Rva2VuRXhwaXJlZEVycm9yJykge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5FeHBpcmVkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH0gZWxzZSBpZiAoZXJyb3IubmFtZSA9PT0gJ0pzb25XZWJUb2tlbkVycm9yJykge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5JbnZhbGlkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH1cblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVFcnJvci5Vbmtub3duLCBIdHRwU3RhdHVzLklOVEVSTkFMX1NFUlZFUl9FUlJPUilcblx0XHR9XG5cdH1cblxuXHR2ZXJpZnlSZWZyZXNoVG9rZW4ocmVmcmVzaFRva2VuOiBzdHJpbmcpOiB7IHVpZDogbnVtYmVyIH0ge1xuXHRcdHRyeSB7XG5cdFx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnZlcmlmeShyZWZyZXNoVG9rZW4sIHsgc2VjcmV0OiB0aGlzLmp3dENvbmZpZy5yZWZyZXNoS2V5IH0pXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vd24sIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQ29udHJvbGxlciwgR2V0LCBQb3N0LCBCb2R5LCBQYXRjaCwgUGFyYW0sIERlbGV0ZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5pbXBvcnQgeyBDcmVhdGVDbGluaWNEdG8sIFVwZGF0ZUNsaW5pY0R0byB9IGZyb20gJy4vY2xpbmljLmR0bydcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5cbkBBcGlUYWdzKCdDbGluaWMnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignY2xpbmljJylcbmV4cG9ydCBjbGFzcyBDbGluaWNDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBjbGluaWNTZXJ2aWNlOiBDbGluaWNTZXJ2aWNlKSB7IH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZUNsaW5pY0R0bzogQ3JlYXRlQ2xpbmljRHRvKSB7XG5cdFx0cmV0dXJuICcnXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLmZpbmRBbGwoKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNFbWFpbCwgTGVuZ3RoIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5leHBvcnQgY2xhc3MgQ3JlYXRlQ2xpbmljRHRvIHtcblx0QElzRW1haWwoKVxuXHRlbWFpbDogc3RyaW5nXG5cblx0QExlbmd0aCgxMCwgMTApXG5cdHBob25lOiBzdHJpbmdcblxuXHRATGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUNsaW5pY0R0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZUNsaW5pY0R0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCB7IENsaW5pY0NvbnRyb2xsZXIgfSBmcm9tICcuL2NsaW5pYy5jb250cm9sbGVyJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbQ2xpbmljQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0NsaW5pY1NlcnZpY2VdLFxuXHRleHBvcnRzOiBbQ2xpbmljU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIENsaW5pY01vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEluamVjdFJlcG9zaXRvcnkgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlLCBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ2xpbmljU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdEBJbmplY3RSZXBvc2l0b3J5KENsaW5pY0VudGl0eSkgcHJpdmF0ZSBjbGluaWNSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PENsaW5pY0VudGl0eT4sXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlXG5cdCkgeyB9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIGNsaW5pY2Bcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHR1cGRhdGUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFJlcSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVXNlSW50ZXJjZXB0b3JzIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9ycydcbmltcG9ydCB7IENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vc2VyaWFsaXplcidcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8sIFVwZGF0ZUVtcGxveWVlRHRvIH0gZnJvbSAnLi9lbXBsb3llZS5kdG8nXG5pbXBvcnQgeyBFbXBsb3llZVNlcnZpY2UgfSBmcm9tICcuL2VtcGxveWVlLnNlcnZpY2UnXG5cbkBBcGlUYWdzKCdFbXBsb3llZScpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBVc2VJbnRlcmNlcHRvcnMoQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IpXG5AQ29udHJvbGxlcignZW1wbG95ZWUnKVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgZW1wbG95ZWVTZXJ2aWNlOiBFbXBsb3llZVNlcnZpY2UpIHsgfVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5maW5kQWxsKGNsaW5pY0lkKVxuXHR9XG5cblx0QFBvc3QoKVxuXHRjcmVhdGUoQEJvZHkoKSBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5jcmVhdGUoY2xpbmljSWQsIGNyZWF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLmZpbmRPbmUoY2xpbmljSWQsICtpZClcblx0fVxuXG5cdEBQYXRjaCgndXBkYXRlLzppZCcpXG5cdGFzeW5jIHVwZGF0ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbiwgQEJvZHkoKSB1cGRhdGVFbXBsb3llZUR0bzogVXBkYXRlRW1wbG95ZWVEdG8pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnVwZGF0ZShjbGluaWNJZCwgK2lkLCB1cGRhdGVFbXBsb3llZUR0bylcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG5cblx0QERlbGV0ZSgncmVtb3ZlLzppZCcpXG5cdGFzeW5jIHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5lbXBsb3llZVNlcnZpY2UucmVtb3ZlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBQYXRjaCgncmVzdG9yZS86aWQnKVxuXHRhc3luYyByZXN0b3JlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLmVtcGxveWVlU2VydmljZS5yZXN0b3JlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHksIFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNEZWZpbmVkLCBNaW5MZW5ndGggfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVFbXBsb3llZUR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICduaGF0ZHVvbmcyMDE5JyB9KVxuXHRASXNEZWZpbmVkKClcblx0dXNlcm5hbWU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdBYmNAMTIzNDU2JyB9KVxuXHRASXNEZWZpbmVkKClcblx0QE1pbkxlbmd0aCg2KVxuXHRwYXNzd29yZDogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ05nw7QgTmjhuq10IETGsMahbmcnIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUVtcGxveWVlRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlRW1wbG95ZWVEdG8pIHsgfVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2NsaW5pYy5lbnRpdHknXG5pbXBvcnQgRW1wbG95ZWVFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBFbXBsb3llZUNvbnRyb2xsZXIgfSBmcm9tICcuL2VtcGxveWVlLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBFbXBsb3llZVNlcnZpY2UgfSBmcm9tICcuL2VtcGxveWVlLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtFbXBsb3llZUVudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtFbXBsb3llZUNvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtFbXBsb3llZVNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBFbXBsb3llZU1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEh0dHBTdGF0dXMgfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9lbnVtcydcbmltcG9ydCB7IEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBwbGFpblRvQ2xhc3MgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVFbXBsb3llZVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVFbXBsb3llZUVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8sIFVwZGF0ZUVtcGxveWVlRHRvIH0gZnJvbSAnLi9lbXBsb3llZS5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBFbXBsb3llZVNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSkgcHJpdmF0ZSBlbXBsb3llZVJlcG9zaXRvcnk6IFJlcG9zaXRvcnk8RW1wbG95ZWVFbnRpdHk+KSB7IH1cblxuXHRhc3luYyBmaW5kQWxsKGNsaW5pY0lkOiBudW1iZXIpOiBQcm9taXNlPEVtcGxveWVlRW50aXR5W10+IHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZCh7IHdoZXJlOiB7IGNsaW5pY0lkIH0gfSlcblx0fVxuXG5cdGFzeW5jIGNyZWF0ZShjbGluaWNJZDogbnVtYmVyLCBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZmluZEVtcGxveWVlID0gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZE9uZUJ5KHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0dXNlcm5hbWU6IGNyZWF0ZUVtcGxveWVlRHRvLnVzZXJuYW1lLFxuXHRcdH0pXG5cdFx0aWYgKGZpbmRFbXBsb3llZSkge1xuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RVc2VybmFtZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHR9XG5cdFx0Y29uc3Qgc25hcEVtcGxveWVlID0gcGxhaW5Ub0NsYXNzKEVtcGxveWVlRW50aXR5LCBjcmVhdGVFbXBsb3llZUR0bylcblx0XHRzbmFwRW1wbG95ZWUucGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaChjcmVhdGVFbXBsb3llZUR0by5wYXNzd29yZCwgNSlcblx0XHRzbmFwRW1wbG95ZWUucm9sZSA9IEVFbXBsb3llZVJvbGUuVXNlclxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5zYXZlKGNyZWF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0YXN5bmMgZmluZE9uZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHR9XG5cblx0YXN5bmMgdXBkYXRlKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIsIHVwZGF0ZUVtcGxveWVlRHRvOiBVcGRhdGVFbXBsb3llZUR0bykge1xuXHRcdGNvbnN0IGZpbmRFbXBsb3llZSA9IGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHRcdGlmICghZmluZEVtcGxveWVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFRW1wbG95ZWVFcnJvci5Ob3RFeGlzdHMsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0fVxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS51cGRhdGUoeyBjbGluaWNJZCwgaWQgfSwgdXBkYXRlRW1wbG95ZWVEdG8pXG5cdH1cblxuXHRhc3luYyByZW1vdmUoY2xpbmljSWQ6IG51bWJlciwgZW1wbG95ZWVJZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LnNvZnREZWxldGUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG5cblx0YXN5bmMgcmVzdG9yZShjbGluaWNJZDogbnVtYmVyLCBlbXBsb3llZUlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkucmVzdG9yZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkOiBlbXBsb3llZUlkLFxuXHRcdH0pXG5cdH1cbn1cbiIsImV4cG9ydCBjbGFzcyBDcmVhdGVNZWRpY2luZUR0byB7fVxuIiwiaW1wb3J0IHsgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBDcmVhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vY3JlYXRlLW1lZGljaW5lLmR0bydcblxuZXhwb3J0IGNsYXNzIFVwZGF0ZU1lZGljaW5lRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlTWVkaWNpbmVEdG8pIHt9XG4iLCJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBEZWxldGUsIEdldCwgUGFyYW0sIFBhdGNoLCBQb3N0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlCZWFyZXJBdXRoLCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgTWVkaWNpbmVTZXJ2aWNlIH0gZnJvbSAnLi9tZWRpY2luZS5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnTWVkaWNpbmUnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignbWVkaWNpbmUnKVxuZXhwb3J0IGNsYXNzIE1lZGljaW5lQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgbWVkaWNpbmVTZXJ2aWNlOiBNZWRpY2luZVNlcnZpY2UpIHsgfVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlTWVkaWNpbmVEdG86IENyZWF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLmNyZWF0ZShjcmVhdGVNZWRpY2luZUR0bylcblx0fVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5maW5kQWxsKClcblx0fVxuXG5cdEBHZXQoJzppZCcpXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRAUGF0Y2goJzppZCcpXG5cdHVwZGF0ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQEJvZHkoKSB1cGRhdGVNZWRpY2luZUR0bzogVXBkYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UudXBkYXRlKCtpZCwgdXBkYXRlTWVkaWNpbmVEdG8pXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IE1lZGljaW5lRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvbWVkaWNpbmUuZW50aXR5J1xuaW1wb3J0IHsgTWVkaWNpbmVDb250cm9sbGVyIH0gZnJvbSAnLi9tZWRpY2luZS5jb250cm9sbGVyJ1xuaW1wb3J0IHsgTWVkaWNpbmVTZXJ2aWNlIH0gZnJvbSAnLi9tZWRpY2luZS5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1R5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbTWVkaWNpbmVFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbTWVkaWNpbmVDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbTWVkaWNpbmVTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgTWVkaWNpbmVNb2R1bGUgeyB9XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDcmVhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL2NyZWF0ZS1tZWRpY2luZS5kdG8nXG5pbXBvcnQgeyBVcGRhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL3VwZGF0ZS1tZWRpY2luZS5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBNZWRpY2luZVNlcnZpY2Uge1xuXHRjcmVhdGUoY3JlYXRlTWVkaWNpbmVEdG86IENyZWF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuICdUaGlzIGFjdGlvbiBhZGRzIGEgbmV3IG1lZGljaW5lJ1xuXHR9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIG1lZGljaW5lYFxuXHR9XG5cblx0ZmluZE9uZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGEgIyR7aWR9IG1lZGljaW5lYFxuXHR9XG5cblx0dXBkYXRlKGlkOiBudW1iZXIsIHVwZGF0ZU1lZGljaW5lRHRvOiBVcGRhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxuXG5cdHJlbW92ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZW1vdmVzIGEgIyR7aWR9IG1lZGljaW5lYFxuXHR9XG59XG4iLCJleHBvcnQgY2xhc3MgQ3JlYXRlUGF0aWVudER0byB7fVxuIiwiaW1wb3J0IHsgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInO1xuaW1wb3J0IHsgQ3JlYXRlUGF0aWVudER0byB9IGZyb20gJy4vY3JlYXRlLXBhdGllbnQuZHRvJztcblxuZXhwb3J0IGNsYXNzIFVwZGF0ZVBhdGllbnREdG8gZXh0ZW5kcyBQYXJ0aWFsVHlwZShDcmVhdGVQYXRpZW50RHRvKSB7fVxuIiwiaW1wb3J0IHsgQ29udHJvbGxlciwgR2V0LCBQb3N0LCBCb2R5LCBQYXRjaCwgUGFyYW0sIERlbGV0ZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJztcbmltcG9ydCB7IFBhdGllbnRTZXJ2aWNlIH0gZnJvbSAnLi9wYXRpZW50LnNlcnZpY2UnO1xuaW1wb3J0IHsgQ3JlYXRlUGF0aWVudER0byB9IGZyb20gJy4vZHRvL2NyZWF0ZS1wYXRpZW50LmR0byc7XG5pbXBvcnQgeyBVcGRhdGVQYXRpZW50RHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlLXBhdGllbnQuZHRvJztcblxuQENvbnRyb2xsZXIoJ3BhdGllbnQnKVxuZXhwb3J0IGNsYXNzIFBhdGllbnRDb250cm9sbGVyIHtcbiAgY29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBwYXRpZW50U2VydmljZTogUGF0aWVudFNlcnZpY2UpIHt9XG5cbiAgQFBvc3QoKVxuICBjcmVhdGUoQEJvZHkoKSBjcmVhdGVQYXRpZW50RHRvOiBDcmVhdGVQYXRpZW50RHRvKSB7XG4gICAgcmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuY3JlYXRlKGNyZWF0ZVBhdGllbnREdG8pO1xuICB9XG5cbiAgQEdldCgpXG4gIGZpbmRBbGwoKSB7XG4gICAgcmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuZmluZEFsbCgpO1xuICB9XG5cbiAgQEdldCgnOmlkJylcbiAgZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuICAgIHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRPbmUoK2lkKTtcbiAgfVxuXG4gIEBQYXRjaCgnOmlkJylcbiAgdXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAQm9keSgpIHVwZGF0ZVBhdGllbnREdG86IFVwZGF0ZVBhdGllbnREdG8pIHtcbiAgICByZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS51cGRhdGUoK2lkLCB1cGRhdGVQYXRpZW50RHRvKTtcbiAgfVxuXG4gIEBEZWxldGUoJzppZCcpXG4gIHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuICAgIHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLnJlbW92ZSgraWQpO1xuICB9XG59XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbic7XG5pbXBvcnQgeyBQYXRpZW50U2VydmljZSB9IGZyb20gJy4vcGF0aWVudC5zZXJ2aWNlJztcbmltcG9ydCB7IFBhdGllbnRDb250cm9sbGVyIH0gZnJvbSAnLi9wYXRpZW50LmNvbnRyb2xsZXInO1xuXG5ATW9kdWxlKHtcbiAgY29udHJvbGxlcnM6IFtQYXRpZW50Q29udHJvbGxlcl0sXG4gIHByb3ZpZGVyczogW1BhdGllbnRTZXJ2aWNlXVxufSlcbmV4cG9ydCBjbGFzcyBQYXRpZW50TW9kdWxlIHt9XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nO1xuaW1wb3J0IHsgQ3JlYXRlUGF0aWVudER0byB9IGZyb20gJy4vZHRvL2NyZWF0ZS1wYXRpZW50LmR0byc7XG5pbXBvcnQgeyBVcGRhdGVQYXRpZW50RHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlLXBhdGllbnQuZHRvJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFBhdGllbnRTZXJ2aWNlIHtcbiAgY3JlYXRlKGNyZWF0ZVBhdGllbnREdG86IENyZWF0ZVBhdGllbnREdG8pIHtcbiAgICByZXR1cm4gJ1RoaXMgYWN0aW9uIGFkZHMgYSBuZXcgcGF0aWVudCc7XG4gIH1cblxuICBmaW5kQWxsKCkge1xuICAgIHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhbGwgcGF0aWVudGA7XG4gIH1cblxuICBmaW5kT25lKGlkOiBudW1iZXIpIHtcbiAgICByZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYSAjJHtpZH0gcGF0aWVudGA7XG4gIH1cblxuICB1cGRhdGUoaWQ6IG51bWJlciwgdXBkYXRlUGF0aWVudER0bzogVXBkYXRlUGF0aWVudER0bykge1xuICAgIHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBwYXRpZW50YDtcbiAgfVxuXG4gIHJlbW92ZShpZDogbnVtYmVyKSB7XG4gICAgcmV0dXJuIGBUaGlzIGFjdGlvbiByZW1vdmVzIGEgIyR7aWR9IHBhdGllbnRgO1xuICB9XG59XG4iLCJpbXBvcnQgeyBDcmVhdGVEYXRlQ29sdW1uLCBEZWxldGVEYXRlQ29sdW1uLCBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLCBVcGRhdGVEYXRlQ29sdW1uIH0gZnJvbSAndHlwZW9ybSdcblxuZXhwb3J0IGNsYXNzIEJhc2VFbnRpdHkge1xuXHRAUHJpbWFyeUdlbmVyYXRlZENvbHVtbih7IG5hbWU6ICdpZCcgfSlcblx0aWQ6IG51bWJlclxuXG5cdEBDcmVhdGVEYXRlQ29sdW1uKHsgbmFtZTogJ2NyZWF0ZWRfYXQnIH0pXG5cdGNyZWF0ZWRBdDogRGF0ZVxuXG5cdEBVcGRhdGVEYXRlQ29sdW1uKHsgbmFtZTogJ3VwZGF0ZWRfYXQnIH0pXG5cdHVwZGF0ZWRBdDogRGF0ZVxuXG5cdEBEZWxldGVEYXRlQ29sdW1uKHsgbmFtZTogJ2RlbGV0ZWRfYXQnIH0pXG5cdGRlbGV0ZWRBdDogRGF0ZVxufVxuIiwiaW1wb3J0IHsgQ29sdW1uLCBFbnRpdHksIEluZGV4IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHkgfSBmcm9tICcuLi9iYXNlLmVudGl0eSdcblxuQEVudGl0eSgnY2xpbmljJylcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIENsaW5pY0VudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgdW5pcXVlOiB0cnVlLCBsZW5ndGg6IDEwLCBudWxsYWJsZTogZmFsc2UgfSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB1bmlxdWU6IHRydWUsIG51bGxhYmxlOiBmYWxzZSB9KVxuXHRlbWFpbDogc3RyaW5nXG5cblx0QENvbHVtbih7IHR5cGU6ICd0aW55aW50JywgZGVmYXVsdDogMSB9KVxuXHRsZXZlbDogbnVtYmVyXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdG5hbWU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRhZGRyZXNzOiBzdHJpbmdcbn1cbiIsImltcG9ydCB7IEV4cG9zZSwgRXhjbHVkZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgQ29sdW1uLCBFbnRpdHksIEluZGV4LCBKb2luQ29sdW1uLCBNYW55VG9PbmUgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuL2NsaW5pYy5lbnRpdHknXG5cbmV4cG9ydCBlbnVtIEVFbXBsb3llZVJvbGUge1xuXHRPd25lciA9ICdPd25lcicsXG5cdEFkbWluID0gJ0FkbWluJyxcblx0VXNlciA9ICdVc2VyJyxcbn1cblxuZXhwb3J0IHR5cGUgVEVtcGxveWVlUm9sZSA9IGtleW9mIHR5cGVvZiBFRW1wbG95ZWVSb2xlXG5cbkBFbnRpdHkoJ2VtcGxveWVlJylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ3VzZXJuYW1lJ10sIHsgdW5pcXVlOiB0cnVlIH0pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBFbXBsb3llZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBNYW55VG9PbmUodHlwZSA9PiBDbGluaWNFbnRpdHkpXG5cdEBKb2luQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcsIHJlZmVyZW5jZWRDb2x1bW5OYW1lOiAnaWQnIH0pXG5cdGNsaW5pYzogQ2xpbmljRW50aXR5XG5cblx0QENvbHVtbih7IGxlbmd0aDogMTAsIG51bGxhYmxlOiB0cnVlIH0pXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQ29sdW1uKClcblx0QEV4cG9zZSgpXG5cdHVzZXJuYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKClcblx0QEV4Y2x1ZGUoKVxuXHRwYXNzd29yZDogc3RyaW5nXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUVtcGxveWVlUm9sZSwgZGVmYXVsdDogRUVtcGxveWVlUm9sZS5Vc2VyIH0pXG5cdHJvbGU6IEVFbXBsb3llZVJvbGVcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2Z1bGxfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcbn1cbiIsImltcG9ydCB7IEVudGl0eSwgQ29sdW1uLCBJbmRleCB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5IH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ21lZGljaW5lJylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ2lkJ10sIHsgdW5pcXVlOiB0cnVlIH0pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNZWRpY2luZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnYnJhbmRfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGJyYW5kTmFtZTogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdMOqbiBiaeG7h3QgZMaw4bujY1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnY2hlbWljYWxfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGNoZW1pY2FsTmFtZTogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdMOqbiBn4buRY1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnY2FsY3VsYXRpb25fdW5pdCcsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGNhbGN1bGF0aW9uVW5pdDogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgLy8gxJHGoW4gduG7iyB0w61uaDogbOG7jSwg4buRbmcsIHbhu4lcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2ltYWdlJywgbnVsbGFibGU6IHRydWUgfSlcblx0aW1hZ2U6IHN0cmluZ1xufVxuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9yc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vbi9lbnVtc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uL3NlcmlhbGl6ZXJcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvand0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvc3dhZ2dlclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3R5cGVvcm1cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiYmNyeXB0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImNsYXNzLXRyYW5zZm9ybWVyXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImNsYXNzLXZhbGlkYXRvclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJleHByZXNzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImV4cHJlc3MtcmF0ZS1saW1pdFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJoZWxtZXRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwicmVxdWVzdC1pcFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJyeGpzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInJ4anMvb3BlcmF0b3JzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInR5cGVvcm1cIik7IiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXS5jYWxsKG1vZHVsZS5leHBvcnRzLCBtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsImltcG9ydCB7IFZhbGlkYXRpb25FcnJvciwgVmFsaWRhdGlvblBpcGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IENvbmZpZ1NlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IE5lc3RGYWN0b3J5LCBSZWZsZWN0b3IgfSBmcm9tICdAbmVzdGpzL2NvcmUnXG5pbXBvcnQgcmF0ZUxpbWl0IGZyb20gJ2V4cHJlc3MtcmF0ZS1saW1pdCdcbmltcG9ydCBoZWxtZXQgZnJvbSAnaGVsbWV0J1xuaW1wb3J0ICogYXMgcmVxdWVzdElwIGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBBcHBNb2R1bGUgfSBmcm9tICcuL2FwcC5tb2R1bGUnXG5pbXBvcnQgeyBzZXR1cFN3YWdnZXIgfSBmcm9tICcuL2NvbW1vbi9zd2FnZ2VyJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbkZpbHRlciB9IGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvaHR0cC1leGNlcHRpb24uZmlsdGVyJ1xuaW1wb3J0IHsgVW5rbm93bkV4Y2VwdGlvbkZpbHRlciB9IGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvdW5rbm93bi1leGNlcHRpb24uZmlsdGVyJ1xuaW1wb3J0IHsgVmFsaWRhdGlvbkV4Y2VwdGlvbiwgVmFsaWRhdGlvbkV4Y2VwdGlvbkZpbHRlciB9IGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvdmFsaWRhdGlvbi1leGNlcHRpb24uZmlsdGVyJ1xuaW1wb3J0IHsgVXNlclJvbGVzR3VhcmQgfSBmcm9tICcuL2d1YXJkcy91c2VyLXJvbGVzLmd1YXJkJ1xuaW1wb3J0IHsgQWNjZXNzTG9nSW50ZXJjZXB0b3IgfSBmcm9tICcuL2ludGVyY2VwdG9yL2FjY2Vzcy1sb2cuaW50ZXJjZXB0b3InXG5pbXBvcnQgeyBUaW1lb3V0SW50ZXJjZXB0b3IgfSBmcm9tICcuL2ludGVyY2VwdG9yL3RpbWVvdXQuaW50ZXJjZXB0b3InXG5cbmFzeW5jIGZ1bmN0aW9uIGJvb3RzdHJhcCgpIHtcblx0Y29uc3QgYXBwID0gYXdhaXQgTmVzdEZhY3RvcnkuY3JlYXRlKEFwcE1vZHVsZSlcblx0XG5cdGNvbnN0IGNvbmZpZ1NlcnZpY2UgPSBhcHAuZ2V0KENvbmZpZ1NlcnZpY2UpXG5cdGNvbnN0IFBPUlQgPSBjb25maWdTZXJ2aWNlLmdldCgnTkVTVEpTX1BPUlQnKVxuXHRjb25zdCBIT1NUID0gY29uZmlnU2VydmljZS5nZXQoJ05FU1RKU19IT1NUJykgfHwgJ2xvY2FsaG9zdCdcblxuXHRhcHAudXNlKGhlbG1ldCgpKVxuXHRhcHAudXNlKHJhdGVMaW1pdCh7XG5cdFx0d2luZG93TXM6IDYwICogMTAwMCwgLy8gMSBtaW51dGVzXG5cdFx0bWF4OiAxMDAsIC8vIGxpbWl0IGVhY2ggSVAgdG8gMTAwIHJlcXVlc3RzIHBlciB3aW5kb3dNc1xuXHR9KSlcblx0YXBwLmVuYWJsZUNvcnMoKVxuXG5cdGFwcC51c2UocmVxdWVzdElwLm13KCkpXG5cblx0YXBwLnVzZUdsb2JhbEludGVyY2VwdG9ycyhcblx0XHRuZXcgQWNjZXNzTG9nSW50ZXJjZXB0b3IoKSxcblx0XHRuZXcgVGltZW91dEludGVyY2VwdG9yKClcblx0KVxuXHRhcHAudXNlR2xvYmFsRmlsdGVycyhcblx0XHRuZXcgVW5rbm93bkV4Y2VwdGlvbkZpbHRlcigpLFxuXHRcdG5ldyBIdHRwRXhjZXB0aW9uRmlsdGVyKCksXG5cdFx0bmV3IFZhbGlkYXRpb25FeGNlcHRpb25GaWx0ZXIoKVxuXHQpXG5cblx0YXBwLnVzZUdsb2JhbEd1YXJkcyhuZXcgVXNlclJvbGVzR3VhcmQoYXBwLmdldChSZWZsZWN0b3IpKSlcblxuXHRhcHAudXNlR2xvYmFsUGlwZXMobmV3IFZhbGlkYXRpb25QaXBlKHtcblx0XHR2YWxpZGF0aW9uRXJyb3I6IHsgdGFyZ2V0OiBmYWxzZSwgdmFsdWU6IHRydWUgfSxcblx0XHRza2lwTWlzc2luZ1Byb3BlcnRpZXM6IHRydWUsXG5cdFx0ZXhjZXB0aW9uRmFjdG9yeTogKGVycm9yczogVmFsaWRhdGlvbkVycm9yW10gPSBbXSkgPT4gbmV3IFZhbGlkYXRpb25FeGNlcHRpb24oZXJyb3JzKSxcblx0fSkpXG5cblx0aWYgKGNvbmZpZ1NlcnZpY2UuZ2V0KCdOT0RFX0VOVicpICE9PSAncHJvZHVjdGlvbicpIHtcblx0XHRzZXR1cFN3YWdnZXIoYXBwKVxuXHR9XG5cblx0YXdhaXQgYXBwLmxpc3RlbihQT1JULCAoKSA9PiB7XG5cdFx0Y29uc29sZS5sb2coYPCfmoAgU2VydmVyIGRvY3VtZW50OiBodHRwOi8vJHtIT1NUfToke1BPUlR9L2RvY3VtZW50YClcblx0fSlcbn1cbmJvb3RzdHJhcCgpXG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=