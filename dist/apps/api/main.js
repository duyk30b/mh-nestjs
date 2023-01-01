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
const health_module_1 = __webpack_require__(/*! ./modules/health/health.module */ "./apps/api/src/modules/health/health.module.ts");
const medicine_module_1 = __webpack_require__(/*! ./modules/medicine/medicine.module */ "./apps/api/src/modules/medicine/medicine.module.ts");
const patient_module_1 = __webpack_require__(/*! ./modules/patient/patient.module */ "./apps/api/src/modules/patient/patient.module.ts");
let AppModule = class AppModule {
    constructor(dataSource) {
        this.dataSource = dataSource;
    }
    configure(consumer) {
        consumer.apply(logger_middleware_1.LoggerMiddleware).forRoutes('*');
        consumer.apply(validate_access_token_middleware_1.ValidateAccessTokenMiddleware)
            .exclude('auth/(.*)', '/', { path: 'health', method: common_1.RequestMethod.GET })
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
            health_module_1.HealthModule,
            auth_module_1.AuthModule,
            employee_module_1.EmployeeModule,
            patient_module_1.PatientModule,
            clinic_module_1.ClinicModule,
            medicine_module_1.MedicineModule,
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
exports.EPatientError = exports.EEmployeeError = exports.ETokenError = exports.ELoginError = exports.ERegisterError = exports.EValidateError = exports.EError = void 0;
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
var EPatientError;
(function (EPatientError) {
    EPatientError["NotExists"] = "P01.PATIENT_DOES_NOT_EXIST";
})(EPatientError = exports.EPatientError || (exports.EPatientError = {}));


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
    (0, swagger_1.ApiProperty)({ example: 'example-2@gmail.com' }),
    (0, class_validator_1.IsDefined)(),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsGmail),
    __metadata("design:type", String)
], RegisterDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: '0376899866' }),
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
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_e = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _e : Object]),
    __metadata("design:returntype", void 0)
], EmployeeController.prototype, "findOne", null);
__decorate([
    (0, common_1.Patch)('update/:id'),
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_f = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _f : Object, typeof (_g = typeof employee_dto_1.UpdateEmployeeDto !== "undefined" && employee_dto_1.UpdateEmployeeDto) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], EmployeeController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)('remove/:id'),
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_h = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _h : Object]),
    __metadata("design:returntype", Promise)
], EmployeeController.prototype, "remove", null);
__decorate([
    (0, common_1.Patch)('restore/:id'),
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
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

/***/ "./apps/api/src/modules/health/health.controller.ts":
/*!**********************************************************!*\
  !*** ./apps/api/src/modules/health/health.controller.ts ***!
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
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const terminus_1 = __webpack_require__(/*! @nestjs/terminus */ "@nestjs/terminus");
let HealthController = class HealthController {
    constructor(health, http, db, disk, memory) {
        this.health = health;
        this.http = http;
        this.db = db;
        this.disk = disk;
        this.memory = memory;
    }
    check() {
        return this.health.check([
            () => this.http.pingCheck('nestjs-docs', 'https://medihome.vn/document'),
            () => this.db.pingCheck('database'),
            () => this.disk.checkStorage('storage', { path: '/', thresholdPercent: 0.5 }),
            () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
            () => this.memory.checkRSS('memory_rss', 150 * 1024 * 1024),
        ]);
    }
};
__decorate([
    (0, common_1.Get)(),
    (0, terminus_1.HealthCheck)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], HealthController.prototype, "check", null);
HealthController = __decorate([
    (0, swagger_1.ApiTags)('Health'),
    (0, common_1.Controller)('health'),
    __metadata("design:paramtypes", [typeof (_a = typeof terminus_1.HealthCheckService !== "undefined" && terminus_1.HealthCheckService) === "function" ? _a : Object, typeof (_b = typeof terminus_1.HttpHealthIndicator !== "undefined" && terminus_1.HttpHealthIndicator) === "function" ? _b : Object, typeof (_c = typeof terminus_1.TypeOrmHealthIndicator !== "undefined" && terminus_1.TypeOrmHealthIndicator) === "function" ? _c : Object, typeof (_d = typeof terminus_1.DiskHealthIndicator !== "undefined" && terminus_1.DiskHealthIndicator) === "function" ? _d : Object, typeof (_e = typeof terminus_1.MemoryHealthIndicator !== "undefined" && terminus_1.MemoryHealthIndicator) === "function" ? _e : Object])
], HealthController);
exports.HealthController = HealthController;


/***/ }),

/***/ "./apps/api/src/modules/health/health.module.ts":
/*!******************************************************!*\
  !*** ./apps/api/src/modules/health/health.module.ts ***!
  \******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthModule = void 0;
const axios_1 = __webpack_require__(/*! @nestjs/axios */ "@nestjs/axios");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const terminus_1 = __webpack_require__(/*! @nestjs/terminus */ "@nestjs/terminus");
const health_controller_1 = __webpack_require__(/*! ./health.controller */ "./apps/api/src/modules/health/health.controller.ts");
let HealthModule = class HealthModule {
};
HealthModule = __decorate([
    (0, common_1.Module)({
        imports: [terminus_1.TerminusModule, axios_1.HttpModule],
        controllers: [health_controller_1.HealthController],
    })
], HealthModule);
exports.HealthModule = HealthModule;


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
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PatientController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const constants_1 = __webpack_require__(/*! ../../common/constants */ "./apps/api/src/common/constants.ts");
const patient_dto_1 = __webpack_require__(/*! ./patient.dto */ "./apps/api/src/modules/patient/patient.dto.ts");
const patient_service_1 = __webpack_require__(/*! ./patient.service */ "./apps/api/src/modules/patient/patient.service.ts");
let PatientController = class PatientController {
    constructor(patientService) {
        this.patientService = patientService;
    }
    findAll(request) {
        const clinicId = request.tokenPayload.cid;
        return this.patientService.findAll(clinicId);
    }
    search(searchText, request) {
        const clinicId = request.tokenPayload.cid;
        if (/^\d+$/.test(searchText)) {
            return this.patientService.findByPhone(clinicId, searchText);
        }
        return this.patientService.findByFullName(clinicId, searchText);
    }
    create(createPatientDto, request) {
        const clinicId = request.tokenPayload.cid;
        return this.patientService.create(clinicId, createPatientDto);
    }
    findOne(id, request) {
        const clinicId = request.tokenPayload.cid;
        return this.patientService.findOne(clinicId, +id);
    }
    async update(id, updatePatientDto, request) {
        const clinicId = request.tokenPayload.cid;
        await this.patientService.update(clinicId, +id, updatePatientDto);
        return { message: 'success' };
    }
    async remove(id, request) {
        const clinicId = request.tokenPayload.cid;
        await this.patientService.remove(clinicId, +id);
        return { message: 'success' };
    }
    async restore(id, request) {
        const clinicId = request.tokenPayload.cid;
        await this.patientService.restore(clinicId, +id);
        return { message: 'success' };
    }
};
__decorate([
    (0, common_1.Get)(),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _b : Object]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)('search'),
    (0, swagger_1.ApiQuery)({ name: 'searchText', example: '0986123456' }),
    __param(0, (0, common_1.Query)('searchText')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_c = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _c : Object]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "search", null);
__decorate([
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof patient_dto_1.CreatePatientDto !== "undefined" && patient_dto_1.CreatePatientDto) === "function" ? _d : Object, typeof (_e = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _e : Object]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_f = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _f : Object]),
    __metadata("design:returntype", void 0)
], PatientController.prototype, "findOne", null);
__decorate([
    (0, common_1.Patch)('update/:id'),
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_g = typeof patient_dto_1.UpdatePatientDto !== "undefined" && patient_dto_1.UpdatePatientDto) === "function" ? _g : Object, typeof (_h = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _h : Object]),
    __metadata("design:returntype", Promise)
], PatientController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)('remove/:id'),
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_j = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _j : Object]),
    __metadata("design:returntype", Promise)
], PatientController.prototype, "remove", null);
__decorate([
    (0, common_1.Patch)('restore/:id'),
    (0, swagger_1.ApiParam)({ name: 'id', example: 1 }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_k = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _k : Object]),
    __metadata("design:returntype", Promise)
], PatientController.prototype, "restore", null);
PatientController = __decorate([
    (0, swagger_1.ApiTags)('Patient'),
    (0, swagger_1.ApiBearerAuth)('access-token'),
    (0, common_1.UseInterceptors)(common_1.ClassSerializerInterceptor),
    (0, common_1.Controller)('patient'),
    __metadata("design:paramtypes", [typeof (_a = typeof patient_service_1.PatientService !== "undefined" && patient_service_1.PatientService) === "function" ? _a : Object])
], PatientController);
exports.PatientController = PatientController;


/***/ }),

/***/ "./apps/api/src/modules/patient/patient.dto.ts":
/*!*****************************************************!*\
  !*** ./apps/api/src/modules/patient/patient.dto.ts ***!
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
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdatePatientDto = exports.CreatePatientDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const base_entity_1 = __webpack_require__(/*! ../../../../../typeorm/base.entity */ "./typeorm/base.entity.ts");
const class_validator_custom_1 = __webpack_require__(/*! ../../common/class-validator.custom */ "./apps/api/src/common/class-validator.custom.ts");
class CreatePatientDto {
}
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: 'Phạm Hoàng Mai' }),
    (0, class_validator_1.IsDefined)(),
    __metadata("design:type", String)
], CreatePatientDto.prototype, "fullName", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: '0986123456' }),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsPhone),
    __metadata("design:type", String)
], CreatePatientDto.prototype, "phone", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: base_entity_1.EGender.Female }),
    __metadata("design:type", typeof (_a = typeof base_entity_1.EGender !== "undefined" && base_entity_1.EGender) === "function" ? _a : Object)
], CreatePatientDto.prototype, "gender", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: 'Thành phố Hà Nội -- Quận Long Biên -- Phường Thạch Bàn -- số 8 - tòa nhà Đảo Cầu Vồng' }),
    __metadata("design:type", String)
], CreatePatientDto.prototype, "address", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: '1998-11-28T00:00:00.000Z' }),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], CreatePatientDto.prototype, "birthday", void 0);
exports.CreatePatientDto = CreatePatientDto;
class UpdatePatientDto extends (0, swagger_1.PartialType)(CreatePatientDto) {
}
exports.UpdatePatientDto = UpdatePatientDto;


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
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const patient_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/patient.entity */ "./typeorm/entities/patient.entity.ts");
const patient_controller_1 = __webpack_require__(/*! ./patient.controller */ "./apps/api/src/modules/patient/patient.controller.ts");
const patient_service_1 = __webpack_require__(/*! ./patient.service */ "./apps/api/src/modules/patient/patient.service.ts");
let PatientModule = class PatientModule {
};
PatientModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([patient_entity_1.default])],
        controllers: [patient_controller_1.PatientController],
        providers: [patient_service_1.PatientService],
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
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PatientService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const exceptions_1 = __webpack_require__(/*! @nestjs/common/exceptions */ "@nestjs/common/exceptions");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const patient_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/patient.entity */ "./typeorm/entities/patient.entity.ts");
const exception_enum_1 = __webpack_require__(/*! ../../exception-filters/exception.enum */ "./apps/api/src/exception-filters/exception.enum.ts");
let PatientService = class PatientService {
    constructor(patientRepository) {
        this.patientRepository = patientRepository;
    }
    async findAll(clinicId) {
        const patientList = await this.patientRepository.find({ where: { clinicId } });
        return patientList;
    }
    async create(clinicId, createPatientDto) {
        const patient = await this.patientRepository.save(Object.assign({ clinicId }, createPatientDto));
        return patient;
    }
    async findOne(clinicId, id) {
        const patient = await this.patientRepository.findOneBy({ clinicId, id });
        return patient;
    }
    async findByPhone(clinicId, phone) {
        const patientList = await this.patientRepository.find({
            where: {
                clinicId: (0, typeorm_2.Equal)(clinicId),
                phone: (0, typeorm_2.Like)(`${phone}%`),
            },
            skip: 0,
            take: 10,
        });
        return patientList;
    }
    async findByFullName(clinicId, fullName) {
        const patientList = await this.patientRepository.find({
            where: {
                clinicId: (0, typeorm_2.Equal)(clinicId),
                fullName: (0, typeorm_2.Like)(`${fullName}%`),
            },
            skip: 0,
            take: 10,
        });
        return patientList;
    }
    async update(clinicId, id, updatePatientDto) {
        const findPatient = await this.patientRepository.findOneBy({ clinicId, id });
        if (!findPatient) {
            throw new exceptions_1.HttpException(exception_enum_1.EPatientError.NotExists, common_1.HttpStatus.BAD_REQUEST);
        }
        return await this.patientRepository.update({ clinicId, id }, updatePatientDto);
    }
    async remove(clinicId, id) {
        return await this.patientRepository.softDelete({
            clinicId,
            id,
        });
    }
    async restore(clinicId, employeeId) {
        return await this.patientRepository.restore({
            clinicId,
            id: employeeId,
        });
    }
};
PatientService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(patient_entity_1.default)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object])
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
exports.BaseEntity = exports.EGender = void 0;
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
var EGender;
(function (EGender) {
    EGender["Male"] = "Male";
    EGender["Female"] = "Female";
})(EGender = exports.EGender || (exports.EGender = {}));
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
    (0, class_transformer_1.Exclude)(),
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
var _a, _b, _c;
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
    (0, class_transformer_1.Exclude)(),
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
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], EmployeeEntity.prototype, "birthday", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'enum', enum: base_entity_1.EGender, nullable: true }),
    __metadata("design:type", typeof (_c = typeof base_entity_1.EGender !== "undefined" && base_entity_1.EGender) === "function" ? _c : Object)
], EmployeeEntity.prototype, "gender", void 0);
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

/***/ "./typeorm/entities/patient.entity.ts":
/*!********************************************!*\
  !*** ./typeorm/entities/patient.entity.ts ***!
  \********************************************/
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
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../base.entity */ "./typeorm/base.entity.ts");
let PatientEntity = class PatientEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ name: 'clinic_id' }),
    (0, class_transformer_1.Exclude)(),
    __metadata("design:type", Number)
], PatientEntity.prototype, "clinicId", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'full_name' }),
    __metadata("design:type", String)
], PatientEntity.prototype, "fullName", void 0);
__decorate([
    (0, typeorm_1.Column)({ length: 10, nullable: true }),
    __metadata("design:type", String)
], PatientEntity.prototype, "phone", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], PatientEntity.prototype, "birthday", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'enum', enum: base_entity_1.EGender, nullable: true }),
    __metadata("design:type", typeof (_b = typeof base_entity_1.EGender !== "undefined" && base_entity_1.EGender) === "function" ? _b : Object)
], PatientEntity.prototype, "gender", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], PatientEntity.prototype, "address", void 0);
PatientEntity = __decorate([
    (0, typeorm_1.Entity)('patient'),
    (0, typeorm_1.Index)(['clinicId', 'fullName']),
    (0, typeorm_1.Index)(['clinicId', 'phone'])
], PatientEntity);
exports["default"] = PatientEntity;


/***/ }),

/***/ "@nestjs/axios":
/*!********************************!*\
  !*** external "@nestjs/axios" ***!
  \********************************/
/***/ ((module) => {

module.exports = require("@nestjs/axios");

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

/***/ "@nestjs/terminus":
/*!***********************************!*\
  !*** external "@nestjs/terminus" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/terminus");

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXBwcy9hcGkvbWFpbi5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLDZFQUFzRjtBQUN0Riw2RUFBeUQ7QUFDekQsZ0ZBQStDO0FBQy9DLGdFQUFvQztBQUNwQyxtR0FBOEM7QUFDOUMsMElBQWtFO0FBQ2xFLHVMQUE4RjtBQUM5RiwwSEFBdUQ7QUFDdkQsb0lBQTZEO0FBQzdELDhJQUFtRTtBQUNuRSxvSUFBNkQ7QUFDN0QsOElBQW1FO0FBQ25FLHlJQUFnRTtBQXVCekQsSUFBTSxTQUFTLEdBQWYsTUFBTSxTQUFTO0lBQ3JCLFlBQW9CLFVBQXNCO1FBQXRCLGVBQVUsR0FBVixVQUFVLENBQVk7SUFBSSxDQUFDO0lBQy9DLFNBQVMsQ0FBQyxRQUE0QjtRQUNyQyxRQUFRLENBQUMsS0FBSyxDQUFDLG9DQUFnQixDQUFDLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQztRQUUvQyxRQUFRLENBQUMsS0FBSyxDQUFDLGdFQUE2QixDQUFDO2FBQzNDLE9BQU8sQ0FDUCxXQUFXLEVBQ1gsR0FBRyxFQUNILEVBQUUsSUFBSSxFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUUsc0JBQWEsQ0FBQyxHQUFHLEVBQUUsQ0FDN0M7YUFDQSxTQUFTLENBQUMsR0FBRyxDQUFDO0lBQ2pCLENBQUM7Q0FDRDtBQWJZLFNBQVM7SUFyQnJCLG1CQUFNLEVBQUM7UUFDUCxPQUFPLEVBQUU7WUFDUixxQkFBWSxDQUFDLE9BQU8sQ0FBQztnQkFDcEIsV0FBVyxFQUFFLENBQUMsUUFBUSxPQUFPLENBQUMsR0FBRyxDQUFDLFFBQVEsSUFBSSxPQUFPLEVBQUUsRUFBRSxNQUFNLENBQUM7Z0JBQ2hFLFFBQVEsRUFBRSxJQUFJO2FBQ2QsQ0FBQztZQUNGLHVCQUFhLENBQUMsWUFBWSxDQUFDO2dCQUMxQixPQUFPLEVBQUUsQ0FBQyxxQkFBWSxDQUFDLFVBQVUsQ0FBQyw0QkFBYSxDQUFDLENBQUM7Z0JBQ2pELE1BQU0sRUFBRSxDQUFDLDRCQUFhLENBQUMsR0FBRyxDQUFDO2dCQUMzQixVQUFVLEVBQUUsQ0FBQyxhQUErQyxFQUFFLEVBQUUsQ0FBQyxhQUFhO2FBRzlFLENBQUM7WUFDRiw0QkFBWTtZQUNaLHdCQUFVO1lBQ1YsZ0NBQWM7WUFDZCw4QkFBYTtZQUNiLDRCQUFZO1lBQ1osZ0NBQWM7U0FDZDtLQUNELENBQUM7eURBRStCLG9CQUFVLG9CQUFWLG9CQUFVO0dBRDlCLFNBQVMsQ0FhckI7QUFiWSw4QkFBUzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNuQ3RCLHdGQUF3RztBQUdqRyxJQUFNLE9BQU8sR0FBYixNQUFNLE9BQU87SUFDbkIsUUFBUSxDQUFDLElBQVksRUFBRSxJQUF5QjtRQUMvQyxPQUFPLGtDQUFrQyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUM7SUFDckQsQ0FBQztJQUVELGNBQWMsQ0FBQyxJQUF5QjtRQUN2QyxPQUFPLHNDQUFzQztJQUM5QyxDQUFDO0NBQ0Q7QUFSWSxPQUFPO0lBRG5CLHlDQUFtQixFQUFDLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxLQUFLLEVBQUUsS0FBSyxFQUFFLENBQUM7R0FDMUMsT0FBTyxDQVFuQjtBQVJZLDBCQUFPO0FBV2IsSUFBTSxPQUFPLEdBQWIsTUFBTSxPQUFPO0lBQ25CLFFBQVEsQ0FBQyxJQUFZLEVBQUUsSUFBeUI7UUFDL0MsT0FBTyxxQ0FBcUMsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDO0lBQ3hELENBQUM7SUFFRCxjQUFjLENBQUMsSUFBeUI7UUFDdkMsT0FBTyxxQ0FBcUM7SUFDN0MsQ0FBQztDQUNEO0FBUlksT0FBTztJQURuQix5Q0FBbUIsRUFBQyxFQUFFLElBQUksRUFBRSxTQUFTLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxDQUFDO0dBQzFDLE9BQU8sQ0FRbkI7QUFSWSwwQkFBTzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNicEIsZ0ZBQWdFO0FBRXpELE1BQU0sWUFBWSxHQUFHLENBQUMsR0FBcUIsRUFBRSxFQUFFO0lBQ3JELE1BQU0sTUFBTSxHQUFHLElBQUkseUJBQWUsRUFBRTtTQUNsQyxRQUFRLENBQUMsWUFBWSxDQUFDO1NBQ3RCLGNBQWMsQ0FBQywwQkFBMEIsQ0FBQztTQUMxQyxVQUFVLENBQUMsS0FBSyxDQUFDO1NBQ2pCLGFBQWEsQ0FDYixFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsV0FBVyxFQUFFLGNBQWMsRUFBRSxFQUM3QyxjQUFjLENBQ2Q7U0FDQSxLQUFLLEVBQUU7SUFDVCxNQUFNLFFBQVEsR0FBRyx1QkFBYSxDQUFDLGNBQWMsQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDO0lBQzFELHVCQUFhLENBQUMsS0FBSyxDQUFDLFVBQVUsRUFBRSxHQUFHLEVBQUUsUUFBUSxDQUFDO0FBQy9DLENBQUM7QUFaWSxvQkFBWSxnQkFZeEI7Ozs7Ozs7Ozs7Ozs7O0FDZkQsNkVBQTJDO0FBRzlCLGlCQUFTLEdBQUcsdUJBQVUsRUFBQyxLQUFLLEVBQUUsR0FBRyxFQUFFLENBQUMsQ0FBQztJQUNqRCxTQUFTLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxjQUFjO0lBQ3JDLFVBQVUsRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLGVBQWU7SUFDdkMsVUFBVSxFQUFFLE1BQU0sQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLGVBQWUsQ0FBQztJQUMvQyxXQUFXLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCLENBQUM7Q0FDakQsQ0FBQyxDQUFDO0FBRVUscUJBQWEsR0FBRyx1QkFBVSxFQUFDLFNBQVMsRUFBRSxHQUF5QixFQUFFLENBQUMsQ0FBQztJQUMvRSxJQUFJLEVBQUUsU0FBUztJQUNmLElBQUksRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLFlBQVk7SUFDOUIsSUFBSSxFQUFFLFFBQVEsQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLFlBQVksRUFBRSxFQUFFLENBQUM7SUFDNUMsUUFBUSxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCO0lBQ3RDLFFBQVEsRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLGdCQUFnQjtJQUN0QyxRQUFRLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxnQkFBZ0I7SUFDdEMsZ0JBQWdCLEVBQUUsSUFBSTtJQUN0QixPQUFPLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxRQUFRLEtBQUssWUFBWTtJQUM5QyxXQUFXLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxRQUFRLEtBQUssT0FBTztDQUM3QyxDQUFDLENBQUM7Ozs7Ozs7Ozs7Ozs7O0FDcEJILElBQVksTUFFWDtBQUZELFdBQVksTUFBTTtJQUNqQixpQ0FBdUI7QUFDeEIsQ0FBQyxFQUZXLE1BQU0sR0FBTixjQUFNLEtBQU4sY0FBTSxRQUVqQjtBQUVELElBQVksY0FFWDtBQUZELFdBQVksY0FBYztJQUN6QixnREFBOEI7QUFDL0IsQ0FBQyxFQUZXLGNBQWMsR0FBZCxzQkFBYyxLQUFkLHNCQUFjLFFBRXpCO0FBRUQsSUFBWSxjQUtYO0FBTEQsV0FBWSxjQUFjO0lBQ3pCLGtFQUFnRDtJQUNoRCxnREFBOEI7SUFDOUIsZ0RBQThCO0lBQzlCLHNEQUFvQztBQUNyQyxDQUFDLEVBTFcsY0FBYyxHQUFkLHNCQUFjLEtBQWQsc0JBQWMsUUFLekI7QUFFRCxJQUFZLFdBR1g7QUFIRCxXQUFZLFdBQVc7SUFDdEIsbUVBQW9EO0lBQ3BELG1EQUFvQztBQUNyQyxDQUFDLEVBSFcsV0FBVyxHQUFYLG1CQUFXLEtBQVgsbUJBQVcsUUFHdEI7QUFFRCxJQUFZLFdBR1g7QUFIRCxXQUFZLFdBQVc7SUFDdEIsc0NBQXVCO0lBQ3ZCLHNDQUF1QjtBQUN4QixDQUFDLEVBSFcsV0FBVyxHQUFYLG1CQUFXLEtBQVgsbUJBQVcsUUFHdEI7QUFFRCxJQUFZLGNBR1g7QUFIRCxXQUFZLGNBQWM7SUFDekIsd0RBQXNDO0lBQ3RDLDJEQUF5QztBQUMxQyxDQUFDLEVBSFcsY0FBYyxHQUFkLHNCQUFjLEtBQWQsc0JBQWMsUUFHekI7QUFFRCxJQUFZLGFBRVg7QUFGRCxXQUFZLGFBQWE7SUFDeEIseURBQXdDO0FBQ3pDLENBQUMsRUFGVyxhQUFhLEdBQWIscUJBQWEsS0FBYixxQkFBYSxRQUV4Qjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNoQ0QsNkVBQXFGO0FBSTlFLElBQU0sbUJBQW1CLEdBQXpCLE1BQU0sbUJBQW1CO0lBQy9CLEtBQUssQ0FBQyxTQUF3QixFQUFFLElBQW1CO1FBQ2xELE1BQU0sR0FBRyxHQUFHLElBQUksQ0FBQyxZQUFZLEVBQUU7UUFDL0IsTUFBTSxRQUFRLEdBQUcsR0FBRyxDQUFDLFdBQVcsRUFBWTtRQUM1QyxNQUFNLE9BQU8sR0FBRyxHQUFHLENBQUMsVUFBVSxFQUFXO1FBQ3pDLE1BQU0sVUFBVSxHQUFHLFNBQVMsQ0FBQyxTQUFTLEVBQUU7UUFFeEMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsQ0FBQyxJQUFJLENBQUM7WUFDaEMsVUFBVTtZQUNWLE9BQU8sRUFBRSxTQUFTLENBQUMsV0FBVyxFQUFFO1lBQ2hDLElBQUksRUFBRSxPQUFPLENBQUMsR0FBRztZQUNqQixTQUFTLEVBQUUsSUFBSSxJQUFJLEVBQUUsQ0FBQyxXQUFXLEVBQUU7U0FDbkMsQ0FBQztJQUNILENBQUM7Q0FDRDtBQWRZLG1CQUFtQjtJQUQvQixrQkFBSyxFQUFDLHNCQUFhLENBQUM7R0FDUixtQkFBbUIsQ0FjL0I7QUFkWSxrREFBbUI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDSmhDLDZFQUEwRjtBQUluRixJQUFNLHNCQUFzQixHQUE1QixNQUFNLHNCQUFzQjtJQUNsQyxZQUE2QixTQUFTLElBQUksZUFBTSxDQUFDLGNBQWMsQ0FBQztRQUFuQyxXQUFNLEdBQU4sTUFBTSxDQUE2QjtJQUFJLENBQUM7SUFFckUsS0FBSyxDQUFDLFNBQWdCLEVBQUUsSUFBbUI7UUFDMUMsTUFBTSxHQUFHLEdBQUcsSUFBSSxDQUFDLFlBQVksRUFBRTtRQUMvQixNQUFNLFFBQVEsR0FBRyxHQUFHLENBQUMsV0FBVyxFQUFZO1FBQzVDLE1BQU0sT0FBTyxHQUFHLEdBQUcsQ0FBQyxVQUFVLEVBQVc7UUFDekMsTUFBTSxVQUFVLEdBQUcsbUJBQVUsQ0FBQyxxQkFBcUI7UUFFbkQsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQztRQUVsQyxRQUFRLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLElBQUksQ0FBQztZQUNoQyxVQUFVO1lBQ1YsT0FBTyxFQUFFLFNBQVMsQ0FBQyxPQUFPO1lBQzFCLElBQUksRUFBRSxPQUFPLENBQUMsR0FBRztZQUNqQixTQUFTLEVBQUUsSUFBSSxJQUFJLEVBQUUsQ0FBQyxXQUFXLEVBQUU7U0FDbkMsQ0FBQztJQUNILENBQUM7Q0FDRDtBQWxCWSxzQkFBc0I7SUFEbEMsa0JBQUssRUFBQyxLQUFLLENBQUM7O0dBQ0Esc0JBQXNCLENBa0JsQztBQWxCWSx3REFBc0I7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDSm5DLDZFQUFtRztBQUVuRywySEFBaUQ7QUFFakQsTUFBYSxtQkFBb0IsU0FBUSxLQUFLO0lBRTdDLFlBQVksbUJBQXNDLEVBQUU7UUFDbkQsS0FBSyxDQUFDLCtCQUFjLENBQUMsTUFBTSxDQUFDO1FBQzVCLElBQUksQ0FBQyxNQUFNLEdBQUcsZ0JBQWdCO0lBQy9CLENBQUM7SUFDRCxVQUFVO1FBQ1QsT0FBTyxJQUFJLENBQUMsT0FBTztJQUNwQixDQUFDO0lBQ0QsU0FBUztRQUNSLE9BQU8sSUFBSSxDQUFDLE1BQU07SUFDbkIsQ0FBQztDQUNEO0FBWkQsa0RBWUM7QUFHTSxJQUFNLHlCQUF5QixHQUEvQixNQUFNLHlCQUF5QjtJQUNyQyxLQUFLLENBQUMsU0FBOEIsRUFBRSxJQUFtQjtRQUN4RCxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsWUFBWSxFQUFFO1FBQy9CLE1BQU0sUUFBUSxHQUFHLEdBQUcsQ0FBQyxXQUFXLEVBQVk7UUFDNUMsTUFBTSxPQUFPLEdBQUcsR0FBRyxDQUFDLFVBQVUsRUFBVztRQUN6QyxNQUFNLFVBQVUsR0FBRyxtQkFBVSxDQUFDLG9CQUFvQjtRQUNsRCxNQUFNLE9BQU8sR0FBRyxTQUFTLENBQUMsVUFBVSxFQUFFO1FBQ3RDLE1BQU0sTUFBTSxHQUFHLFNBQVMsQ0FBQyxTQUFTLEVBQUU7UUFFcEMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsQ0FBQyxJQUFJLENBQUM7WUFDaEMsVUFBVTtZQUNWLE9BQU87WUFDUCxNQUFNO1lBQ04sSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHO1lBQ2pCLFNBQVMsRUFBRSxJQUFJLElBQUksRUFBRSxDQUFDLFdBQVcsRUFBRTtTQUNuQyxDQUFDO0lBQ0gsQ0FBQztDQUNEO0FBakJZLHlCQUF5QjtJQURyQyxrQkFBSyxFQUFDLG1CQUFtQixDQUFDO0dBQ2QseUJBQXlCLENBaUJyQztBQWpCWSw4REFBeUI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ25CdEMsNkVBQXVGO0FBQ3ZGLHVFQUF3QztBQUtqQyxNQUFNLFNBQVMsR0FBRyxDQUFDLEdBQUcsU0FBMEIsRUFBRSxFQUFFLENBQUMsd0JBQVcsRUFBQyxZQUFZLEVBQUUsU0FBUyxDQUFDO0FBQW5GLGlCQUFTLGFBQTBFO0FBRXpGLElBQU0sY0FBYyxHQUFwQixNQUFNLGNBQWM7SUFDMUIsWUFBb0IsU0FBb0I7UUFBcEIsY0FBUyxHQUFULFNBQVMsQ0FBVztJQUFJLENBQUM7SUFFN0MsV0FBVyxDQUFDLE9BQXlCO1FBQ3BDLE1BQU0sS0FBSyxHQUFHLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFrQixZQUFZLEVBQUUsT0FBTyxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBQ3JGLElBQUksQ0FBQyxLQUFLO1lBQUUsT0FBTyxJQUFJO1FBRXZCLE1BQU0sT0FBTyxHQUFpQixPQUFPLENBQUMsWUFBWSxFQUFFLENBQUMsVUFBVSxFQUFFO1FBQ2pFLE1BQU0sRUFBRSxJQUFJLEVBQUUsR0FBRyxPQUFPLENBQUMsWUFBWTtRQUNyQyxPQUFPLEtBQUssQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDO0lBQzVCLENBQUM7Q0FDRDtBQVhZLGNBQWM7SUFEMUIsdUJBQVUsR0FBRTt5REFFbUIsZ0JBQVMsb0JBQVQsZ0JBQVM7R0FENUIsY0FBYyxDQVcxQjtBQVhZLHdDQUFjOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1IzQiw2RUFBbUc7QUFDbkcseUVBQXdDO0FBRXhDLGdGQUFvQztBQUc3QixJQUFNLG9CQUFvQixHQUExQixNQUFNLG9CQUFvQjtJQUNoQyxZQUE2QixTQUFTLElBQUksZUFBTSxDQUFDLFlBQVksQ0FBQztRQUFqQyxXQUFNLEdBQU4sTUFBTSxDQUEyQjtJQUFJLENBQUM7SUFFbkUsU0FBUyxDQUFDLE9BQXlCLEVBQUUsSUFBaUI7UUFDckQsTUFBTSxTQUFTLEdBQUcsSUFBSSxJQUFJLEVBQUU7UUFDNUIsTUFBTSxHQUFHLEdBQUcsT0FBTyxDQUFDLFlBQVksRUFBRTtRQUNsQyxNQUFNLE9BQU8sR0FBRyxHQUFHLENBQUMsVUFBVSxFQUFFO1FBQ2hDLE1BQU0sUUFBUSxHQUFHLEdBQUcsQ0FBQyxVQUFVLEVBQUU7UUFFakMsTUFBTSxFQUFFLEdBQUcsRUFBRSxNQUFNLEVBQUUsR0FBRyxPQUFPO1FBQy9CLE1BQU0sRUFBRSxVQUFVLEVBQUUsR0FBRyxRQUFRO1FBQy9CLE1BQU0sRUFBRSxHQUFHLDRCQUFXLEVBQUMsT0FBTyxDQUFDO1FBRS9CLE9BQU8sSUFBSSxDQUFDLE1BQU0sRUFBRSxDQUFDLElBQUksQ0FBQyxtQkFBRyxFQUFDLEdBQUcsRUFBRTtZQUNsQyxNQUFNLEdBQUcsR0FBRyxHQUFHLFNBQVMsQ0FBQyxXQUFXLEVBQUUsTUFBTSxFQUFFLE1BQU0sTUFBTSxNQUFNLFVBQVUsTUFBTSxHQUFHLE1BQU0sSUFBSSxDQUFDLEdBQUcsRUFBRSxHQUFHLFNBQVMsQ0FBQyxPQUFPLEVBQUUsSUFBSTtZQUM3SCxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQztRQUM1QixDQUFDLENBQUMsQ0FBQztJQUNKLENBQUM7Q0FDRDtBQWxCWSxvQkFBb0I7SUFEaEMsdUJBQVUsR0FBRTs7R0FDQSxvQkFBb0IsQ0FrQmhDO0FBbEJZLG9EQUFvQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNOakMsNkVBQW9IO0FBQ3BILHVEQUEyRDtBQUMzRCxnRkFBb0Q7QUFHN0MsSUFBTSxrQkFBa0IsR0FBeEIsTUFBTSxrQkFBa0I7SUFDOUIsU0FBUyxDQUFDLE9BQXlCLEVBQUUsSUFBaUI7UUFDckQsT0FBTyxJQUFJLENBQUMsTUFBTSxFQUFFLENBQUMsSUFBSSxDQUN4Qix1QkFBTyxFQUFDLEtBQUssQ0FBQyxFQUNkLDBCQUFVLEVBQUMsR0FBRyxDQUFDLEVBQUU7WUFDaEIsSUFBSSxHQUFHLFlBQVksbUJBQVksRUFBRTtnQkFDaEMsT0FBTyxxQkFBVSxFQUFDLEdBQUcsRUFBRSxDQUFDLElBQUksZ0NBQXVCLEVBQUUsQ0FBQzthQUN0RDtZQUNELE9BQU8scUJBQVUsRUFBQyxHQUFHLEVBQUUsQ0FBQyxHQUFHLENBQUM7UUFDN0IsQ0FBQyxDQUFDLENBQ0Y7SUFDRixDQUFDO0NBQ0Q7QUFaWSxrQkFBa0I7SUFEOUIsdUJBQVUsR0FBRTtHQUNBLGtCQUFrQixDQVk5QjtBQVpZLGdEQUFrQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNML0IsNkVBQTJEO0FBSXBELElBQU0sZ0JBQWdCLEdBQXRCLE1BQU0sZ0JBQWdCO0lBQzVCLEdBQUcsQ0FBQyxHQUFZLEVBQUUsR0FBYSxFQUFFLElBQWtCO1FBQ2xELE9BQU8sQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1FBQ3pCLElBQUksRUFBRTtJQUNQLENBQUM7Q0FDRDtBQUxZLGdCQUFnQjtJQUQ1Qix1QkFBVSxHQUFFO0dBQ0EsZ0JBQWdCLENBSzVCO0FBTFksNENBQWdCOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNKN0IsNkVBQTJEO0FBRzNELGdKQUFxRTtBQUc5RCxJQUFNLDZCQUE2QixHQUFuQyxNQUFNLDZCQUE2QjtJQUN6QyxZQUE2QixnQkFBa0M7UUFBbEMscUJBQWdCLEdBQWhCLGdCQUFnQixDQUFrQjtJQUFJLENBQUM7SUFFcEUsS0FBSyxDQUFDLEdBQUcsQ0FBQyxHQUFpQixFQUFFLEdBQWEsRUFBRSxJQUFrQjtRQUM3RCxNQUFNLGFBQWEsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLGVBQWUsQ0FBQyxJQUFJLEVBQUU7UUFDdkQsTUFBTSxDQUFDLEVBQUUsV0FBVyxDQUFDLEdBQUcsYUFBYSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUM7UUFDaEQsTUFBTSxNQUFNLEdBQWdCLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxpQkFBaUIsQ0FBQyxXQUFXLENBQUM7UUFDaEYsR0FBRyxDQUFDLFlBQVksR0FBRyxNQUFNO1FBQ3pCLElBQUksRUFBRTtJQUNQLENBQUM7Q0FDRDtBQVZZLDZCQUE2QjtJQUR6Qyx1QkFBVSxHQUFFO3lEQUVtQyxxQ0FBZ0Isb0JBQWhCLHFDQUFnQjtHQURuRCw2QkFBNkIsQ0FVekM7QUFWWSxzRUFBNkI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ04xQyw2RUFBbUU7QUFDbkUsZ0ZBQXlDO0FBQ3pDLGdFQUFpQztBQUNqQyx5RUFBd0M7QUFDeEMsb0dBQW1FO0FBQ25FLGdIQUE0QztBQUM1QyxrSUFBdUQ7QUFJaEQsSUFBTSxjQUFjLEdBQXBCLE1BQU0sY0FBYztJQUMxQixZQUNrQixXQUF3QixFQUN4QixnQkFBa0M7UUFEbEMsZ0JBQVcsR0FBWCxXQUFXLENBQWE7UUFDeEIscUJBQWdCLEdBQWhCLGdCQUFnQixDQUFrQjtJQUNoRCxDQUFDO0lBR0MsS0FBRCxDQUFDLFFBQVEsQ0FBUyxXQUF3QixFQUFTLE9BQWdCO1FBQ3ZFLE1BQU0sRUFBRSxHQUFHLDRCQUFXLEVBQUMsT0FBTyxDQUFDO1FBQy9CLE1BQU0sUUFBUSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxRQUFRLENBQUMsV0FBVyxDQUFDO1FBQzdELE1BQU0sRUFBRSxXQUFXLEVBQUUsWUFBWSxFQUFFLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixDQUFDLG1CQUFtQixDQUFDLFFBQVEsQ0FBQztRQUN6RixPQUFPLEVBQUUsV0FBVyxFQUFFLFlBQVksRUFBRTtJQUNyQyxDQUFDO0lBR0ssS0FBRCxDQUFDLEtBQUssQ0FBUyxRQUFrQjtRQUNyQyxNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQztRQUN2RCxNQUFNLEVBQUUsV0FBVyxFQUFFLFlBQVksRUFBRSxHQUFHLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxtQkFBbUIsQ0FBQyxRQUFRLENBQUM7UUFDekYsT0FBTyxFQUFFLFdBQVcsRUFBRSxZQUFZLEVBQUU7SUFDckMsQ0FBQztJQUdELE1BQU0sQ0FBYyxFQUFVO0lBRTlCLENBQUM7SUFHRCxjQUFjLENBQWMsRUFBVSxFQUFVLGFBQXVCO0lBRXZFLENBQUM7SUFHRCxjQUFjLENBQWMsRUFBVTtJQUV0QyxDQUFDO0lBR0ssS0FBRCxDQUFDLGdCQUFnQixDQUFTLGVBQWdDO1FBQzlELE1BQU0sV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxnQkFBZ0IsQ0FBQyxlQUFlLENBQUMsWUFBWSxDQUFDO1FBQ3pGLE9BQU8sRUFBRSxXQUFXLEVBQUU7SUFDdkIsQ0FBQztDQUNEO0FBbENNO0lBREwsaUJBQUksRUFBQyxVQUFVLENBQUM7SUFDRCw0QkFBSSxHQUFFO0lBQTRCLDJCQUFHLEdBQUU7O3lEQUFuQixzQkFBVyxvQkFBWCxzQkFBVyxvREFBa0IsaUJBQU8sb0JBQVAsaUJBQU87OzhDQUt2RTtBQUdLO0lBREwsaUJBQUksRUFBQyxPQUFPLENBQUM7SUFDRCw0QkFBSSxHQUFFOzt5REFBVyxtQkFBUSxvQkFBUixtQkFBUTs7MkNBSXJDO0FBRUQ7SUFBQyxpQkFBSSxFQUFDLFFBQVEsQ0FBQztJQUNQLDZCQUFLLEVBQUMsSUFBSSxDQUFDOzs7OzRDQUVsQjtBQUVEO0lBQUMsaUJBQUksRUFBQyxpQkFBaUIsQ0FBQztJQUNSLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsNEJBQUksR0FBRTs7aUVBQWdCLG1CQUFRLG9CQUFSLG1CQUFROztvREFFdEU7QUFFRDtJQUFDLGlCQUFJLEVBQUMsaUJBQWlCLENBQUM7SUFDUiw2QkFBSyxFQUFDLElBQUksQ0FBQzs7OztvREFFMUI7QUFHSztJQURMLGlCQUFJLEVBQUMsZUFBZSxDQUFDO0lBQ0UsNEJBQUksR0FBRTs7eURBQWtCLDBCQUFlLG9CQUFmLDBCQUFlOztzREFHOUQ7QUF4Q1csY0FBYztJQUYxQixxQkFBTyxFQUFDLE1BQU0sQ0FBQztJQUNmLHVCQUFVLEVBQUMsTUFBTSxDQUFDO3lEQUdhLDBCQUFXLG9CQUFYLDBCQUFXLG9EQUNOLHFDQUFnQixvQkFBaEIscUNBQWdCO0dBSHhDLGNBQWMsQ0F5QzFCO0FBekNZLHdDQUFjOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1YzQixnRkFBNkM7QUFDN0Msd0ZBQXdFO0FBQ3hFLG1KQUFzRTtBQUV0RSxNQUFhLFdBQVc7Q0FtQnZCO0FBbEJBO0lBQUMseUJBQVcsRUFBQyxFQUFFLE9BQU8sRUFBRSxxQkFBcUIsRUFBRSxDQUFDO0lBQy9DLCtCQUFTLEdBQUU7SUFDWCw4QkFBUSxFQUFDLGdDQUFPLENBQUM7OzBDQUNMO0FBRWI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQ3RDLCtCQUFTLEdBQUU7SUFDWCw4QkFBUSxFQUFDLGdDQUFPLENBQUM7OzBDQUNMO0FBRWI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLE9BQU8sRUFBRSxDQUFDO0lBQ2pDLCtCQUFTLEdBQUU7OzZDQUNJO0FBRWhCO0lBQUMseUJBQVcsRUFBQyxFQUFFLE9BQU8sRUFBRSxZQUFZLEVBQUUsQ0FBQztJQUN0QywrQkFBUyxHQUFFO0lBQ1gsK0JBQVMsRUFBQyxDQUFDLENBQUM7OzZDQUNHO0FBbEJqQixrQ0FtQkM7QUFFRCxNQUFhLFFBQVE7Q0FjcEI7QUFiQTtJQUFDLHlCQUFXLEVBQUMsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDdEMsK0JBQVMsR0FBRTtJQUNYLDRCQUFNLEVBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQzs7d0NBQ0Q7QUFFZDtJQUFDLHlCQUFXLEVBQUMsRUFBRSxPQUFPLEVBQUUsT0FBTyxFQUFFLENBQUM7SUFDakMsK0JBQVMsR0FBRTs7MENBQ0k7QUFFaEI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQ3RDLCtCQUFTLEdBQUU7SUFDWCwrQkFBUyxFQUFDLENBQUMsQ0FBQzs7MENBQ0c7QUFiakIsNEJBY0M7QUFFRCxNQUFhLGVBQWU7Q0FJM0I7QUFIQTtJQUFDLHlCQUFXLEdBQUU7SUFDYiwrQkFBUyxHQUFFOztxREFDUTtBQUhyQiwwQ0FJQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUM3Q0QsNkVBQXVDO0FBQ3ZDLDZFQUE2QztBQUM3QyxvRUFBdUM7QUFDdkMsZ0ZBQStDO0FBQy9DLHdJQUF3RTtBQUN4RSw4SUFBNEU7QUFDNUUsdUdBQThDO0FBQzlDLHlIQUFrRDtBQUNsRCxnSEFBNEM7QUFDNUMsa0lBQXVEO0FBWWhELElBQU0sVUFBVSxHQUFoQixNQUFNLFVBQVU7Q0FBSTtBQUFkLFVBQVU7SUFWdEIsbUJBQU0sRUFBQztRQUNQLE9BQU8sRUFBRTtZQUNSLHVCQUFhLENBQUMsVUFBVSxDQUFDLENBQUMsdUJBQVksRUFBRSx5QkFBYyxDQUFDLENBQUM7WUFDeEQscUJBQVksQ0FBQyxVQUFVLENBQUMsd0JBQVMsQ0FBQztZQUNsQyxlQUFTO1NBQ1Q7UUFDRCxXQUFXLEVBQUUsQ0FBQyxnQ0FBYyxDQUFDO1FBQzdCLFNBQVMsRUFBRSxDQUFDLDBCQUFXLEVBQUUscUNBQWdCLENBQUM7UUFDMUMsT0FBTyxFQUFFLENBQUMscUNBQWdCLENBQUM7S0FDM0IsQ0FBQztHQUNXLFVBQVUsQ0FBSTtBQUFkLGdDQUFVOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNyQnZCLDZFQUFzRTtBQUN0RSwyREFBZ0M7QUFDaEMsZ0VBQW9DO0FBQ3BDLHdJQUF3RTtBQUN4RSw4SUFBK0Y7QUFDL0YsaUpBQW9GO0FBRXBGLGtJQUF1RDtBQUdoRCxJQUFNLFdBQVcsR0FBakIsTUFBTSxXQUFXO0lBQ3ZCLFlBQ1MsVUFBc0IsRUFDdEIsZ0JBQWtDO1FBRGxDLGVBQVUsR0FBVixVQUFVLENBQVk7UUFDdEIscUJBQWdCLEdBQWhCLGdCQUFnQixDQUFrQjtJQUN2QyxDQUFDO0lBRUwsS0FBSyxDQUFDLFFBQVEsQ0FBQyxXQUF3QjtRQUN0QyxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxRQUFRLEVBQUUsUUFBUSxFQUFFLEdBQUcsV0FBVztRQUN4RCxNQUFNLFlBQVksR0FBRyxNQUFNLE1BQU0sQ0FBQyxJQUFJLENBQUMsUUFBUSxFQUFFLENBQUMsQ0FBQztRQUVuRCxNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsV0FBVyxDQUFDLEtBQUssRUFBRSxPQUFPLEVBQUUsRUFBRTtZQUNwRSxNQUFNLFVBQVUsR0FBRyxNQUFNLE9BQU8sQ0FBQyxPQUFPLENBQUMsdUJBQVksRUFBRSxFQUFFLEtBQUssRUFBRSxDQUFDLEVBQUUsS0FBSyxFQUFFLEVBQUUsRUFBRSxLQUFLLEVBQUUsQ0FBQyxFQUFFLENBQUM7WUFDekYsSUFBSSxVQUFVLEVBQUU7Z0JBQ2YsSUFBSSxVQUFVLENBQUMsS0FBSyxLQUFLLEtBQUssSUFBSSxVQUFVLENBQUMsS0FBSyxLQUFLLEtBQUssRUFBRTtvQkFDN0QsTUFBTSxJQUFJLHNCQUFhLENBQUMsK0JBQWMsQ0FBQyxrQkFBa0IsRUFBRSxtQkFBVSxDQUFDLFdBQVcsQ0FBQztpQkFDbEY7cUJBQ0ksSUFBSSxVQUFVLENBQUMsS0FBSyxLQUFLLEtBQUssRUFBRTtvQkFDcEMsTUFBTSxJQUFJLHNCQUFhLENBQUMsK0JBQWMsQ0FBQyxVQUFVLEVBQUUsbUJBQVUsQ0FBQyxXQUFXLENBQUM7aUJBQzFFO3FCQUNJLElBQUksVUFBVSxDQUFDLEtBQUssS0FBSyxLQUFLLEVBQUU7b0JBQ3BDLE1BQU0sSUFBSSxzQkFBYSxDQUFDLCtCQUFjLENBQUMsVUFBVSxFQUFFLG1CQUFVLENBQUMsV0FBVyxDQUFDO2lCQUMxRTthQUNEO1lBQ0QsTUFBTSxVQUFVLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyx1QkFBWSxFQUFFO2dCQUMvQyxLQUFLO2dCQUNMLEtBQUs7Z0JBQ0wsS0FBSyxFQUFFLENBQUM7YUFDUixDQUFDO1lBQ0YsTUFBTSxTQUFTLEdBQUcsTUFBTSxPQUFPLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQztZQUVoRCxNQUFNLFlBQVksR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLHlCQUFjLEVBQUU7Z0JBQ25ELFFBQVEsRUFBRSxTQUFTLENBQUMsRUFBRTtnQkFDdEIsUUFBUTtnQkFDUixRQUFRLEVBQUUsWUFBWTtnQkFDdEIsSUFBSSxFQUFFLCtCQUFhLENBQUMsS0FBSzthQUN6QixDQUFDO1lBRUYsTUFBTSxXQUFXLEdBQUcsTUFBTSxPQUFPLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQztZQUNwRCxXQUFXLENBQUMsTUFBTSxHQUFHLFNBQVM7WUFFOUIsT0FBTyxXQUFXO1FBQ25CLENBQUMsQ0FBQztRQUVGLE9BQU8sUUFBUTtJQUNoQixDQUFDO0lBRUQsS0FBSyxDQUFDLEtBQUssQ0FBQyxRQUFrQjtRQUM3QixNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsYUFBYSxDQUFDLHlCQUFjLENBQUM7YUFDbEUsa0JBQWtCLENBQUMsVUFBVSxDQUFDO2FBQzlCLGlCQUFpQixDQUFDLGlCQUFpQixFQUFFLFFBQVEsQ0FBQzthQUM5QyxLQUFLLENBQUMsc0JBQXNCLEVBQUUsRUFBRSxRQUFRLEVBQUUsUUFBUSxDQUFDLFFBQVEsRUFBRSxDQUFDO2FBQzlELFFBQVEsQ0FBQyx3QkFBd0IsRUFBRSxFQUFFLE1BQU0sRUFBRSxRQUFRLENBQUMsTUFBTSxFQUFFLENBQUM7YUFDL0QsTUFBTSxFQUFFO1FBRVYsSUFBSSxDQUFDLFFBQVEsRUFBRTtZQUNkLE1BQU0sSUFBSSxzQkFBYSxDQUFDLDRCQUFXLENBQUMsb0JBQW9CLEVBQUUsbUJBQVUsQ0FBQyxXQUFXLENBQUM7U0FDakY7UUFFRCxNQUFNLGFBQWEsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLFFBQVEsRUFBRSxRQUFRLENBQUMsUUFBUSxDQUFDO1FBQ2hGLElBQUksQ0FBQyxhQUFhLEVBQUU7WUFDbkIsTUFBTSxJQUFJLHNCQUFhLENBQUMsNEJBQVcsQ0FBQyxhQUFhLEVBQUUsbUJBQVUsQ0FBQyxXQUFXLENBQUM7U0FDMUU7UUFFRCxPQUFPLFFBQVE7SUFDaEIsQ0FBQztJQUVELEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxZQUFvQjtRQUMxQyxNQUFNLEVBQUUsR0FBRyxFQUFFLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixDQUFDLGtCQUFrQixDQUFDLFlBQVksQ0FBQztRQUN0RSxNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsYUFBYSxDQUFDLHlCQUFjLENBQUM7YUFDbEUsa0JBQWtCLENBQUMsVUFBVSxDQUFDO2FBQzlCLGlCQUFpQixDQUFDLGlCQUFpQixFQUFFLFFBQVEsQ0FBQzthQUM5QyxLQUFLLENBQUMsbUJBQW1CLEVBQUUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLENBQUM7YUFDdkMsTUFBTSxFQUFFO1FBQ1YsTUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixDQUFDLGlCQUFpQixDQUFDLFFBQVEsQ0FBQztRQUNyRSxPQUFPLFdBQVc7SUFDbkIsQ0FBQztDQUNEO0FBNUVZLFdBQVc7SUFEdkIsdUJBQVUsR0FBRTt5REFHUyxvQkFBVSxvQkFBVixvQkFBVSxvREFDSixxQ0FBZ0Isb0JBQWhCLHFDQUFnQjtHQUgvQixXQUFXLENBNEV2QjtBQTVFWSxrQ0FBVzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDVnhCLDZFQUFrRTtBQUNsRSw2RUFBMkM7QUFDM0Msb0VBQXdDO0FBR3hDLHVHQUE4QztBQUM5QyxpSkFBNEU7QUFFckUsSUFBTSxnQkFBZ0IsR0FBdEIsTUFBTSxnQkFBZ0I7SUFDNUIsWUFDZ0MsU0FBdUMsRUFDckQsVUFBc0I7UUFEUixjQUFTLEdBQVQsU0FBUyxDQUE4QjtRQUNyRCxlQUFVLEdBQVYsVUFBVSxDQUFZO0lBQ3BDLENBQUM7SUFFTCxpQkFBaUIsQ0FBQyxJQUFnQjtRQUNqQyxNQUFNLFdBQVcsR0FBZ0I7WUFDaEMsTUFBTSxFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSztZQUN6QixHQUFHLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxFQUFFO1lBQ25CLEdBQUcsRUFBRSxJQUFJLENBQUMsRUFBRTtZQUNaLFFBQVEsRUFBRSxJQUFJLENBQUMsUUFBUTtZQUN2QixJQUFJLEVBQUUsSUFBSSxDQUFDLElBQUk7U0FDZjtRQUNELE9BQU8sSUFBSSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsV0FBVyxFQUFFO1lBQ3hDLE1BQU0sRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFNBQVM7WUFDaEMsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsVUFBVTtTQUNwQyxDQUFDO0lBQ0gsQ0FBQztJQUVELGtCQUFrQixDQUFDLEdBQVc7UUFDN0IsT0FBTyxJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxFQUFFLEdBQUcsRUFBRSxFQUFFO1lBQ3BDLE1BQU0sRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFVBQVU7WUFDakMsU0FBUyxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsV0FBVztTQUNyQyxDQUFDO0lBQ0gsQ0FBQztJQUVELG1CQUFtQixDQUFDLElBQWdCO1FBQ25DLE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLENBQUM7UUFDaEQsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLElBQUksQ0FBQyxFQUFFLENBQUM7UUFDckQsT0FBTyxFQUFFLFdBQVcsRUFBRSxZQUFZLEVBQUU7SUFDckMsQ0FBQztJQUVELGlCQUFpQixDQUFDLFdBQW1CO1FBQ3BDLElBQUk7WUFDSCxPQUFPLElBQUksQ0FBQyxVQUFVLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxFQUFFLE1BQU0sRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFNBQVMsRUFBRSxDQUFDO1NBQ2hGO1FBQUMsT0FBTyxLQUFLLEVBQUU7WUFDZixJQUFJLEtBQUssQ0FBQyxJQUFJLEtBQUssbUJBQW1CLEVBQUU7Z0JBQ3ZDLE1BQU0sSUFBSSxzQkFBYSxDQUFDLDRCQUFXLENBQUMsT0FBTyxFQUFFLG1CQUFVLENBQUMsWUFBWSxDQUFDO2FBQ3JFO2lCQUFNLElBQUksS0FBSyxDQUFDLElBQUksS0FBSyxtQkFBbUIsRUFBRTtnQkFDOUMsTUFBTSxJQUFJLHNCQUFhLENBQUMsNEJBQVcsQ0FBQyxPQUFPLEVBQUUsbUJBQVUsQ0FBQyxZQUFZLENBQUM7YUFDckU7WUFDRCxNQUFNLElBQUksc0JBQWEsQ0FBQyx1QkFBTSxDQUFDLE9BQU8sRUFBRSxtQkFBVSxDQUFDLHFCQUFxQixDQUFDO1NBQ3pFO0lBQ0YsQ0FBQztJQUVELGtCQUFrQixDQUFDLFlBQW9CO1FBQ3RDLElBQUk7WUFDSCxPQUFPLElBQUksQ0FBQyxVQUFVLENBQUMsTUFBTSxDQUFDLFlBQVksRUFBRSxFQUFFLE1BQU0sRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFVBQVUsRUFBRSxDQUFDO1NBQ2xGO1FBQUMsT0FBTyxLQUFLLEVBQUU7WUFDZixJQUFJLEtBQUssQ0FBQyxJQUFJLEtBQUssbUJBQW1CLEVBQUU7Z0JBQ3ZDLE1BQU0sSUFBSSxzQkFBYSxDQUFDLDRCQUFXLENBQUMsT0FBTyxFQUFFLG1CQUFVLENBQUMsU0FBUyxDQUFDO2FBQ2xFO2lCQUFNLElBQUksS0FBSyxDQUFDLElBQUksS0FBSyxtQkFBbUIsRUFBRTtnQkFDOUMsTUFBTSxJQUFJLHNCQUFhLENBQUMsNEJBQVcsQ0FBQyxPQUFPLEVBQUUsbUJBQVUsQ0FBQyxTQUFTLENBQUM7YUFDbEU7WUFDRCxNQUFNLElBQUksc0JBQWEsQ0FBQyx1QkFBTSxDQUFDLE9BQU8sRUFBRSxtQkFBVSxDQUFDLHFCQUFxQixDQUFDO1NBQ3pFO0lBQ0YsQ0FBQztDQUNEO0FBMURZLGdCQUFnQjtJQUUxQiw4QkFBTSxFQUFDLHdCQUFTLENBQUMsR0FBRyxDQUFDO3lEQUFvQixtQkFBVSxvQkFBVixtQkFBVSxvREFDdkIsZ0JBQVUsb0JBQVYsZ0JBQVU7R0FINUIsZ0JBQWdCLENBMEQ1QjtBQTFEWSw0Q0FBZ0I7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1I3Qiw2RUFBa0Y7QUFDbEYsd0hBQWdEO0FBQ2hELDRHQUErRDtBQUMvRCxnRkFBd0Q7QUFLakQsSUFBTSxnQkFBZ0IsR0FBdEIsTUFBTSxnQkFBZ0I7SUFDNUIsWUFBNkIsYUFBNEI7UUFBNUIsa0JBQWEsR0FBYixhQUFhLENBQWU7SUFBSSxDQUFDO0lBRzlELE1BQU0sQ0FBUyxlQUFnQztRQUM5QyxPQUFPLEVBQUU7SUFDVixDQUFDO0lBR0QsT0FBTztRQUNOLE9BQU8sSUFBSSxDQUFDLGFBQWEsQ0FBQyxPQUFPLEVBQUU7SUFDcEMsQ0FBQztJQUdELE9BQU8sQ0FBYyxFQUFVO1FBQzlCLE9BQU8sSUFBSSxDQUFDLGFBQWEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxFQUFFLENBQUM7SUFDdkMsQ0FBQztJQUdELE1BQU0sQ0FBYyxFQUFVO1FBQzdCLE9BQU8sSUFBSSxDQUFDLGFBQWEsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUM7SUFDdEMsQ0FBQztDQUNEO0FBbkJBO0lBQUMsaUJBQUksR0FBRTtJQUNDLDRCQUFJLEdBQUU7O3lEQUFrQiw0QkFBZSxvQkFBZiw0QkFBZTs7OENBRTlDO0FBRUQ7SUFBQyxnQkFBRyxHQUFFOzs7OytDQUdMO0FBRUQ7SUFBQyxnQkFBRyxFQUFDLEtBQUssQ0FBQztJQUNGLDZCQUFLLEVBQUMsSUFBSSxDQUFDOzs7OytDQUVuQjtBQUVEO0lBQUMsbUJBQU0sRUFBQyxLQUFLLENBQUM7SUFDTiw2QkFBSyxFQUFDLElBQUksQ0FBQzs7Ozs4Q0FFbEI7QUFyQlcsZ0JBQWdCO0lBSDVCLHFCQUFPLEVBQUMsUUFBUSxDQUFDO0lBQ2pCLDJCQUFhLEVBQUMsY0FBYyxDQUFDO0lBQzdCLHVCQUFVLEVBQUMsUUFBUSxDQUFDO3lEQUV3Qiw4QkFBYSxvQkFBYiw4QkFBYTtHQUQ3QyxnQkFBZ0IsQ0FzQjVCO0FBdEJZLDRDQUFnQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNSN0IsZ0ZBQTZDO0FBQzdDLHdGQUFpRDtBQUVqRCxNQUFhLGVBQWU7Q0FTM0I7QUFSQTtJQUFDLDZCQUFPLEdBQUU7OzhDQUNHO0FBRWI7SUFBQyw0QkFBTSxFQUFDLEVBQUUsRUFBRSxFQUFFLENBQUM7OzhDQUNGO0FBRWI7SUFBQyw0QkFBTSxFQUFDLENBQUMsQ0FBQzs7aURBQ007QUFSakIsMENBU0M7QUFFRCxNQUFhLGVBQWdCLFNBQVEseUJBQVcsRUFBQyxlQUFlLENBQUM7Q0FBSTtBQUFyRSwwQ0FBcUU7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDZHJFLDZFQUF1QztBQUN2QyxnRkFBK0M7QUFDL0Msd0lBQXdFO0FBQ3hFLGlJQUFzRDtBQUN0RCx3SEFBZ0Q7QUFRekMsSUFBTSxZQUFZLEdBQWxCLE1BQU0sWUFBWTtDQUFJO0FBQWhCLFlBQVk7SUFOeEIsbUJBQU0sRUFBQztRQUNQLE9BQU8sRUFBRSxDQUFDLHVCQUFhLENBQUMsVUFBVSxDQUFDLENBQUMsdUJBQVksQ0FBQyxDQUFDLENBQUM7UUFDbkQsV0FBVyxFQUFFLENBQUMsb0NBQWdCLENBQUM7UUFDL0IsU0FBUyxFQUFFLENBQUMsOEJBQWEsQ0FBQztRQUMxQixPQUFPLEVBQUUsQ0FBQyw4QkFBYSxDQUFDO0tBQ3hCLENBQUM7R0FDVyxZQUFZLENBQUk7QUFBaEIsb0NBQVk7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1p6Qiw2RUFBMkM7QUFDM0MsZ0ZBQWtEO0FBQ2xELGdFQUFnRDtBQUNoRCx3SUFBd0U7QUFHakUsSUFBTSxhQUFhLEdBQW5CLE1BQU0sYUFBYTtJQUN6QixZQUN5QyxnQkFBMEMsRUFDMUUsVUFBc0I7UUFEVSxxQkFBZ0IsR0FBaEIsZ0JBQWdCLENBQTBCO1FBQzFFLGVBQVUsR0FBVixVQUFVLENBQVk7SUFDM0IsQ0FBQztJQUVMLE9BQU87UUFDTixPQUFPLGdDQUFnQztJQUN4QyxDQUFDO0lBRUQsT0FBTyxDQUFDLEVBQVU7UUFDakIsT0FBTywwQkFBMEIsRUFBRSxTQUFTO0lBQzdDLENBQUM7SUFFRCxNQUFNLENBQUMsRUFBVTtRQUNoQixPQUFPLDBCQUEwQixFQUFFLFNBQVM7SUFDN0MsQ0FBQztJQUVELE1BQU0sQ0FBQyxFQUFVO1FBQ2hCLE9BQU8sMEJBQTBCLEVBQUUsU0FBUztJQUM3QyxDQUFDO0NBQ0Q7QUFyQlksYUFBYTtJQUR6Qix1QkFBVSxHQUFFO0lBR1YseUNBQWdCLEVBQUMsdUJBQVksQ0FBQzt5REFBMkIsb0JBQVUsb0JBQVYsb0JBQVUsb0RBQ2hELG9CQUFVLG9CQUFWLG9CQUFVO0dBSG5CLGFBQWEsQ0FxQnpCO0FBckJZLHNDQUFhOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNOMUIsNkVBQXVGO0FBQ3ZGLHVHQUEyRDtBQUMzRCx1R0FBc0U7QUFDdEUsZ0ZBQWtFO0FBQ2xFLDRHQUFxRDtBQUNyRCxvSEFBcUU7QUFDckUsZ0lBQW9EO0FBTTdDLElBQU0sa0JBQWtCLEdBQXhCLE1BQU0sa0JBQWtCO0lBQzlCLFlBQTZCLGVBQWdDO1FBQWhDLG9CQUFlLEdBQWYsZUFBZSxDQUFpQjtJQUFJLENBQUM7SUFHbEUsT0FBTyxDQUFRLE9BQXFCO1FBQ25DLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQztJQUM5QyxDQUFDO0lBR0QsTUFBTSxDQUFTLGlCQUFvQyxFQUFTLE9BQXFCO1FBQ2hGLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLFFBQVEsRUFBRSxpQkFBaUIsQ0FBQztJQUNoRSxDQUFDO0lBSUQsT0FBTyxDQUFjLEVBQVUsRUFBUyxPQUFxQjtRQUM1RCxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUc7UUFDekMsT0FBTyxJQUFJLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDbkQsQ0FBQztJQUlLLEtBQUQsQ0FBQyxNQUFNLENBQWMsRUFBVSxFQUFTLE9BQXFCLEVBQVUsaUJBQW9DO1FBQy9HLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxNQUFNLElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLFFBQVEsRUFBRSxDQUFDLEVBQUUsRUFBRSxpQkFBaUIsQ0FBQztRQUNuRSxPQUFPLEVBQUUsT0FBTyxFQUFFLFNBQVMsRUFBRTtJQUM5QixDQUFDO0lBSUssS0FBRCxDQUFDLE1BQU0sQ0FBYyxFQUFVLEVBQVMsT0FBcUI7UUFDakUsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLE1BQU0sSUFBSSxDQUFDLGVBQWUsQ0FBQyxNQUFNLENBQUMsUUFBUSxFQUFFLENBQUMsRUFBRSxDQUFDO1FBQ2hELE9BQU8sRUFBRSxPQUFPLEVBQUUsU0FBUyxFQUFFO0lBQzlCLENBQUM7SUFJSyxLQUFELENBQUMsT0FBTyxDQUFjLEVBQVUsRUFBUyxPQUFxQjtRQUNsRSxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUc7UUFDekMsTUFBTSxJQUFJLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsQ0FBQyxFQUFFLENBQUM7UUFDakQsT0FBTyxFQUFFLE9BQU8sRUFBRSxTQUFTLEVBQUU7SUFDOUIsQ0FBQztDQUNEO0FBMUNBO0lBQUMsZ0JBQUcsR0FBRTtJQUNHLDJCQUFHLEdBQUU7O3lEQUFVLHdCQUFZLG9CQUFaLHdCQUFZOztpREFHbkM7QUFFRDtJQUFDLGlCQUFJLEdBQUU7SUFDQyw0QkFBSSxHQUFFO0lBQXdDLDJCQUFHLEdBQUU7O3lEQUF6QixnQ0FBaUIsb0JBQWpCLGdDQUFpQixvREFBa0Isd0JBQVksb0JBQVosd0JBQVk7O2dEQUdoRjtBQUVEO0lBQUMsZ0JBQUcsRUFBQyxLQUFLLENBQUM7SUFDVixzQkFBUSxFQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDNUIsNkJBQUssRUFBQyxJQUFJLENBQUM7SUFBYywyQkFBRyxHQUFFOztpRUFBVSx3QkFBWSxvQkFBWix3QkFBWTs7aURBRzVEO0FBSUs7SUFGTCxrQkFBSyxFQUFDLFlBQVksQ0FBQztJQUNuQixzQkFBUSxFQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDdkIsNkJBQUssRUFBQyxJQUFJLENBQUM7SUFBYywyQkFBRyxHQUFFO0lBQXlCLDRCQUFJLEdBQUU7O2lFQUFyQix3QkFBWSxvQkFBWix3QkFBWSxvREFBNkIsZ0NBQWlCLG9CQUFqQixnQ0FBaUI7O2dEQUkvRztBQUlLO0lBRkwsbUJBQU0sRUFBQyxZQUFZLENBQUM7SUFDcEIsc0JBQVEsRUFBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUMsRUFBRSxDQUFDO0lBQ3ZCLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsMkJBQUcsR0FBRTs7aUVBQVUsd0JBQVksb0JBQVosd0JBQVk7O2dEQUlqRTtBQUlLO0lBRkwsa0JBQUssRUFBQyxhQUFhLENBQUM7SUFDcEIsc0JBQVEsRUFBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUMsRUFBRSxDQUFDO0lBQ3RCLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsMkJBQUcsR0FBRTs7aUVBQVUsd0JBQVksb0JBQVosd0JBQVk7O2lEQUlsRTtBQTVDVyxrQkFBa0I7SUFKOUIscUJBQU8sRUFBQyxVQUFVLENBQUM7SUFDbkIsMkJBQWEsRUFBQyxjQUFjLENBQUM7SUFDN0IsZ0NBQWUsRUFBQyx1Q0FBMEIsQ0FBQztJQUMzQyx1QkFBVSxFQUFDLFVBQVUsQ0FBQzt5REFFd0Isa0NBQWUsb0JBQWYsa0NBQWU7R0FEakQsa0JBQWtCLENBNkM5QjtBQTdDWSxnREFBa0I7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDWi9CLGdGQUEwRDtBQUMxRCx3RkFBc0Q7QUFFdEQsTUFBYSxpQkFBaUI7Q0FZN0I7QUFYQTtJQUFDLHlCQUFXLEVBQUMsRUFBRSxPQUFPLEVBQUUsZUFBZSxFQUFFLENBQUM7SUFDekMsK0JBQVMsR0FBRTs7bURBQ0k7QUFFaEI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQ3RDLCtCQUFTLEdBQUU7SUFDWCwrQkFBUyxFQUFDLENBQUMsQ0FBQzs7bURBQ0c7QUFFaEI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLGdCQUFnQixFQUFFLENBQUM7O21EQUMzQjtBQVhqQiw4Q0FZQztBQUVELE1BQWEsaUJBQWtCLFNBQVEseUJBQVcsRUFBQyxpQkFBaUIsQ0FBQztDQUFJO0FBQXpFLDhDQUF5RTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNqQnpFLDZFQUF1QztBQUN2QyxnRkFBK0M7QUFFL0MsOElBQTRFO0FBQzVFLHlJQUEwRDtBQUMxRCxnSUFBb0Q7QUFPN0MsSUFBTSxjQUFjLEdBQXBCLE1BQU0sY0FBYztDQUFJO0FBQWxCLGNBQWM7SUFMMUIsbUJBQU0sRUFBQztRQUNQLE9BQU8sRUFBRSxDQUFDLHVCQUFhLENBQUMsVUFBVSxDQUFDLENBQUMseUJBQWMsQ0FBQyxDQUFDLENBQUM7UUFDckQsV0FBVyxFQUFFLENBQUMsd0NBQWtCLENBQUM7UUFDakMsU0FBUyxFQUFFLENBQUMsa0NBQWUsQ0FBQztLQUM1QixDQUFDO0dBQ1csY0FBYyxDQUFJO0FBQWxCLHdDQUFjOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNaM0IsNkVBQTJDO0FBQzNDLHdGQUFpRDtBQUNqRCx1R0FBeUQ7QUFDekQsZ0ZBQWtEO0FBQ2xELDJEQUFnQztBQUNoQyw4RkFBZ0Q7QUFDaEQsZ0VBQW9DO0FBQ3BDLDhJQUErRjtBQUMvRixpSkFBdUY7QUFJaEYsSUFBTSxlQUFlLEdBQXJCLE1BQU0sZUFBZTtJQUMzQixZQUFzRCxrQkFBOEM7UUFBOUMsdUJBQWtCLEdBQWxCLGtCQUFrQixDQUE0QjtJQUFJLENBQUM7SUFFekcsS0FBSyxDQUFDLE9BQU8sQ0FBQyxRQUFnQjtRQUM3QixPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLElBQUksQ0FBQyxFQUFFLEtBQUssRUFBRSxFQUFFLFFBQVEsRUFBRSxFQUFFLENBQUM7SUFDbkUsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxpQkFBb0M7UUFDbEUsTUFBTSxZQUFZLEdBQUcsTUFBTSxJQUFJLENBQUMsa0JBQWtCLENBQUMsU0FBUyxDQUFDO1lBQzVELFFBQVE7WUFDUixRQUFRLEVBQUUsaUJBQWlCLENBQUMsUUFBUTtTQUNwQyxDQUFDO1FBQ0YsSUFBSSxZQUFZLEVBQUU7WUFDakIsTUFBTSxJQUFJLDBCQUFhLENBQUMsK0JBQWMsQ0FBQyxhQUFhLEVBQUUsa0JBQVUsQ0FBQyxXQUFXLENBQUM7U0FDN0U7UUFDRCxNQUFNLFlBQVksR0FBRyxvQ0FBWSxFQUFDLHlCQUFjLEVBQUUsaUJBQWlCLENBQUM7UUFDcEUsWUFBWSxDQUFDLFFBQVEsR0FBRyxNQUFNLE1BQU0sQ0FBQyxJQUFJLENBQUMsaUJBQWlCLENBQUMsUUFBUSxFQUFFLENBQUMsQ0FBQztRQUN4RSxZQUFZLENBQUMsSUFBSSxHQUFHLCtCQUFhLENBQUMsSUFBSTtRQUN0QyxPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQztJQUM3RCxDQUFDO0lBRUQsS0FBSyxDQUFDLE9BQU8sQ0FBQyxRQUFnQixFQUFFLEVBQVU7UUFDekMsT0FBTyxNQUFNLElBQUksQ0FBQyxrQkFBa0IsQ0FBQyxTQUFTLENBQUMsRUFBRSxRQUFRLEVBQUUsRUFBRSxFQUFFLENBQUM7SUFDakUsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxFQUFVLEVBQUUsaUJBQW9DO1FBQzlFLE1BQU0sWUFBWSxHQUFHLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLFNBQVMsQ0FBQyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsQ0FBQztRQUM5RSxJQUFJLENBQUMsWUFBWSxFQUFFO1lBQ2xCLE1BQU0sSUFBSSwwQkFBYSxDQUFDLCtCQUFjLENBQUMsU0FBUyxFQUFFLGtCQUFVLENBQUMsV0FBVyxDQUFDO1NBQ3pFO1FBQ0QsT0FBTyxNQUFNLElBQUksQ0FBQyxrQkFBa0IsQ0FBQyxNQUFNLENBQUMsRUFBRSxRQUFRLEVBQUUsRUFBRSxFQUFFLEVBQUUsaUJBQWlCLENBQUM7SUFDakYsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxVQUFrQjtRQUNoRCxPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLFVBQVUsQ0FBQztZQUMvQyxRQUFRO1lBQ1IsRUFBRSxFQUFFLFVBQVU7U0FDZCxDQUFDO0lBQ0gsQ0FBQztJQUVELEtBQUssQ0FBQyxPQUFPLENBQUMsUUFBZ0IsRUFBRSxVQUFrQjtRQUNqRCxPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLE9BQU8sQ0FBQztZQUM1QyxRQUFRO1lBQ1IsRUFBRSxFQUFFLFVBQVU7U0FDZCxDQUFDO0lBQ0gsQ0FBQztDQUNEO0FBOUNZLGVBQWU7SUFEM0IsdUJBQVUsR0FBRTtJQUVDLHlDQUFnQixFQUFDLHlCQUFjLENBQUM7eURBQTZCLG9CQUFVLG9CQUFWLG9CQUFVO0dBRHhFLGVBQWUsQ0E4QzNCO0FBOUNZLDBDQUFlOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNaNUIsNkVBQWdEO0FBQ2hELGdGQUF5QztBQUN6QyxtRkFHeUI7QUFJbEIsSUFBTSxnQkFBZ0IsR0FBdEIsTUFBTSxnQkFBZ0I7SUFDNUIsWUFDa0IsTUFBMEIsRUFDMUIsSUFBeUIsRUFDekIsRUFBMEIsRUFDMUIsSUFBeUIsRUFDekIsTUFBNkI7UUFKN0IsV0FBTSxHQUFOLE1BQU0sQ0FBb0I7UUFDMUIsU0FBSSxHQUFKLElBQUksQ0FBcUI7UUFDekIsT0FBRSxHQUFGLEVBQUUsQ0FBd0I7UUFDMUIsU0FBSSxHQUFKLElBQUksQ0FBcUI7UUFDekIsV0FBTSxHQUFOLE1BQU0sQ0FBdUI7SUFDM0MsQ0FBQztJQUlMLEtBQUs7UUFDSixPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDO1lBQ3hCLEdBQUcsRUFBRSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLGFBQWEsRUFBRSw4QkFBOEIsQ0FBQztZQUN4RSxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLFNBQVMsQ0FBQyxVQUFVLENBQUM7WUFDbkMsR0FBRyxFQUFFLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsU0FBUyxFQUFFLEVBQUUsSUFBSSxFQUFFLEdBQUcsRUFBRSxnQkFBZ0IsRUFBRSxHQUFHLEVBQUUsQ0FBQztZQUM3RSxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxhQUFhLEVBQUUsR0FBRyxHQUFHLElBQUksR0FBRyxJQUFJLENBQUM7WUFDN0QsR0FBRyxFQUFFLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsWUFBWSxFQUFFLEdBQUcsR0FBRyxJQUFJLEdBQUcsSUFBSSxDQUFDO1NBQzNELENBQUM7SUFDSCxDQUFDO0NBQ0Q7QUFYQTtJQUFDLGdCQUFHLEdBQUU7SUFDTCwwQkFBVyxHQUFFOzs7OzZDQVNiO0FBbkJXLGdCQUFnQjtJQUY1QixxQkFBTyxFQUFDLFFBQVEsQ0FBQztJQUNqQix1QkFBVSxFQUFDLFFBQVEsQ0FBQzt5REFHTSw2QkFBa0Isb0JBQWxCLDZCQUFrQixvREFDcEIsOEJBQW1CLG9CQUFuQiw4QkFBbUIsb0RBQ3JCLGlDQUFzQixvQkFBdEIsaUNBQXNCLG9EQUNwQiw4QkFBbUIsb0JBQW5CLDhCQUFtQixvREFDakIsZ0NBQXFCLG9CQUFyQixnQ0FBcUI7R0FObkMsZ0JBQWdCLENBb0I1QjtBQXBCWSw0Q0FBZ0I7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDVDdCLDBFQUEwQztBQUMxQyw2RUFBdUM7QUFDdkMsbUZBQWlEO0FBQ2pELGlJQUFzRDtBQU0vQyxJQUFNLFlBQVksR0FBbEIsTUFBTSxZQUFZO0NBQUk7QUFBaEIsWUFBWTtJQUp4QixtQkFBTSxFQUFDO1FBQ1AsT0FBTyxFQUFFLENBQUMseUJBQWMsRUFBRSxrQkFBVSxDQUFDO1FBQ3JDLFdBQVcsRUFBRSxDQUFDLG9DQUFnQixDQUFDO0tBQy9CLENBQUM7R0FDVyxZQUFZLENBQUk7QUFBaEIsb0NBQVk7Ozs7Ozs7Ozs7Ozs7O0FDVHpCLE1BQWEsaUJBQWlCO0NBQUc7QUFBakMsOENBQWlDOzs7Ozs7Ozs7Ozs7OztBQ0FqQyxnRkFBNkM7QUFDN0MsNklBQXlEO0FBRXpELE1BQWEsaUJBQWtCLFNBQVEseUJBQVcsRUFBQyx1Q0FBaUIsQ0FBQztDQUFHO0FBQXhFLDhDQUF3RTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDSHhFLDZFQUFrRjtBQUNsRixnRkFBd0Q7QUFDeEQsaUpBQTZEO0FBQzdELGlKQUE2RDtBQUM3RCxnSUFBb0Q7QUFLN0MsSUFBTSxrQkFBa0IsR0FBeEIsTUFBTSxrQkFBa0I7SUFDOUIsWUFBNkIsZUFBZ0M7UUFBaEMsb0JBQWUsR0FBZixlQUFlLENBQWlCO0lBQUksQ0FBQztJQUdsRSxNQUFNLENBQVMsaUJBQW9DO1FBQ2xELE9BQU8sSUFBSSxDQUFDLGVBQWUsQ0FBQyxNQUFNLENBQUMsaUJBQWlCLENBQUM7SUFDdEQsQ0FBQztJQUdELE9BQU87UUFDTixPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsT0FBTyxFQUFFO0lBQ3RDLENBQUM7SUFHRCxPQUFPLENBQWMsRUFBVTtRQUM5QixPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsT0FBTyxDQUFDLENBQUMsRUFBRSxDQUFDO0lBQ3pDLENBQUM7SUFHRCxNQUFNLENBQWMsRUFBVSxFQUFVLGlCQUFvQztRQUMzRSxPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxFQUFFLGlCQUFpQixDQUFDO0lBQzNELENBQUM7SUFHRCxNQUFNLENBQWMsRUFBVTtRQUM3QixPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxDQUFDO0lBQ3hDLENBQUM7Q0FDRDtBQXhCQTtJQUFDLGlCQUFJLEdBQUU7SUFDQyw0QkFBSSxHQUFFOzt5REFBb0IsdUNBQWlCLG9CQUFqQix1Q0FBaUI7O2dEQUVsRDtBQUVEO0lBQUMsZ0JBQUcsR0FBRTs7OztpREFHTDtBQUVEO0lBQUMsZ0JBQUcsRUFBQyxLQUFLLENBQUM7SUFDRiw2QkFBSyxFQUFDLElBQUksQ0FBQzs7OztpREFFbkI7QUFFRDtJQUFDLGtCQUFLLEVBQUMsS0FBSyxDQUFDO0lBQ0wsNkJBQUssRUFBQyxJQUFJLENBQUM7SUFBYyw0QkFBSSxHQUFFOztpRUFBb0IsdUNBQWlCLG9CQUFqQix1Q0FBaUI7O2dEQUUzRTtBQUVEO0lBQUMsbUJBQU0sRUFBQyxLQUFLLENBQUM7SUFDTiw2QkFBSyxFQUFDLElBQUksQ0FBQzs7OztnREFFbEI7QUExQlcsa0JBQWtCO0lBSDlCLHFCQUFPLEVBQUMsVUFBVSxDQUFDO0lBQ25CLDJCQUFhLEVBQUMsY0FBYyxDQUFDO0lBQzdCLHVCQUFVLEVBQUMsVUFBVSxDQUFDO3lEQUV3QixrQ0FBZSxvQkFBZixrQ0FBZTtHQURqRCxrQkFBa0IsQ0EyQjlCO0FBM0JZLGdEQUFrQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNUL0IsNkVBQXVDO0FBQ3ZDLGdGQUErQztBQUMvQyw4SUFBNEU7QUFDNUUseUlBQTBEO0FBQzFELGdJQUFvRDtBQU83QyxJQUFNLGNBQWMsR0FBcEIsTUFBTSxjQUFjO0NBQUk7QUFBbEIsY0FBYztJQUwxQixtQkFBTSxFQUFDO1FBQ1AsT0FBTyxFQUFFLENBQUMsdUJBQWEsQ0FBQyxVQUFVLENBQUMsQ0FBQyx5QkFBYyxDQUFDLENBQUMsQ0FBQztRQUNyRCxXQUFXLEVBQUUsQ0FBQyx3Q0FBa0IsQ0FBQztRQUNqQyxTQUFTLEVBQUUsQ0FBQyxrQ0FBZSxDQUFDO0tBQzVCLENBQUM7R0FDVyxjQUFjLENBQUk7QUFBbEIsd0NBQWM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDWDNCLDZFQUEyQztBQUtwQyxJQUFNLGVBQWUsR0FBckIsTUFBTSxlQUFlO0lBQzNCLE1BQU0sQ0FBQyxpQkFBb0M7UUFDMUMsT0FBTyxpQ0FBaUM7SUFDekMsQ0FBQztJQUVELE9BQU87UUFDTixPQUFPLGtDQUFrQztJQUMxQyxDQUFDO0lBRUQsT0FBTyxDQUFDLEVBQVU7UUFDakIsT0FBTywwQkFBMEIsRUFBRSxXQUFXO0lBQy9DLENBQUM7SUFFRCxNQUFNLENBQUMsRUFBVSxFQUFFLGlCQUFvQztRQUN0RCxPQUFPLDBCQUEwQixFQUFFLFdBQVc7SUFDL0MsQ0FBQztJQUVELE1BQU0sQ0FBQyxFQUFVO1FBQ2hCLE9BQU8sMEJBQTBCLEVBQUUsV0FBVztJQUMvQyxDQUFDO0NBQ0Q7QUFwQlksZUFBZTtJQUQzQix1QkFBVSxHQUFFO0dBQ0EsZUFBZSxDQW9CM0I7QUFwQlksMENBQWU7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ0w1Qiw2RUFBMkk7QUFDM0ksZ0ZBQTRFO0FBQzVFLDRHQUFxRDtBQUNyRCxnSEFBa0U7QUFDbEUsNEhBQWtEO0FBTTNDLElBQU0saUJBQWlCLEdBQXZCLE1BQU0saUJBQWlCO0lBQzdCLFlBQTZCLGNBQThCO1FBQTlCLG1CQUFjLEdBQWQsY0FBYyxDQUFnQjtJQUFJLENBQUM7SUFHaEUsT0FBTyxDQUFRLE9BQXFCO1FBQ25DLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxPQUFPLElBQUksQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQztJQUM3QyxDQUFDO0lBSUQsTUFBTSxDQUFzQixVQUFrQixFQUFTLE9BQXFCO1FBQzNFLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxJQUFJLE9BQU8sQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLEVBQUU7WUFDN0IsT0FBTyxJQUFJLENBQUMsY0FBYyxDQUFDLFdBQVcsQ0FBQyxRQUFRLEVBQUUsVUFBVSxDQUFDO1NBQzVEO1FBQ0QsT0FBTyxJQUFJLENBQUMsY0FBYyxDQUFDLGNBQWMsQ0FBQyxRQUFRLEVBQUUsVUFBVSxDQUFDO0lBQ2hFLENBQUM7SUFHRCxNQUFNLENBQVMsZ0JBQWtDLEVBQVMsT0FBcUI7UUFDOUUsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLE9BQU8sSUFBSSxDQUFDLGNBQWMsQ0FBQyxNQUFNLENBQUMsUUFBUSxFQUFFLGdCQUFnQixDQUFDO0lBQzlELENBQUM7SUFJRCxPQUFPLENBQWMsRUFBVSxFQUFTLE9BQXFCO1FBQzVELE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxPQUFPLElBQUksQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxDQUFDLEVBQUUsQ0FBQztJQUNsRCxDQUFDO0lBSUssS0FBRCxDQUFDLE1BQU0sQ0FBYyxFQUFVLEVBQVUsZ0JBQWtDLEVBQVMsT0FBcUI7UUFDN0csTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLE1BQU0sSUFBSSxDQUFDLGNBQWMsQ0FBQyxNQUFNLENBQUMsUUFBUSxFQUFFLENBQUMsRUFBRSxFQUFFLGdCQUFnQixDQUFDO1FBQ2pFLE9BQU8sRUFBRSxPQUFPLEVBQUUsU0FBUyxFQUFFO0lBQzlCLENBQUM7SUFJSyxLQUFELENBQUMsTUFBTSxDQUFjLEVBQVUsRUFBUyxPQUFxQjtRQUNqRSxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUc7UUFDekMsTUFBTSxJQUFJLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FBQyxRQUFRLEVBQUUsQ0FBQyxFQUFFLENBQUM7UUFDL0MsT0FBTyxFQUFFLE9BQU8sRUFBRSxTQUFTLEVBQUU7SUFDOUIsQ0FBQztJQUlLLEtBQUQsQ0FBQyxPQUFPLENBQWMsRUFBVSxFQUFTLE9BQXFCO1FBQ2xFLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxNQUFNLElBQUksQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxDQUFDLEVBQUUsQ0FBQztRQUNoRCxPQUFPLEVBQUUsT0FBTyxFQUFFLFNBQVMsRUFBRTtJQUM5QixDQUFDO0NBQ0Q7QUFwREE7SUFBQyxnQkFBRyxHQUFFO0lBQ0csMkJBQUcsR0FBRTs7eURBQVUsd0JBQVksb0JBQVosd0JBQVk7O2dEQUduQztBQUVEO0lBQUMsZ0JBQUcsRUFBQyxRQUFRLENBQUM7SUFDYixzQkFBUSxFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDaEQsNkJBQUssRUFBQyxZQUFZLENBQUM7SUFBc0IsMkJBQUcsR0FBRTs7aUVBQVUsd0JBQVksb0JBQVosd0JBQVk7OytDQU0zRTtBQUVEO0lBQUMsaUJBQUksR0FBRTtJQUNDLDRCQUFJLEdBQUU7SUFBc0MsMkJBQUcsR0FBRTs7eURBQXhCLDhCQUFnQixvQkFBaEIsOEJBQWdCLG9EQUFrQix3QkFBWSxvQkFBWix3QkFBWTs7K0NBRzlFO0FBRUQ7SUFBQyxnQkFBRyxFQUFDLEtBQUssQ0FBQztJQUNWLHNCQUFRLEVBQUMsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE9BQU8sRUFBRSxDQUFDLEVBQUUsQ0FBQztJQUM1Qiw2QkFBSyxFQUFDLElBQUksQ0FBQztJQUFjLDJCQUFHLEdBQUU7O2lFQUFVLHdCQUFZLG9CQUFaLHdCQUFZOztnREFHNUQ7QUFJSztJQUZMLGtCQUFLLEVBQUMsWUFBWSxDQUFDO0lBQ25CLHNCQUFRLEVBQUMsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE9BQU8sRUFBRSxDQUFDLEVBQUUsQ0FBQztJQUN2Qiw2QkFBSyxFQUFDLElBQUksQ0FBQztJQUFjLDRCQUFJLEdBQUU7SUFBc0MsMkJBQUcsR0FBRTs7aUVBQXhCLDhCQUFnQixvQkFBaEIsOEJBQWdCLG9EQUFrQix3QkFBWSxvQkFBWix3QkFBWTs7K0NBSTdHO0FBSUs7SUFGTCxtQkFBTSxFQUFDLFlBQVksQ0FBQztJQUNwQixzQkFBUSxFQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDdkIsNkJBQUssRUFBQyxJQUFJLENBQUM7SUFBYywyQkFBRyxHQUFFOztpRUFBVSx3QkFBWSxvQkFBWix3QkFBWTs7K0NBSWpFO0FBSUs7SUFGTCxrQkFBSyxFQUFDLGFBQWEsQ0FBQztJQUNwQixzQkFBUSxFQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDdEIsNkJBQUssRUFBQyxJQUFJLENBQUM7SUFBYywyQkFBRyxHQUFFOztpRUFBVSx3QkFBWSxvQkFBWix3QkFBWTs7Z0RBSWxFO0FBdERXLGlCQUFpQjtJQUo3QixxQkFBTyxFQUFDLFNBQVMsQ0FBQztJQUNsQiwyQkFBYSxFQUFDLGNBQWMsQ0FBQztJQUM3Qiw0QkFBZSxFQUFDLG1DQUEwQixDQUFDO0lBQzNDLHVCQUFVLEVBQUMsU0FBUyxDQUFDO3lEQUV3QixnQ0FBYyxvQkFBZCxnQ0FBYztHQUQvQyxpQkFBaUIsQ0F1RDdCO0FBdkRZLDhDQUFpQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDVjlCLGdGQUFrRTtBQUNsRSx3RkFBcUQ7QUFDckQsZ0hBQTREO0FBQzVELG1KQUE2RDtBQUU3RCxNQUFhLGdCQUFnQjtDQWlCNUI7QUFoQkE7SUFBQyxpQ0FBbUIsRUFBQyxFQUFFLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxDQUFDO0lBQ2xELCtCQUFTLEdBQUU7O2tEQUNJO0FBRWhCO0lBQUMsaUNBQW1CLEVBQUMsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDOUMsOEJBQVEsRUFBQyxnQ0FBTyxDQUFDOzsrQ0FDTDtBQUViO0lBQUMsaUNBQW1CLEVBQUMsRUFBRSxPQUFPLEVBQUUscUJBQU8sQ0FBQyxNQUFNLEVBQUUsQ0FBQztrREFDekMscUJBQU8sb0JBQVAscUJBQU87Z0RBQUE7QUFFZjtJQUFDLGlDQUFtQixFQUFDLEVBQUUsT0FBTyxFQUFFLHVGQUF1RixFQUFFLENBQUM7O2lEQUMzRztBQUVmO0lBQUMsaUNBQW1CLEVBQUMsRUFBRSxPQUFPLEVBQUUsMEJBQTBCLEVBQUUsQ0FBQztrREFDbkQsSUFBSSxvQkFBSixJQUFJO2tEQUFBO0FBaEJmLDRDQWlCQztBQUVELE1BQWEsZ0JBQWlCLFNBQVEseUJBQVcsRUFBQyxnQkFBZ0IsQ0FBQztDQUFJO0FBQXZFLDRDQUF1RTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUN4QnZFLDZFQUF1QztBQUN2QyxnRkFBK0M7QUFDL0MsMklBQTBFO0FBQzFFLHFJQUF3RDtBQUN4RCw0SEFBa0Q7QUFPM0MsSUFBTSxhQUFhLEdBQW5CLE1BQU0sYUFBYTtDQUFJO0FBQWpCLGFBQWE7SUFMekIsbUJBQU0sRUFBQztRQUNQLE9BQU8sRUFBRSxDQUFDLHVCQUFhLENBQUMsVUFBVSxDQUFDLENBQUMsd0JBQWEsQ0FBQyxDQUFDLENBQUM7UUFDcEQsV0FBVyxFQUFFLENBQUMsc0NBQWlCLENBQUM7UUFDaEMsU0FBUyxFQUFFLENBQUMsZ0NBQWMsQ0FBQztLQUMzQixDQUFDO0dBQ1csYUFBYSxDQUFJO0FBQWpCLHNDQUFhOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNYMUIsNkVBQXVEO0FBQ3ZELHVHQUF5RDtBQUN6RCxnRkFBa0Q7QUFDbEQsZ0VBQWlEO0FBQ2pELDJJQUEwRTtBQUMxRSxpSkFBc0U7QUFJL0QsSUFBTSxjQUFjLEdBQXBCLE1BQU0sY0FBYztJQUMxQixZQUFxRCxpQkFBNEM7UUFBNUMsc0JBQWlCLEdBQWpCLGlCQUFpQixDQUEyQjtJQUFJLENBQUM7SUFFdEcsS0FBSyxDQUFDLE9BQU8sQ0FBQyxRQUFnQjtRQUM3QixNQUFNLFdBQVcsR0FBRyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLENBQUMsRUFBRSxLQUFLLEVBQUUsRUFBRSxRQUFRLEVBQUUsRUFBRSxDQUFDO1FBQzlFLE9BQU8sV0FBVztJQUNuQixDQUFDO0lBRUQsS0FBSyxDQUFDLE1BQU0sQ0FBQyxRQUFnQixFQUFFLGdCQUFrQztRQUNoRSxNQUFNLE9BQU8sR0FBRyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLGlCQUNoRCxRQUFRLElBQ0wsZ0JBQWdCLEVBQ2xCO1FBQ0YsT0FBTyxPQUFPO0lBQ2YsQ0FBQztJQUVELEtBQUssQ0FBQyxPQUFPLENBQUMsUUFBZ0IsRUFBRSxFQUFVO1FBQ3pDLE1BQU0sT0FBTyxHQUFHLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsQ0FBQztRQUN4RSxPQUFPLE9BQU87SUFDZixDQUFDO0lBRUQsS0FBSyxDQUFDLFdBQVcsQ0FBQyxRQUFnQixFQUFFLEtBQWE7UUFDaEQsTUFBTSxXQUFXLEdBQUcsTUFBTSxJQUFJLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDO1lBQ3JELEtBQUssRUFBRTtnQkFDTixRQUFRLEVBQUUsbUJBQUssRUFBQyxRQUFRLENBQUM7Z0JBQ3pCLEtBQUssRUFBRSxrQkFBSSxFQUFDLEdBQUcsS0FBSyxHQUFHLENBQUM7YUFDeEI7WUFDRCxJQUFJLEVBQUUsQ0FBQztZQUNQLElBQUksRUFBRSxFQUFFO1NBQ1IsQ0FBQztRQUNGLE9BQU8sV0FBVztJQUNuQixDQUFDO0lBQ0QsS0FBSyxDQUFDLGNBQWMsQ0FBQyxRQUFnQixFQUFFLFFBQWdCO1FBQ3RELE1BQU0sV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLElBQUksQ0FBQztZQUNyRCxLQUFLLEVBQUU7Z0JBQ04sUUFBUSxFQUFFLG1CQUFLLEVBQUMsUUFBUSxDQUFDO2dCQUN6QixRQUFRLEVBQUUsa0JBQUksRUFBQyxHQUFHLFFBQVEsR0FBRyxDQUFDO2FBQzlCO1lBQ0QsSUFBSSxFQUFFLENBQUM7WUFDUCxJQUFJLEVBQUUsRUFBRTtTQUNSLENBQUM7UUFDRixPQUFPLFdBQVc7SUFDbkIsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxFQUFVLEVBQUUsZ0JBQWtDO1FBQzVFLE1BQU0sV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsQ0FBQztRQUM1RSxJQUFJLENBQUMsV0FBVyxFQUFFO1lBQ2pCLE1BQU0sSUFBSSwwQkFBYSxDQUFDLDhCQUFhLENBQUMsU0FBUyxFQUFFLG1CQUFVLENBQUMsV0FBVyxDQUFDO1NBQ3hFO1FBQ0QsT0FBTyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxNQUFNLENBQUMsRUFBRSxRQUFRLEVBQUUsRUFBRSxFQUFFLEVBQUUsZ0JBQWdCLENBQUM7SUFDL0UsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxFQUFVO1FBQ3hDLE9BQU8sTUFBTSxJQUFJLENBQUMsaUJBQWlCLENBQUMsVUFBVSxDQUFDO1lBQzlDLFFBQVE7WUFDUixFQUFFO1NBQ0YsQ0FBQztJQUNILENBQUM7SUFFRCxLQUFLLENBQUMsT0FBTyxDQUFDLFFBQWdCLEVBQUUsVUFBa0I7UUFDakQsT0FBTyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxPQUFPLENBQUM7WUFDM0MsUUFBUTtZQUNSLEVBQUUsRUFBRSxVQUFVO1NBQ2QsQ0FBQztJQUNILENBQUM7Q0FDRDtBQWpFWSxjQUFjO0lBRDFCLHVCQUFVLEdBQUU7SUFFQyx5Q0FBZ0IsRUFBQyx3QkFBYSxDQUFDO3lEQUE0QixvQkFBVSxvQkFBVixvQkFBVTtHQUR0RSxjQUFjLENBaUUxQjtBQWpFWSx3Q0FBYzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDVDNCLDhGQUEyQztBQUMzQyxnRUFBc0c7QUFFdEcsSUFBWSxPQUdYO0FBSEQsV0FBWSxPQUFPO0lBQ2xCLHdCQUFhO0lBQ2IsNEJBQWlCO0FBQ2xCLENBQUMsRUFIVyxPQUFPLEdBQVAsZUFBTyxLQUFQLGVBQU8sUUFHbEI7QUFFRCxNQUFhLFVBQVU7Q0FhdEI7QUFaQTtJQUFDLG9DQUFzQixFQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxDQUFDOztzQ0FDN0I7QUFFVjtJQUFDLDhCQUFnQixFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxDQUFDO2tEQUM5QixJQUFJLG9CQUFKLElBQUk7NkNBQUE7QUFFZjtJQUFDLDhCQUFnQixFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxDQUFDO2tEQUM5QixJQUFJLG9CQUFKLElBQUk7NkNBQUE7QUFFZjtJQUFDLDhCQUFnQixFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQ3hDLCtCQUFPLEdBQUU7a0RBQ0MsSUFBSSxvQkFBSixJQUFJOzZDQUFBO0FBWmhCLGdDQWFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDckJELGdFQUErQztBQUMvQyw0RkFBMkM7QUFHNUIsSUFBTSxZQUFZLEdBQWxCLE1BQU0sWUFBYSxTQUFRLHdCQUFVO0NBZW5EO0FBZEE7SUFBQyxvQkFBTSxFQUFDLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsRUFBRSxFQUFFLFFBQVEsRUFBRSxLQUFLLEVBQUUsQ0FBQzs7MkNBQ3pDO0FBRWI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsS0FBSyxFQUFFLENBQUM7OzJDQUM3QjtBQUViO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxTQUFTLEVBQUUsT0FBTyxFQUFFLENBQUMsRUFBRSxDQUFDOzsyQ0FDM0I7QUFFYjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7OzBDQUNmO0FBRVo7SUFBQyxvQkFBTSxFQUFDLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDOzs2Q0FDWjtBQWRLLFlBQVk7SUFEaEMsb0JBQU0sRUFBQyxRQUFRLENBQUM7R0FDSSxZQUFZLENBZWhDO3FCQWZvQixZQUFZOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNKakMsOEZBQTJDO0FBQzNDLGdFQUFzRTtBQUN0RSw0RkFBb0Q7QUFDcEQsMEdBQTBDO0FBRTFDLElBQVksYUFJWDtBQUpELFdBQVksYUFBYTtJQUN4QixnQ0FBZTtJQUNmLGdDQUFlO0lBQ2YsOEJBQWE7QUFDZCxDQUFDLEVBSlcsYUFBYSxHQUFiLHFCQUFhLEtBQWIscUJBQWEsUUFJeEI7QUFNYyxJQUFNLGNBQWMsR0FBcEIsTUFBTSxjQUFlLFNBQVEsd0JBQVU7Q0E4QnJEO0FBN0JBO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsQ0FBQztJQUM3QiwrQkFBTyxHQUFFOztnREFDTTtBQUVoQjtJQUFDLHVCQUFTLEVBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyx1QkFBWSxDQUFDO0lBQy9CLHdCQUFVLEVBQUMsRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFLG9CQUFvQixFQUFFLElBQUksRUFBRSxDQUFDO2tEQUN0RCx1QkFBWSxvQkFBWix1QkFBWTs4Q0FBQTtBQUVwQjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxNQUFNLEVBQUUsRUFBRSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQzs7NkNBQzFCO0FBRWI7SUFBQyxvQkFBTSxHQUFFOztnREFDTztBQUVoQjtJQUFDLG9CQUFNLEdBQUU7SUFDUiwrQkFBTyxHQUFFOztnREFDTTtBQUVoQjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxhQUFhLEVBQUUsT0FBTyxFQUFFLGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQzs7NENBQ3hEO0FBRW5CO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDOztnREFDOUI7QUFFaEI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDO2tEQUNqQixJQUFJLG9CQUFKLElBQUk7Z0RBQUE7QUFFZDtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxxQkFBTyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztrREFDaEQscUJBQU8sb0JBQVAscUJBQU87OENBQUE7QUE3QkssY0FBYztJQUZsQyxvQkFBTSxFQUFDLFVBQVUsQ0FBQztJQUNsQixtQkFBSyxFQUFDLENBQUMsVUFBVSxFQUFFLFVBQVUsQ0FBQyxFQUFFLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxDQUFDO0dBQzdCLGNBQWMsQ0E4QmxDO3FCQTlCb0IsY0FBYzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ2ZuQyxnRUFBK0M7QUFDL0MsNEZBQTJDO0FBSTVCLElBQU0sY0FBYyxHQUFwQixNQUFNLGNBQWUsU0FBUSx3QkFBVTtDQWVyRDtBQWRBO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsQ0FBQzs7Z0RBQ2Q7QUFFaEI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7O2lEQUM5QjtBQUVqQjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsZUFBZSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQzs7b0RBQzlCO0FBRXBCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxrQkFBa0IsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7O3VEQUM5QjtBQUV2QjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQzs7NkNBQzdCO0FBZE8sY0FBYztJQUZsQyxvQkFBTSxFQUFDLFVBQVUsQ0FBQztJQUNsQixtQkFBSyxFQUFDLENBQUMsVUFBVSxFQUFFLElBQUksQ0FBQyxFQUFFLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxDQUFDO0dBQ3ZCLGNBQWMsQ0FlbEM7cUJBZm9CLGNBQWM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDTG5DLDhGQUEyQztBQUMzQyxnRUFBK0M7QUFDL0MsNEZBQW9EO0FBS3JDLElBQU0sYUFBYSxHQUFuQixNQUFNLGFBQWMsU0FBUSx3QkFBVTtDQW1CcEQ7QUFsQkE7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLFdBQVcsRUFBRSxDQUFDO0lBQzdCLCtCQUFPLEdBQUU7OytDQUNNO0FBRWhCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsQ0FBQzs7K0NBQ2Q7QUFFaEI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsTUFBTSxFQUFFLEVBQUUsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7OzRDQUMxQjtBQUViO0lBQUMsb0JBQU0sRUFBQyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztrREFDakIsSUFBSSxvQkFBSixJQUFJOytDQUFBO0FBRWQ7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxJQUFJLEVBQUUscUJBQU8sRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7a0RBQ2hELHFCQUFPLG9CQUFQLHFCQUFPOzZDQUFBO0FBRWY7SUFBQyxvQkFBTSxFQUFDLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDOzs4Q0FDWjtBQWxCSyxhQUFhO0lBSGpDLG9CQUFNLEVBQUMsU0FBUyxDQUFDO0lBQ2pCLG1CQUFLLEVBQUMsQ0FBQyxVQUFVLEVBQUUsVUFBVSxDQUFDLENBQUM7SUFDL0IsbUJBQUssRUFBQyxDQUFDLFVBQVUsRUFBRSxPQUFPLENBQUMsQ0FBQztHQUNSLGFBQWEsQ0FtQmpDO3FCQW5Cb0IsYUFBYTs7Ozs7Ozs7Ozs7QUNQbEM7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7OztVQ0FBO1VBQ0E7O1VBRUE7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7O1VBRUE7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7Ozs7Ozs7Ozs7OztBQ3RCQSw2RUFBZ0U7QUFDaEUsNkVBQThDO0FBQzlDLHVFQUFxRDtBQUNyRCxpR0FBMEM7QUFDMUMsNkRBQTJCO0FBQzNCLHNFQUF1QztBQUN2Qyw2RkFBd0M7QUFDeEMsa0dBQStDO0FBQy9DLGtLQUErRTtBQUMvRSwyS0FBcUY7QUFDckYsb0xBQWdIO0FBQ2hILDZIQUEwRDtBQUMxRCx5SkFBMkU7QUFDM0UsZ0pBQXNFO0FBRXRFLEtBQUssVUFBVSxTQUFTO0lBQ3ZCLE1BQU0sR0FBRyxHQUFHLE1BQU0sa0JBQVcsQ0FBQyxNQUFNLENBQUMsc0JBQVMsQ0FBQztJQUUvQyxNQUFNLGFBQWEsR0FBRyxHQUFHLENBQUMsR0FBRyxDQUFDLHNCQUFhLENBQUM7SUFDNUMsTUFBTSxJQUFJLEdBQUcsYUFBYSxDQUFDLEdBQUcsQ0FBQyxhQUFhLENBQUM7SUFDN0MsTUFBTSxJQUFJLEdBQUcsYUFBYSxDQUFDLEdBQUcsQ0FBQyxhQUFhLENBQUMsSUFBSSxXQUFXO0lBRTVELEdBQUcsQ0FBQyxHQUFHLENBQUMsb0JBQU0sR0FBRSxDQUFDO0lBQ2pCLEdBQUcsQ0FBQyxHQUFHLENBQUMsZ0NBQVMsRUFBQztRQUNqQixRQUFRLEVBQUUsRUFBRSxHQUFHLElBQUk7UUFDbkIsR0FBRyxFQUFFLEdBQUc7S0FDUixDQUFDLENBQUM7SUFDSCxHQUFHLENBQUMsVUFBVSxFQUFFO0lBRWhCLEdBQUcsQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLEVBQUUsRUFBRSxDQUFDO0lBRXZCLEdBQUcsQ0FBQyxxQkFBcUIsQ0FDeEIsSUFBSSw2Q0FBb0IsRUFBRSxFQUMxQixJQUFJLHdDQUFrQixFQUFFLENBQ3hCO0lBQ0QsR0FBRyxDQUFDLGdCQUFnQixDQUNuQixJQUFJLGlEQUFzQixFQUFFLEVBQzVCLElBQUksMkNBQW1CLEVBQUUsRUFDekIsSUFBSSx1REFBeUIsRUFBRSxDQUMvQjtJQUVELEdBQUcsQ0FBQyxlQUFlLENBQUMsSUFBSSxpQ0FBYyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsZ0JBQVMsQ0FBQyxDQUFDLENBQUM7SUFFM0QsR0FBRyxDQUFDLGNBQWMsQ0FBQyxJQUFJLHVCQUFjLENBQUM7UUFDckMsZUFBZSxFQUFFLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxLQUFLLEVBQUUsSUFBSSxFQUFFO1FBQy9DLHFCQUFxQixFQUFFLElBQUk7UUFDM0IsZ0JBQWdCLEVBQUUsQ0FBQyxTQUE0QixFQUFFLEVBQUUsRUFBRSxDQUFDLElBQUksaURBQW1CLENBQUMsTUFBTSxDQUFDO0tBQ3JGLENBQUMsQ0FBQztJQUVILElBQUksYUFBYSxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsS0FBSyxZQUFZLEVBQUU7UUFDbkQsMEJBQVksRUFBQyxHQUFHLENBQUM7S0FDakI7SUFFRCxNQUFNLEdBQUcsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLEdBQUcsRUFBRTtRQUMzQixPQUFPLENBQUMsR0FBRyxDQUFDLDhCQUE4QixJQUFJLElBQUksSUFBSSxXQUFXLENBQUM7SUFDbkUsQ0FBQyxDQUFDO0FBQ0gsQ0FBQztBQUNELFNBQVMsRUFBRSIsInNvdXJjZXMiOlsid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9hcHAubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvY29tbW9uL3N3YWdnZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2Vudmlyb25tZW50cy50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2V4Y2VwdGlvbi1maWx0ZXJzL2h0dHAtZXhjZXB0aW9uLmZpbHRlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvdW5rbm93bi1leGNlcHRpb24uZmlsdGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy92YWxpZGF0aW9uLWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2d1YXJkcy91c2VyLXJvbGVzLmd1YXJkLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9pbnRlcmNlcHRvci9hY2Nlc3MtbG9nLmludGVyY2VwdG9yLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9pbnRlcmNlcHRvci90aW1lb3V0LmludGVyY2VwdG9yLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9taWRkbGV3YXJlcy9sb2dnZXIubWlkZGxld2FyZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbWlkZGxld2FyZXMvdmFsaWRhdGUtYWNjZXNzLXRva2VuLm1pZGRsZXdhcmUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvand0LWV4dGVuZC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvaGVhbHRoL2hlYWx0aC5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2hlYWx0aC9oZWFsdGgubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L3BhdGllbnQubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL3BhdGllbnQvcGF0aWVudC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vYmFzZS5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvbWVkaWNpbmUuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvcGF0aWVudC5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9heGlvc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9yc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL2VudW1zXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb24vZXhjZXB0aW9uc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL3NlcmlhbGl6ZXJcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbmZpZ1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29yZVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvand0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9zd2FnZ2VyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy90ZXJtaW51c1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvdHlwZW9ybVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImJjcnlwdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImNsYXNzLXRyYW5zZm9ybWVyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiY2xhc3MtdmFsaWRhdG9yXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiZXhwcmVzc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImV4cHJlc3MtcmF0ZS1saW1pdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImhlbG1ldFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInJlcXVlc3QtaXBcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJyeGpzXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwicnhqcy9vcGVyYXRvcnNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJ0eXBlb3JtXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE1pZGRsZXdhcmVDb25zdW1lciwgTW9kdWxlLCBOZXN0TW9kdWxlLCBSZXF1ZXN0TWV0aG9kIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUsIENvbmZpZ1R5cGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IE1hcmlhZGJDb25maWcgfSBmcm9tICcuL2Vudmlyb25tZW50cydcbmltcG9ydCB7IExvZ2dlck1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL2xvZ2dlci5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgVmFsaWRhdGVBY2Nlc3NUb2tlbk1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL3ZhbGlkYXRlLWFjY2Vzcy10b2tlbi5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlJ1xuaW1wb3J0IHsgQ2xpbmljTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlJ1xuaW1wb3J0IHsgRW1wbG95ZWVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlJ1xuaW1wb3J0IHsgSGVhbHRoTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2hlYWx0aC9oZWFsdGgubW9kdWxlJ1xuaW1wb3J0IHsgTWVkaWNpbmVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlJ1xuaW1wb3J0IHsgUGF0aWVudE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9wYXRpZW50L3BhdGllbnQubW9kdWxlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1xuXHRcdENvbmZpZ01vZHVsZS5mb3JSb290KHtcblx0XHRcdGVudkZpbGVQYXRoOiBbYC5lbnYuJHtwcm9jZXNzLmVudi5OT0RFX0VOViB8fCAnbG9jYWwnfWAsICcuZW52J10sXG5cdFx0XHRpc0dsb2JhbDogdHJ1ZSxcblx0XHR9KSxcblx0XHRUeXBlT3JtTW9kdWxlLmZvclJvb3RBc3luYyh7XG5cdFx0XHRpbXBvcnRzOiBbQ29uZmlnTW9kdWxlLmZvckZlYXR1cmUoTWFyaWFkYkNvbmZpZyldLFxuXHRcdFx0aW5qZWN0OiBbTWFyaWFkYkNvbmZpZy5LRVldLFxuXHRcdFx0dXNlRmFjdG9yeTogKG1hcmlhZGJDb25maWc6IENvbmZpZ1R5cGU8dHlwZW9mIE1hcmlhZGJDb25maWc+KSA9PiBtYXJpYWRiQ29uZmlnLFxuXHRcdFx0Ly8gaW5qZWN0OiBbQ29uZmlnU2VydmljZV0sXG5cdFx0XHQvLyB1c2VGYWN0b3J5OiAoY29uZmlnU2VydmljZTogQ29uZmlnU2VydmljZSkgPT4gY29uZmlnU2VydmljZS5nZXQoJ215c3FsJyksXG5cdFx0fSksXG5cdFx0SGVhbHRoTW9kdWxlLFxuXHRcdEF1dGhNb2R1bGUsXG5cdFx0RW1wbG95ZWVNb2R1bGUsXG5cdFx0UGF0aWVudE1vZHVsZSxcblx0XHRDbGluaWNNb2R1bGUsXG5cdFx0TWVkaWNpbmVNb2R1bGUsXG5cdF0sXG59KVxuZXhwb3J0IGNsYXNzIEFwcE1vZHVsZSBpbXBsZW1lbnRzIE5lc3RNb2R1bGUge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2UpIHsgfVxuXHRjb25maWd1cmUoY29uc3VtZXI6IE1pZGRsZXdhcmVDb25zdW1lcikge1xuXHRcdGNvbnN1bWVyLmFwcGx5KExvZ2dlck1pZGRsZXdhcmUpLmZvclJvdXRlcygnKicpXG5cblx0XHRjb25zdW1lci5hcHBseShWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSlcblx0XHRcdC5leGNsdWRlKFxuXHRcdFx0XHQnYXV0aC8oLiopJyxcblx0XHRcdFx0Jy8nLFxuXHRcdFx0XHR7IHBhdGg6ICdoZWFsdGgnLCBtZXRob2Q6IFJlcXVlc3RNZXRob2QuR0VUIH1cblx0XHRcdClcblx0XHRcdC5mb3JSb3V0ZXMoJyonKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBWYWxpZGF0b3JDb25zdHJhaW50LCBWYWxpZGF0b3JDb25zdHJhaW50SW50ZXJmYWNlLCBWYWxpZGF0aW9uQXJndW1lbnRzIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5AVmFsaWRhdG9yQ29uc3RyYWludCh7IG5hbWU6ICdpc1Bob25lJywgYXN5bmM6IGZhbHNlIH0pXG5leHBvcnQgY2xhc3MgSXNQaG9uZSBpbXBsZW1lbnRzIFZhbGlkYXRvckNvbnN0cmFpbnRJbnRlcmZhY2Uge1xuXHR2YWxpZGF0ZSh0ZXh0OiBzdHJpbmcsIGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRyZXR1cm4gLygoMDl8MDN8MDd8MDh8MDUpKyhbMC05XXs4fSlcXGIpL2cudGVzdCh0ZXh0KVxuXHR9XG5cblx0ZGVmYXVsdE1lc3NhZ2UoYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAnJHByb3BlcnR5IG11c3QgYmUgcmVhbCBudW1iZXJwaG9uZSAhJ1xuXHR9XG59XG5cbkBWYWxpZGF0b3JDb25zdHJhaW50KHsgbmFtZTogJ2lzR21haWwnLCBhc3luYzogZmFsc2UgfSlcbmV4cG9ydCBjbGFzcyBJc0dtYWlsIGltcGxlbWVudHMgVmFsaWRhdG9yQ29uc3RyYWludEludGVyZmFjZSB7XG5cdHZhbGlkYXRlKHRleHQ6IHN0cmluZywgYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAvXihbYS16QS1aMC05XXxcXC58LXxfKSsoQGdtYWlsLmNvbSkkLy50ZXN0KHRleHQpXG5cdH1cblxuXHRkZWZhdWx0TWVzc2FnZShhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0cmV0dXJuICckcHJvcGVydHkgbXVzdCBiZSBhIGdtYWlsIGFkZHJlc3MgISdcblx0fVxufVxuIiwiaW1wb3J0IHsgSU5lc3RBcHBsaWNhdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgU3dhZ2dlck1vZHVsZSwgRG9jdW1lbnRCdWlsZGVyIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuXG5leHBvcnQgY29uc3Qgc2V0dXBTd2FnZ2VyID0gKGFwcDogSU5lc3RBcHBsaWNhdGlvbikgPT4ge1xuXHRjb25zdCBjb25maWcgPSBuZXcgRG9jdW1lbnRCdWlsZGVyKClcblx0XHQuc2V0VGl0bGUoJ1NpbXBsZSBBUEknKVxuXHRcdC5zZXREZXNjcmlwdGlvbignTWVkaWhvbWUgQVBJIHVzZSBTd2FnZ2VyJylcblx0XHQuc2V0VmVyc2lvbignMS4wJylcblx0XHQuYWRkQmVhcmVyQXV0aChcblx0XHRcdHsgdHlwZTogJ2h0dHAnLCBkZXNjcmlwdGlvbjogJ0FjY2VzcyB0b2tlbicgfSxcblx0XHRcdCdhY2Nlc3MtdG9rZW4nXG5cdFx0KVxuXHRcdC5idWlsZCgpXG5cdGNvbnN0IGRvY3VtZW50ID0gU3dhZ2dlck1vZHVsZS5jcmVhdGVEb2N1bWVudChhcHAsIGNvbmZpZylcblx0U3dhZ2dlck1vZHVsZS5zZXR1cCgnZG9jdW1lbnQnLCBhcHAsIGRvY3VtZW50KVxufVxuIiwiaW1wb3J0IHsgcmVnaXN0ZXJBcyB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZU9wdGlvbnMgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5cbmV4cG9ydCBjb25zdCBKd3RDb25maWcgPSByZWdpc3RlckFzKCdqd3QnLCAoKSA9PiAoe1xuXHRhY2Nlc3NLZXk6IHByb2Nlc3MuZW52LkpXVF9BQ0NFU1NfS0VZLFxuXHRyZWZyZXNoS2V5OiBwcm9jZXNzLmVudi5KV1RfUkVGUkVTSF9LRVksXG5cdGFjY2Vzc1RpbWU6IE51bWJlcihwcm9jZXNzLmVudi5KV1RfQUNDRVNTX1RJTUUpLFxuXHRyZWZyZXNoVGltZTogTnVtYmVyKHByb2Nlc3MuZW52LkpXVF9SRUZSRVNIX1RJTUUpLFxufSkpXG5cbmV4cG9ydCBjb25zdCBNYXJpYWRiQ29uZmlnID0gcmVnaXN0ZXJBcygnbWFyaWFkYicsICgpOiBUeXBlT3JtTW9kdWxlT3B0aW9ucyA9PiAoe1xuXHR0eXBlOiAnbWFyaWFkYicsXG5cdGhvc3Q6IHByb2Nlc3MuZW52Lk1BUklBREJfSE9TVCxcblx0cG9ydDogcGFyc2VJbnQocHJvY2Vzcy5lbnYuTUFSSUFEQl9QT1JULCAxMCksXG5cdGRhdGFiYXNlOiBwcm9jZXNzLmVudi5NQVJJQURCX0RBVEFCQVNFLFxuXHR1c2VybmFtZTogcHJvY2Vzcy5lbnYuTUFSSUFEQl9VU0VSTkFNRSxcblx0cGFzc3dvcmQ6IHByb2Nlc3MuZW52Lk1BUklBREJfUEFTU1dPUkQsXG5cdGF1dG9Mb2FkRW50aXRpZXM6IHRydWUsXG5cdGxvZ2dpbmc6IHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicsXG5cdHN5bmNocm9uaXplOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ2xvY2FsJyxcbn0pKVxuIiwiZXhwb3J0IGVudW0gRUVycm9yIHtcblx0VW5rbm93biA9ICdBMDAuVU5LTk9XTidcbn1cblxuZXhwb3J0IGVudW0gRVZhbGlkYXRlRXJyb3Ige1xuXHRGYWlsZWQgPSAnVjAwLlZBTElEQVRFX0ZBSUxFRCdcbn1cblxuZXhwb3J0IGVudW0gRVJlZ2lzdGVyRXJyb3Ige1xuXHRFeGlzdEVtYWlsQW5kUGhvbmUgPSAnUjAxLkVYSVNUX0VNQUlMX0FORF9QSE9ORScsXG5cdEV4aXN0RW1haWwgPSAnUjAyLkVYSVNUX0VNQUlMJyxcblx0RXhpc3RQaG9uZSA9ICdSMDMuRVhJU1RfUEhPTkUnLFxuXHRFeGlzdFVzZXJuYW1lID0gJ1IwNC5FWElTVF9VU0VSTkFNRSdcbn1cblxuZXhwb3J0IGVudW0gRUxvZ2luRXJyb3Ige1xuXHRFbXBsb3llZURvZXNOb3RFeGlzdCA9ICdMMDEuRU1QTE9ZRUVfRE9FU19OT1RfRVhJU1QnLFxuXHRXcm9uZ1Bhc3N3b3JkID0gJ0wwMi5XUk9OR19QQVNTV09SRCdcbn1cblxuZXhwb3J0IGVudW0gRVRva2VuRXJyb3Ige1xuXHRFeHBpcmVkID0gJ1QwMS5FWFBJUkVEJyxcblx0SW52YWxpZCA9ICdUMDIuSU5WQUxJRCdcbn1cblxuZXhwb3J0IGVudW0gRUVtcGxveWVlRXJyb3Ige1xuXHRVc2VybmFtZUV4aXN0cyA9ICdVMDEuVVNFUk5BTUVfRVhJU1RTJyxcblx0Tm90RXhpc3RzID0gJ1UwMi5FTVBMT1lFRV9ET0VTX05PVF9FWElTVCdcbn1cblxuZXhwb3J0IGVudW0gRVBhdGllbnRFcnJvciB7XG5cdE5vdEV4aXN0cyA9ICdQMDEuUEFUSUVOVF9ET0VTX05PVF9FWElTVCdcbn1cbiIsImltcG9ydCB7IEV4Y2VwdGlvbkZpbHRlciwgQ2F0Y2gsIEFyZ3VtZW50c0hvc3QsIEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcblxuQENhdGNoKEh0dHBFeGNlcHRpb24pXG5leHBvcnQgY2xhc3MgSHR0cEV4Y2VwdGlvbkZpbHRlciBpbXBsZW1lbnRzIEV4Y2VwdGlvbkZpbHRlciB7XG5cdGNhdGNoKGV4Y2VwdGlvbjogSHR0cEV4Y2VwdGlvbiwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IGV4Y2VwdGlvbi5nZXRTdGF0dXMoKVxuXG5cdFx0cmVzcG9uc2Uuc3RhdHVzKGh0dHBTdGF0dXMpLmpzb24oe1xuXHRcdFx0aHR0cFN0YXR1cyxcblx0XHRcdG1lc3NhZ2U6IGV4Y2VwdGlvbi5nZXRSZXNwb25zZSgpLFxuXHRcdFx0cGF0aDogcmVxdWVzdC51cmwsXG5cdFx0XHR0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcmd1bWVudHNIb3N0LCBDYXRjaCwgRXhjZXB0aW9uRmlsdGVyLCBIdHRwU3RhdHVzLCBMb2dnZXIgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcblxuQENhdGNoKEVycm9yKVxuZXhwb3J0IGNsYXNzIFVua25vd25FeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ1NFUlZFUl9FUlJPUicpKSB7IH1cblxuXHRjYXRjaChleGNlcHRpb246IEVycm9yLCBob3N0OiBBcmd1bWVudHNIb3N0KSB7XG5cdFx0Y29uc3QgY3R4ID0gaG9zdC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlc3BvbnNlID0gY3R4LmdldFJlc3BvbnNlPFJlc3BvbnNlPigpXG5cdFx0Y29uc3QgcmVxdWVzdCA9IGN0eC5nZXRSZXF1ZXN0PFJlcXVlc3Q+KClcblx0XHRjb25zdCBodHRwU3RhdHVzID0gSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1JcblxuXHRcdHRoaXMubG9nZ2VyLmVycm9yKGV4Y2VwdGlvbi5zdGFjaylcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlOiBleGNlcHRpb24ubWVzc2FnZSxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXJndW1lbnRzSG9zdCwgQ2F0Y2gsIEV4Y2VwdGlvbkZpbHRlciwgSHR0cFN0YXR1cywgVmFsaWRhdGlvbkVycm9yIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBFVmFsaWRhdGVFcnJvciB9IGZyb20gJy4vZXhjZXB0aW9uLmVudW0nXG5cbmV4cG9ydCBjbGFzcyBWYWxpZGF0aW9uRXhjZXB0aW9uIGV4dGVuZHMgRXJyb3Ige1xuXHRwcml2YXRlIHJlYWRvbmx5IGVycm9yczogVmFsaWRhdGlvbkVycm9yW11cblx0Y29uc3RydWN0b3IodmFsaWRhdGlvbkVycm9yczogVmFsaWRhdGlvbkVycm9yW10gPSBbXSkge1xuXHRcdHN1cGVyKEVWYWxpZGF0ZUVycm9yLkZhaWxlZClcblx0XHR0aGlzLmVycm9ycyA9IHZhbGlkYXRpb25FcnJvcnNcblx0fVxuXHRnZXRNZXNzYWdlKCkge1xuXHRcdHJldHVybiB0aGlzLm1lc3NhZ2Vcblx0fVxuXHRnZXRFcnJvcnMoKSB7XG5cdFx0cmV0dXJuIHRoaXMuZXJyb3JzXG5cdH1cbn1cblxuQENhdGNoKFZhbGlkYXRpb25FeGNlcHRpb24pXG5leHBvcnQgY2xhc3MgVmFsaWRhdGlvbkV4Y2VwdGlvbkZpbHRlciBpbXBsZW1lbnRzIEV4Y2VwdGlvbkZpbHRlciB7XG5cdGNhdGNoKGV4Y2VwdGlvbjogVmFsaWRhdGlvbkV4Y2VwdGlvbiwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IEh0dHBTdGF0dXMuVU5QUk9DRVNTQUJMRV9FTlRJVFlcblx0XHRjb25zdCBtZXNzYWdlID0gZXhjZXB0aW9uLmdldE1lc3NhZ2UoKVxuXHRcdGNvbnN0IGVycm9ycyA9IGV4Y2VwdGlvbi5nZXRFcnJvcnMoKVxuXG5cdFx0cmVzcG9uc2Uuc3RhdHVzKGh0dHBTdGF0dXMpLmpzb24oe1xuXHRcdFx0aHR0cFN0YXR1cyxcblx0XHRcdG1lc3NhZ2UsXG5cdFx0XHRlcnJvcnMsXG5cdFx0XHRwYXRoOiByZXF1ZXN0LnVybCxcblx0XHRcdHRpbWVzdGFtcDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IENhbkFjdGl2YXRlLCBFeGVjdXRpb25Db250ZXh0LCBJbmplY3RhYmxlLCBTZXRNZXRhZGF0YSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVmbGVjdG9yIH0gZnJvbSAnQG5lc3Rqcy9jb3JlJ1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBURW1wbG95ZWVSb2xlIH0gZnJvbSAndHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuXG5leHBvcnQgY29uc3QgVXNlclJvbGVzID0gKC4uLnVzZXJSb2xlczogVEVtcGxveWVlUm9sZVtdKSA9PiBTZXRNZXRhZGF0YSgndXNlcl9yb2xlcycsIHVzZXJSb2xlcylcbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBVc2VyUm9sZXNHdWFyZCBpbXBsZW1lbnRzIENhbkFjdGl2YXRlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWZsZWN0b3I6IFJlZmxlY3RvcikgeyB9XG5cblx0Y2FuQWN0aXZhdGUoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCk6IGJvb2xlYW4gfCBQcm9taXNlPGJvb2xlYW4+IHwgT2JzZXJ2YWJsZTxib29sZWFuPiB7XG5cdFx0Y29uc3Qgcm9sZXMgPSB0aGlzLnJlZmxlY3Rvci5nZXQ8VEVtcGxveWVlUm9sZVtdPigndXNlcl9yb2xlcycsIGNvbnRleHQuZ2V0SGFuZGxlcigpKVxuXHRcdGlmICghcm9sZXMpIHJldHVybiB0cnVlXG5cblx0XHRjb25zdCByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4gPSBjb250ZXh0LnN3aXRjaFRvSHR0cCgpLmdldFJlcXVlc3QoKVxuXHRcdGNvbnN0IHsgcm9sZSB9ID0gcmVxdWVzdC50b2tlblBheWxvYWRcblx0XHRyZXR1cm4gcm9sZXMuaW5jbHVkZXMocm9sZSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQ2FsbEhhbmRsZXIsIEV4ZWN1dGlvbkNvbnRleHQsIEluamVjdGFibGUsIE5lc3RJbnRlcmNlcHRvciwgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcydcbmltcG9ydCB7IHRhcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQWNjZXNzTG9nSW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ0FDQ0VTU19MT0cnKSkgeyB9XG5cblx0aW50ZXJjZXB0KGNvbnRleHQ6IEV4ZWN1dGlvbkNvbnRleHQsIG5leHQ6IENhbGxIYW5kbGVyKTogT2JzZXJ2YWJsZTxhbnk+IHtcblx0XHRjb25zdCBzdGFydFRpbWUgPSBuZXcgRGF0ZSgpXG5cdFx0Y29uc3QgY3R4ID0gY29udGV4dC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVxdWVzdCgpXG5cblx0XHRjb25zdCB7IHVybCwgbWV0aG9kIH0gPSByZXF1ZXN0XG5cdFx0Y29uc3QgeyBzdGF0dXNDb2RlIH0gPSByZXNwb25zZVxuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxdWVzdClcblxuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUodGFwKCgpID0+IHtcblx0XHRcdGNvbnN0IG1zZyA9IGAke3N0YXJ0VGltZS50b0lTT1N0cmluZygpfSB8ICR7aXB9IHwgJHttZXRob2R9IHwgJHtzdGF0dXNDb2RlfSB8ICR7dXJsfSB8ICR7RGF0ZS5ub3coKSAtIHN0YXJ0VGltZS5nZXRUaW1lKCl9bXNgXG5cdFx0XHRyZXR1cm4gdGhpcy5sb2dnZXIubG9nKG1zZylcblx0XHR9KSlcblx0fVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmVzdEludGVyY2VwdG9yLCBFeGVjdXRpb25Db250ZXh0LCBDYWxsSGFuZGxlciwgUmVxdWVzdFRpbWVvdXRFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IE9ic2VydmFibGUsIHRocm93RXJyb3IsIFRpbWVvdXRFcnJvciB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBjYXRjaEVycm9yLCB0aW1lb3V0IH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBUaW1lb3V0SW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRpbnRlcmNlcHQoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCwgbmV4dDogQ2FsbEhhbmRsZXIpOiBPYnNlcnZhYmxlPGFueT4ge1xuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUoXG5cdFx0XHR0aW1lb3V0KDEwMDAwKSxcblx0XHRcdGNhdGNoRXJyb3IoZXJyID0+IHtcblx0XHRcdFx0aWYgKGVyciBpbnN0YW5jZW9mIFRpbWVvdXRFcnJvcikge1xuXHRcdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IG5ldyBSZXF1ZXN0VGltZW91dEV4Y2VwdGlvbigpKVxuXHRcdFx0XHR9XG5cdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IGVycilcblx0XHRcdH0pXG5cdFx0KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZXN0TWlkZGxld2FyZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gJ2V4cHJlc3MnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBMb2dnZXJNaWRkbGV3YXJlIGltcGxlbWVudHMgTmVzdE1pZGRsZXdhcmUge1xuXHR1c2UocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pIHtcblx0XHRjb25zb2xlLmxvZygnUmVxdWVzdC4uLicpXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUsIE5lc3RNaWRkbGV3YXJlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBOZXh0RnVuY3Rpb24sIFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcbmltcG9ydCB7IElKd3RQYXlsb2FkLCBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4uL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSBpbXBsZW1lbnRzIE5lc3RNaWRkbGV3YXJlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlKSB7IH1cblxuXHRhc3luYyB1c2UocmVxOiBSZXF1ZXN0VG9rZW4sIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikge1xuXHRcdGNvbnN0IGF1dGhvcml6YXRpb24gPSByZXEuaGVhZGVyKCdBdXRob3JpemF0aW9uJykgfHwgJydcblx0XHRjb25zdCBbLCBhY2Nlc3NUb2tlbl0gPSBhdXRob3JpemF0aW9uLnNwbGl0KCcgJylcblx0XHRjb25zdCBkZWNvZGU6IElKd3RQYXlsb2FkID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuKVxuXHRcdHJlcS50b2tlblBheWxvYWQgPSBkZWNvZGVcblx0XHRuZXh0KClcblx0fVxufVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgUGFyYW0sIFBvc3QsIFJlcSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IFJlcXVlc3QgfSBmcm9tICdleHByZXNzJ1xuaW1wb3J0IHsgZ2V0Q2xpZW50SXAgfSBmcm9tICdyZXF1ZXN0LWlwJ1xuaW1wb3J0IHsgTG9naW5EdG8sIFJlZnJlc2hUb2tlbkR0bywgUmVnaXN0ZXJEdG8gfSBmcm9tICcuL2F1dGguZHRvJ1xuaW1wb3J0IHsgQXV0aFNlcnZpY2UgfSBmcm9tICcuL2F1dGguc2VydmljZSdcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ0F1dGgnKVxuQENvbnRyb2xsZXIoJ2F1dGgnKVxuZXhwb3J0IGNsYXNzIEF1dGhDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSByZWFkb25seSBhdXRoU2VydmljZTogQXV0aFNlcnZpY2UsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlXG5cdCkgeyB9XG5cblx0QFBvc3QoJ3JlZ2lzdGVyJylcblx0YXN5bmMgcmVnaXN0ZXIoQEJvZHkoKSByZWdpc3RlckR0bzogUmVnaXN0ZXJEdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0KSB7XG5cdFx0Y29uc3QgaXAgPSBnZXRDbGllbnRJcChyZXF1ZXN0KVxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5yZWdpc3RlcihyZWdpc3RlckR0bylcblx0XHRjb25zdCB7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfSA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVUb2tlbkZyb21Vc2VyKGVtcGxveWVlKVxuXHRcdHJldHVybiB7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfVxuXHR9XG5cblx0QFBvc3QoJ2xvZ2luJylcblx0YXN5bmMgbG9naW4oQEJvZHkoKSBsb2dpbkR0bzogTG9naW5EdG8pIHtcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UubG9naW4obG9naW5EdG8pXG5cdFx0Y29uc3QgeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0gPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UuY3JlYXRlVG9rZW5Gcm9tVXNlcihlbXBsb3llZSlcblx0XHRyZXR1cm4geyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH1cblx0fVxuXG5cdEBQb3N0KCdsb2dvdXQnKVxuXHRsb2dvdXQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBQb3N0KCdjaGFuZ2UtcGFzc3dvcmQnKVxuXHRjaGFuZ2VQYXNzd29yZChAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQEJvZHkoKSB1cGRhdGVBdXRoRHRvOiBMb2dpbkR0bykge1xuXHRcdC8vIHJldHVybiB0aGlzLmF1dGhTZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZUF1dGhEdG8pXG5cdH1cblxuXHRAUG9zdCgnZm9yZ290LXBhc3N3b3JkJylcblx0Zm9yZ290UGFzc3dvcmQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS5yZW1vdmUoK2lkKVxuXHR9XG5cblx0QFBvc3QoJ3JlZnJlc2gtdG9rZW4nKVxuXHRhc3luYyBncmFudEFjY2Vzc1Rva2VuKEBCb2R5KCkgcmVmcmVzaFRva2VuRHRvOiBSZWZyZXNoVG9rZW5EdG8pIHtcblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UuZ3JhbnRBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW5EdG8ucmVmcmVzaFRva2VuKVxuXHRcdHJldHVybiB7IGFjY2Vzc1Rva2VuIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHkgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0RlZmluZWQsIExlbmd0aCwgTWluTGVuZ3RoLCBWYWxpZGF0ZSB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcbmltcG9ydCB7IElzR21haWwsIElzUGhvbmUgfSBmcm9tICcuLi8uLi9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbSdcblxuZXhwb3J0IGNsYXNzIFJlZ2lzdGVyRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2V4YW1wbGUtMkBnbWFpbC5jb20nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRAVmFsaWRhdGUoSXNHbWFpbClcblx0ZW1haWw6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICcwMzc2ODk5ODY2JyB9KVxuXHRASXNEZWZpbmVkKClcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnYWRtaW4nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIExvZ2luRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJzA5ODYwMjExOTAnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATGVuZ3RoKDEwLCAxMClcblx0Y1Bob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnYWRtaW4nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFJlZnJlc2hUb2tlbkR0byB7XG5cdEBBcGlQcm9wZXJ0eSgpXG5cdEBJc0RlZmluZWQoKVxuXHRyZWZyZXNoVG9rZW46IHN0cmluZ1xufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEp3dE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvand0J1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgSnd0Q29uZmlnIH0gZnJvbSAnLi4vLi4vZW52aXJvbm1lbnRzJ1xuaW1wb3J0IHsgQXV0aENvbnRyb2xsZXIgfSBmcm9tICcuL2F1dGguY29udHJvbGxlcidcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHksIEVtcGxveWVlRW50aXR5XSksXG5cdFx0Q29uZmlnTW9kdWxlLmZvckZlYXR1cmUoSnd0Q29uZmlnKSxcblx0XHRKd3RNb2R1bGUsXG5cdF0sXG5cdGNvbnRyb2xsZXJzOiBbQXV0aENvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtBdXRoU2VydmljZSwgSnd0RXh0ZW5kU2VydmljZV0sXG5cdGV4cG9ydHM6IFtKd3RFeHRlbmRTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb24sIEh0dHBTdGF0dXMsIEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVFbXBsb3llZVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVMb2dpbkVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgTG9naW5EdG8sIFJlZ2lzdGVyRHRvIH0gZnJvbSAnLi9hdXRoLmR0bydcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlLFxuXHRcdHByaXZhdGUgand0RXh0ZW5kU2VydmljZTogSnd0RXh0ZW5kU2VydmljZVxuXHQpIHsgfVxuXG5cdGFzeW5jIHJlZ2lzdGVyKHJlZ2lzdGVyRHRvOiBSZWdpc3RlckR0byk6IFByb21pc2U8RW1wbG95ZWVFbnRpdHk+IHtcblx0XHRjb25zdCB7IGVtYWlsLCBwaG9uZSwgdXNlcm5hbWUsIHBhc3N3b3JkIH0gPSByZWdpc3RlckR0b1xuXHRcdGNvbnN0IGhhc2hQYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5oYXNoKHBhc3N3b3JkLCA1KVxuXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UudHJhbnNhY3Rpb24oYXN5bmMgKG1hbmFnZXIpID0+IHtcblx0XHRcdGNvbnN0IGZpbmRDbGluaWMgPSBhd2FpdCBtYW5hZ2VyLmZpbmRPbmUoQ2xpbmljRW50aXR5LCB7IHdoZXJlOiBbeyBlbWFpbCB9LCB7IHBob25lIH1dIH0pXG5cdFx0XHRpZiAoZmluZENsaW5pYykge1xuXHRcdFx0XHRpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwgJiYgZmluZENsaW5pYy5waG9uZSA9PT0gcGhvbmUpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsQW5kUGhvbmUsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZSBpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2UgaWYgKGZpbmRDbGluaWMucGhvbmUgPT09IHBob25lKSB7XG5cdFx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RQaG9uZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdFx0Y29uc3Qgc25hcENsaW5pYyA9IG1hbmFnZXIuY3JlYXRlKENsaW5pY0VudGl0eSwge1xuXHRcdFx0XHRwaG9uZSxcblx0XHRcdFx0ZW1haWwsXG5cdFx0XHRcdGxldmVsOiAxLFxuXHRcdFx0fSlcblx0XHRcdGNvbnN0IG5ld0NsaW5pYyA9IGF3YWl0IG1hbmFnZXIuc2F2ZShzbmFwQ2xpbmljKVxuXG5cdFx0XHRjb25zdCBzbmFwRW1wbG95ZWUgPSBtYW5hZ2VyLmNyZWF0ZShFbXBsb3llZUVudGl0eSwge1xuXHRcdFx0XHRjbGluaWNJZDogbmV3Q2xpbmljLmlkLFxuXHRcdFx0XHR1c2VybmFtZSxcblx0XHRcdFx0cGFzc3dvcmQ6IGhhc2hQYXNzd29yZCxcblx0XHRcdFx0cm9sZTogRUVtcGxveWVlUm9sZS5Pd25lcixcblx0XHRcdH0pXG5cblx0XHRcdGNvbnN0IG5ld0VtcGxveWVlID0gYXdhaXQgbWFuYWdlci5zYXZlKHNuYXBFbXBsb3llZSlcblx0XHRcdG5ld0VtcGxveWVlLmNsaW5pYyA9IG5ld0NsaW5pY1xuXG5cdFx0XHRyZXR1cm4gbmV3RW1wbG95ZWVcblx0XHR9KVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBsb2dpbihsb2dpbkR0bzogTG9naW5EdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UuZ2V0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSlcblx0XHRcdC5jcmVhdGVRdWVyeUJ1aWxkZXIoJ2VtcGxveWVlJylcblx0XHRcdC5sZWZ0Sm9pbkFuZFNlbGVjdCgnZW1wbG95ZWUuY2xpbmljJywgJ2NsaW5pYycpXG5cdFx0XHQud2hlcmUoJ3VzZXJuYW1lID0gOnVzZXJuYW1lJywgeyB1c2VybmFtZTogbG9naW5EdG8udXNlcm5hbWUgfSlcblx0XHRcdC5hbmRXaGVyZSgnY2xpbmljLnBob25lID0gOmNQaG9uZScsIHsgY1Bob25lOiBsb2dpbkR0by5jUGhvbmUgfSlcblx0XHRcdC5nZXRPbmUoKVxuXG5cdFx0aWYgKCFlbXBsb3llZSkge1xuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuRW1wbG95ZWVEb2VzTm90RXhpc3QsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0fVxuXG5cdFx0Y29uc3QgY2hlY2tQYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5jb21wYXJlKGxvZ2luRHRvLnBhc3N3b3JkLCBlbXBsb3llZS5wYXNzd29yZClcblx0XHRpZiAoIWNoZWNrUGFzc3dvcmQpIHtcblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVMb2dpbkVycm9yLldyb25nUGFzc3dvcmQsIEh0dHBTdGF0dXMuQkFEX0dBVEVXQVkpXG5cdFx0fVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBncmFudEFjY2Vzc1Rva2VuKHJlZnJlc2hUb2tlbjogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcblx0XHRjb25zdCB7IHVpZCB9ID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeVJlZnJlc2hUb2tlbihyZWZyZXNoVG9rZW4pXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UuZ2V0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSlcblx0XHRcdC5jcmVhdGVRdWVyeUJ1aWxkZXIoJ2VtcGxveWVlJylcblx0XHRcdC5sZWZ0Sm9pbkFuZFNlbGVjdCgnZW1wbG95ZWUuY2xpbmljJywgJ2NsaW5pYycpXG5cdFx0XHQud2hlcmUoJ2VtcGxveWVlLmlkID0gOmlkJywgeyBpZDogdWlkIH0pXG5cdFx0XHQuZ2V0T25lKClcblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVBY2Nlc3NUb2tlbihlbXBsb3llZSlcblx0XHRyZXR1cm4gYWNjZXNzVG9rZW5cblx0fVxufVxuIiwiaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiwgSHR0cFN0YXR1cywgSW5qZWN0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdUeXBlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnXG5pbXBvcnQgeyBKd3RTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9qd3QnXG5pbXBvcnQgVXNlckVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IElKd3RQYXlsb2FkIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IEp3dENvbmZpZyB9IGZyb20gJy4uLy4uL2Vudmlyb25tZW50cydcbmltcG9ydCB7IEVFcnJvciwgRVRva2VuRXJyb3IgfSBmcm9tICcuLi8uLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcblxuZXhwb3J0IGNsYXNzIEp3dEV4dGVuZFNlcnZpY2Uge1xuXHRjb25zdHJ1Y3Rvcihcblx0XHRASW5qZWN0KEp3dENvbmZpZy5LRVkpIHByaXZhdGUgand0Q29uZmlnOiBDb25maWdUeXBlPHR5cGVvZiBKd3RDb25maWc+LFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgand0U2VydmljZTogSnd0U2VydmljZVxuXHQpIHsgfVxuXG5cdGNyZWF0ZUFjY2Vzc1Rva2VuKHVzZXI6IFVzZXJFbnRpdHkpOiBzdHJpbmcge1xuXHRcdGNvbnN0IHVzZXJQYXlsb2FkOiBJSnd0UGF5bG9hZCA9IHtcblx0XHRcdGNQaG9uZTogdXNlci5jbGluaWMucGhvbmUsXG5cdFx0XHRjaWQ6IHVzZXIuY2xpbmljLmlkLFxuXHRcdFx0dWlkOiB1c2VyLmlkLFxuXHRcdFx0dXNlcm5hbWU6IHVzZXIudXNlcm5hbWUsXG5cdFx0XHRyb2xlOiB1c2VyLnJvbGUsXG5cdFx0fVxuXHRcdHJldHVybiB0aGlzLmp3dFNlcnZpY2Uuc2lnbih1c2VyUGF5bG9hZCwge1xuXHRcdFx0c2VjcmV0OiB0aGlzLmp3dENvbmZpZy5hY2Nlc3NLZXksXG5cdFx0XHRleHBpcmVzSW46IHRoaXMuand0Q29uZmlnLmFjY2Vzc1RpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVJlZnJlc2hUb2tlbih1aWQ6IG51bWJlcik6IHN0cmluZyB7XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHsgdWlkIH0sIHtcblx0XHRcdHNlY3JldDogdGhpcy5qd3RDb25maWcucmVmcmVzaEtleSxcblx0XHRcdGV4cGlyZXNJbjogdGhpcy5qd3RDb25maWcucmVmcmVzaFRpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVRva2VuRnJvbVVzZXIodXNlcjogVXNlckVudGl0eSkge1xuXHRcdGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5jcmVhdGVBY2Nlc3NUb2tlbih1c2VyKVxuXHRcdGNvbnN0IHJlZnJlc2hUb2tlbiA9IHRoaXMuY3JlYXRlUmVmcmVzaFRva2VuKHVzZXIuaWQpXG5cdFx0cmV0dXJuIHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9XG5cdH1cblxuXHR2ZXJpZnlBY2Nlc3NUb2tlbihhY2Nlc3NUb2tlbjogc3RyaW5nKTogSUp3dFBheWxvYWQge1xuXHRcdHRyeSB7XG5cdFx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnZlcmlmeShhY2Nlc3NUb2tlbiwgeyBzZWNyZXQ6IHRoaXMuand0Q29uZmlnLmFjY2Vzc0tleSB9KVxuXHRcdH0gY2F0Y2ggKGVycm9yKSB7XG5cdFx0XHRpZiAoZXJyb3IubmFtZSA9PT0gJ1Rva2VuRXhwaXJlZEVycm9yJykge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5FeHBpcmVkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH0gZWxzZSBpZiAoZXJyb3IubmFtZSA9PT0gJ0pzb25XZWJUb2tlbkVycm9yJykge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5JbnZhbGlkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH1cblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVFcnJvci5Vbmtub3duLCBIdHRwU3RhdHVzLklOVEVSTkFMX1NFUlZFUl9FUlJPUilcblx0XHR9XG5cdH1cblxuXHR2ZXJpZnlSZWZyZXNoVG9rZW4ocmVmcmVzaFRva2VuOiBzdHJpbmcpOiB7IHVpZDogbnVtYmVyIH0ge1xuXHRcdHRyeSB7XG5cdFx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnZlcmlmeShyZWZyZXNoVG9rZW4sIHsgc2VjcmV0OiB0aGlzLmp3dENvbmZpZy5yZWZyZXNoS2V5IH0pXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vd24sIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQ29udHJvbGxlciwgR2V0LCBQb3N0LCBCb2R5LCBQYXRjaCwgUGFyYW0sIERlbGV0ZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5pbXBvcnQgeyBDcmVhdGVDbGluaWNEdG8sIFVwZGF0ZUNsaW5pY0R0byB9IGZyb20gJy4vY2xpbmljLmR0bydcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5cbkBBcGlUYWdzKCdDbGluaWMnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignY2xpbmljJylcbmV4cG9ydCBjbGFzcyBDbGluaWNDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBjbGluaWNTZXJ2aWNlOiBDbGluaWNTZXJ2aWNlKSB7IH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZUNsaW5pY0R0bzogQ3JlYXRlQ2xpbmljRHRvKSB7XG5cdFx0cmV0dXJuICcnXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLmZpbmRBbGwoKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNFbWFpbCwgTGVuZ3RoIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5leHBvcnQgY2xhc3MgQ3JlYXRlQ2xpbmljRHRvIHtcblx0QElzRW1haWwoKVxuXHRlbWFpbDogc3RyaW5nXG5cblx0QExlbmd0aCgxMCwgMTApXG5cdHBob25lOiBzdHJpbmdcblxuXHRATGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUNsaW5pY0R0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZUNsaW5pY0R0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCB7IENsaW5pY0NvbnRyb2xsZXIgfSBmcm9tICcuL2NsaW5pYy5jb250cm9sbGVyJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbQ2xpbmljQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0NsaW5pY1NlcnZpY2VdLFxuXHRleHBvcnRzOiBbQ2xpbmljU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIENsaW5pY01vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEluamVjdFJlcG9zaXRvcnkgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlLCBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ2xpbmljU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdEBJbmplY3RSZXBvc2l0b3J5KENsaW5pY0VudGl0eSkgcHJpdmF0ZSBjbGluaWNSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PENsaW5pY0VudGl0eT4sXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlXG5cdCkgeyB9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIGNsaW5pY2Bcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHR1cGRhdGUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFJlcSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVXNlSW50ZXJjZXB0b3JzIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9ycydcbmltcG9ydCB7IENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vc2VyaWFsaXplcidcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVBhcmFtLCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IENyZWF0ZUVtcGxveWVlRHRvLCBVcGRhdGVFbXBsb3llZUR0byB9IGZyb20gJy4vZW1wbG95ZWUuZHRvJ1xuaW1wb3J0IHsgRW1wbG95ZWVTZXJ2aWNlIH0gZnJvbSAnLi9lbXBsb3llZS5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnRW1wbG95ZWUnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AVXNlSW50ZXJjZXB0b3JzKENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yKVxuQENvbnRyb2xsZXIoJ2VtcGxveWVlJylcbmV4cG9ydCBjbGFzcyBFbXBsb3llZUNvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGVtcGxveWVlU2VydmljZTogRW1wbG95ZWVTZXJ2aWNlKSB7IH1cblxuXHRAR2V0KClcblx0ZmluZEFsbChAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5lbXBsb3llZVNlcnZpY2UuZmluZEFsbChjbGluaWNJZClcblx0fVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlRW1wbG95ZWVEdG86IENyZWF0ZUVtcGxveWVlRHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5lbXBsb3llZVNlcnZpY2UuY3JlYXRlKGNsaW5pY0lkLCBjcmVhdGVFbXBsb3llZUR0bylcblx0fVxuXG5cdEBHZXQoJzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLmZpbmRPbmUoY2xpbmljSWQsICtpZClcblx0fVxuXG5cdEBQYXRjaCgndXBkYXRlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgdXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuLCBAQm9keSgpIHVwZGF0ZUVtcGxveWVlRHRvOiBVcGRhdGVFbXBsb3llZUR0bykge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5lbXBsb3llZVNlcnZpY2UudXBkYXRlKGNsaW5pY0lkLCAraWQsIHVwZGF0ZUVtcGxveWVlRHRvKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cblxuXHRARGVsZXRlKCdyZW1vdmUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyByZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnJlbW92ZShjbGluaWNJZCwgK2lkKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cblxuXHRAUGF0Y2goJ3Jlc3RvcmUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyByZXN0b3JlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLmVtcGxveWVlU2VydmljZS5yZXN0b3JlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHksIFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNEZWZpbmVkLCBNaW5MZW5ndGggfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVFbXBsb3llZUR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICduaGF0ZHVvbmcyMDE5JyB9KVxuXHRASXNEZWZpbmVkKClcblx0dXNlcm5hbWU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdBYmNAMTIzNDU2JyB9KVxuXHRASXNEZWZpbmVkKClcblx0QE1pbkxlbmd0aCg2KVxuXHRwYXNzd29yZDogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ05nw7QgTmjhuq10IETGsMahbmcnIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUVtcGxveWVlRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlRW1wbG95ZWVEdG8pIHsgfVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2NsaW5pYy5lbnRpdHknXG5pbXBvcnQgRW1wbG95ZWVFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBFbXBsb3llZUNvbnRyb2xsZXIgfSBmcm9tICcuL2VtcGxveWVlLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBFbXBsb3llZVNlcnZpY2UgfSBmcm9tICcuL2VtcGxveWVlLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtFbXBsb3llZUVudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtFbXBsb3llZUNvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtFbXBsb3llZVNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBFbXBsb3llZU1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEh0dHBTdGF0dXMgfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9lbnVtcydcbmltcG9ydCB7IEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBwbGFpblRvQ2xhc3MgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVFbXBsb3llZVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVFbXBsb3llZUVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8sIFVwZGF0ZUVtcGxveWVlRHRvIH0gZnJvbSAnLi9lbXBsb3llZS5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBFbXBsb3llZVNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSkgcHJpdmF0ZSBlbXBsb3llZVJlcG9zaXRvcnk6IFJlcG9zaXRvcnk8RW1wbG95ZWVFbnRpdHk+KSB7IH1cblxuXHRhc3luYyBmaW5kQWxsKGNsaW5pY0lkOiBudW1iZXIpOiBQcm9taXNlPEVtcGxveWVlRW50aXR5W10+IHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZCh7IHdoZXJlOiB7IGNsaW5pY0lkIH0gfSlcblx0fVxuXG5cdGFzeW5jIGNyZWF0ZShjbGluaWNJZDogbnVtYmVyLCBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZmluZEVtcGxveWVlID0gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZE9uZUJ5KHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0dXNlcm5hbWU6IGNyZWF0ZUVtcGxveWVlRHRvLnVzZXJuYW1lLFxuXHRcdH0pXG5cdFx0aWYgKGZpbmRFbXBsb3llZSkge1xuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RVc2VybmFtZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHR9XG5cdFx0Y29uc3Qgc25hcEVtcGxveWVlID0gcGxhaW5Ub0NsYXNzKEVtcGxveWVlRW50aXR5LCBjcmVhdGVFbXBsb3llZUR0bylcblx0XHRzbmFwRW1wbG95ZWUucGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaChjcmVhdGVFbXBsb3llZUR0by5wYXNzd29yZCwgNSlcblx0XHRzbmFwRW1wbG95ZWUucm9sZSA9IEVFbXBsb3llZVJvbGUuVXNlclxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5zYXZlKGNyZWF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0YXN5bmMgZmluZE9uZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHR9XG5cblx0YXN5bmMgdXBkYXRlKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIsIHVwZGF0ZUVtcGxveWVlRHRvOiBVcGRhdGVFbXBsb3llZUR0bykge1xuXHRcdGNvbnN0IGZpbmRFbXBsb3llZSA9IGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHRcdGlmICghZmluZEVtcGxveWVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFRW1wbG95ZWVFcnJvci5Ob3RFeGlzdHMsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0fVxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS51cGRhdGUoeyBjbGluaWNJZCwgaWQgfSwgdXBkYXRlRW1wbG95ZWVEdG8pXG5cdH1cblxuXHRhc3luYyByZW1vdmUoY2xpbmljSWQ6IG51bWJlciwgZW1wbG95ZWVJZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LnNvZnREZWxldGUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG5cblx0YXN5bmMgcmVzdG9yZShjbGluaWNJZDogbnVtYmVyLCBlbXBsb3llZUlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkucmVzdG9yZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkOiBlbXBsb3llZUlkLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IENvbnRyb2xsZXIsIEdldCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7XG5cdERpc2tIZWFsdGhJbmRpY2F0b3IsIEhlYWx0aENoZWNrLCBIZWFsdGhDaGVja1NlcnZpY2UsIEh0dHBIZWFsdGhJbmRpY2F0b3IsXG5cdE1lbW9yeUhlYWx0aEluZGljYXRvciwgVHlwZU9ybUhlYWx0aEluZGljYXRvcixcbn0gZnJvbSAnQG5lc3Rqcy90ZXJtaW51cydcblxuQEFwaVRhZ3MoJ0hlYWx0aCcpXG5AQ29udHJvbGxlcignaGVhbHRoJylcbmV4cG9ydCBjbGFzcyBIZWFsdGhDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSByZWFkb25seSBoZWFsdGg6IEhlYWx0aENoZWNrU2VydmljZSxcblx0XHRwcml2YXRlIHJlYWRvbmx5IGh0dHA6IEh0dHBIZWFsdGhJbmRpY2F0b3IsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBkYjogVHlwZU9ybUhlYWx0aEluZGljYXRvcixcblx0XHRwcml2YXRlIHJlYWRvbmx5IGRpc2s6IERpc2tIZWFsdGhJbmRpY2F0b3IsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBtZW1vcnk6IE1lbW9yeUhlYWx0aEluZGljYXRvclxuXHQpIHsgfVxuXG5cdEBHZXQoKVxuXHRASGVhbHRoQ2hlY2soKVxuXHRjaGVjaygpIHtcblx0XHRyZXR1cm4gdGhpcy5oZWFsdGguY2hlY2soW1xuXHRcdFx0KCkgPT4gdGhpcy5odHRwLnBpbmdDaGVjaygnbmVzdGpzLWRvY3MnLCAnaHR0cHM6Ly9tZWRpaG9tZS52bi9kb2N1bWVudCcpLFxuXHRcdFx0KCkgPT4gdGhpcy5kYi5waW5nQ2hlY2soJ2RhdGFiYXNlJyksXG5cdFx0XHQoKSA9PiB0aGlzLmRpc2suY2hlY2tTdG9yYWdlKCdzdG9yYWdlJywgeyBwYXRoOiAnLycsIHRocmVzaG9sZFBlcmNlbnQ6IDAuNSB9KSxcblx0XHRcdCgpID0+IHRoaXMubWVtb3J5LmNoZWNrSGVhcCgnbWVtb3J5X2hlYXAnLCAxNTAgKiAxMDI0ICogMTAyNCksXG5cdFx0XHQoKSA9PiB0aGlzLm1lbW9yeS5jaGVja1JTUygnbWVtb3J5X3JzcycsIDE1MCAqIDEwMjQgKiAxMDI0KSxcblx0XHRdKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBIdHRwTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9heGlvcydcbmltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVGVybWludXNNb2R1bGUgfSBmcm9tICdAbmVzdGpzL3Rlcm1pbnVzJ1xuaW1wb3J0IHsgSGVhbHRoQ29udHJvbGxlciB9IGZyb20gJy4vaGVhbHRoLmNvbnRyb2xsZXInXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVGVybWludXNNb2R1bGUsIEh0dHBNb2R1bGVdLFxuXHRjb250cm9sbGVyczogW0hlYWx0aENvbnRyb2xsZXJdLFxufSlcbmV4cG9ydCBjbGFzcyBIZWFsdGhNb2R1bGUgeyB9XG4iLCJleHBvcnQgY2xhc3MgQ3JlYXRlTWVkaWNpbmVEdG8ge31cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2NyZWF0ZS1tZWRpY2luZS5kdG8nXG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVNZWRpY2luZUR0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZU1lZGljaW5lRHRvKSB7fVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgRGVsZXRlLCBHZXQsIFBhcmFtLCBQYXRjaCwgUG9zdCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IENyZWF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vY3JlYXRlLW1lZGljaW5lLmR0bydcbmltcG9ydCB7IFVwZGF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlLW1lZGljaW5lLmR0bydcbmltcG9ydCB7IE1lZGljaW5lU2VydmljZSB9IGZyb20gJy4vbWVkaWNpbmUuc2VydmljZSdcblxuQEFwaVRhZ3MoJ01lZGljaW5lJylcbkBBcGlCZWFyZXJBdXRoKCdhY2Nlc3MtdG9rZW4nKVxuQENvbnRyb2xsZXIoJ21lZGljaW5lJylcbmV4cG9ydCBjbGFzcyBNZWRpY2luZUNvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IG1lZGljaW5lU2VydmljZTogTWVkaWNpbmVTZXJ2aWNlKSB7IH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZU1lZGljaW5lRHRvOiBDcmVhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5jcmVhdGUoY3JlYXRlTWVkaWNpbmVEdG8pXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLmZpbmRPbmUoK2lkKVxuXHR9XG5cblx0QFBhdGNoKCc6aWQnKVxuXHR1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlTWVkaWNpbmVEdG86IFVwZGF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZU1lZGljaW5lRHRvKVxuXHR9XG5cblx0QERlbGV0ZSgnOmlkJylcblx0cmVtb3ZlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBNZWRpY2luZUVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL21lZGljaW5lLmVudGl0eSdcbmltcG9ydCB7IE1lZGljaW5lQ29udHJvbGxlciB9IGZyb20gJy4vbWVkaWNpbmUuY29udHJvbGxlcidcbmltcG9ydCB7IE1lZGljaW5lU2VydmljZSB9IGZyb20gJy4vbWVkaWNpbmUuc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW01lZGljaW5lRW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW01lZGljaW5lQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW01lZGljaW5lU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIE1lZGljaW5lTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTWVkaWNpbmVTZXJ2aWNlIHtcblx0Y3JlYXRlKGNyZWF0ZU1lZGljaW5lRHRvOiBDcmVhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiAnVGhpcyBhY3Rpb24gYWRkcyBhIG5ldyBtZWRpY2luZSdcblx0fVxuXG5cdGZpbmRBbGwoKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGFsbCBtZWRpY2luZWBcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxuXG5cdHVwZGF0ZShpZDogbnVtYmVyLCB1cGRhdGVNZWRpY2luZUR0bzogVXBkYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHVwZGF0ZXMgYSAjJHtpZH0gbWVkaWNpbmVgXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxufVxuIiwiaW1wb3J0IHsgQm9keSwgQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IsIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFF1ZXJ5LCBSZXEsIFVzZUludGVyY2VwdG9ycyB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpUGFyYW0sIEFwaVF1ZXJ5LCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IENyZWF0ZVBhdGllbnREdG8sIFVwZGF0ZVBhdGllbnREdG8gfSBmcm9tICcuL3BhdGllbnQuZHRvJ1xuaW1wb3J0IHsgUGF0aWVudFNlcnZpY2UgfSBmcm9tICcuL3BhdGllbnQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ1BhdGllbnQnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AVXNlSW50ZXJjZXB0b3JzKENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yKVxuQENvbnRyb2xsZXIoJ3BhdGllbnQnKVxuZXhwb3J0IGNsYXNzIFBhdGllbnRDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBwYXRpZW50U2VydmljZTogUGF0aWVudFNlcnZpY2UpIHsgfVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRBbGwoY2xpbmljSWQpXG5cdH1cblxuXHRAR2V0KCdzZWFyY2gnKVxuXHRAQXBpUXVlcnkoeyBuYW1lOiAnc2VhcmNoVGV4dCcsIGV4YW1wbGU6ICcwOTg2MTIzNDU2JyB9KVxuXHRzZWFyY2goQFF1ZXJ5KCdzZWFyY2hUZXh0Jykgc2VhcmNoVGV4dDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRpZiAoL15cXGQrJC8udGVzdChzZWFyY2hUZXh0KSkge1xuXHRcdFx0cmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuZmluZEJ5UGhvbmUoY2xpbmljSWQsIHNlYXJjaFRleHQpXG5cdFx0fVxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRCeUZ1bGxOYW1lKGNsaW5pY0lkLCBzZWFyY2hUZXh0KVxuXHR9XG5cblx0QFBvc3QoKVxuXHRjcmVhdGUoQEJvZHkoKSBjcmVhdGVQYXRpZW50RHRvOiBDcmVhdGVQYXRpZW50RHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS5jcmVhdGUoY2xpbmljSWQsIGNyZWF0ZVBhdGllbnREdG8pXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRPbmUoY2xpbmljSWQsICtpZClcblx0fVxuXG5cdEBQYXRjaCgndXBkYXRlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgdXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAQm9keSgpIHVwZGF0ZVBhdGllbnREdG86IFVwZGF0ZVBhdGllbnREdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMucGF0aWVudFNlcnZpY2UudXBkYXRlKGNsaW5pY0lkLCAraWQsIHVwZGF0ZVBhdGllbnREdG8pXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBEZWxldGUoJ3JlbW92ZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5wYXRpZW50U2VydmljZS5yZW1vdmUoY2xpbmljSWQsICtpZClcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG5cblx0QFBhdGNoKCdyZXN0b3JlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgcmVzdG9yZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5wYXRpZW50U2VydmljZS5yZXN0b3JlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHlPcHRpb25hbCwgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0RlZmluZWQsIFZhbGlkYXRlIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuaW1wb3J0IHsgRUdlbmRlciB9IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vYmFzZS5lbnRpdHknXG5pbXBvcnQgeyBJc1Bob25lIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NsYXNzLXZhbGlkYXRvci5jdXN0b20nXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVQYXRpZW50RHRvIHtcblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnUGjhuqFtIEhvw6BuZyBNYWknIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRmdWxsTmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnMDk4NjEyMzQ1NicgfSlcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6IEVHZW5kZXIuRmVtYWxlIH0pXG5cdGdlbmRlcjogRUdlbmRlclxuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogJ1Row6BuaCBwaOG7kSBIw6AgTuG7mWkgLS0gUXXhuq1uIExvbmcgQmnDqm4gLS0gUGjGsOG7nW5nIFRo4bqhY2ggQsOgbiAtLSBz4buRIDggLSB0w7JhIG5ow6AgxJDhuqNvIEPhuqd1IFbhu5NuZycgfSlcblx0YWRkcmVzczogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnMTk5OC0xMS0yOFQwMDowMDowMC4wMDBaJyB9KVxuXHRiaXJ0aGRheTogRGF0ZVxufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlUGF0aWVudER0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZVBhdGllbnREdG8pIHsgfVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eSdcbmltcG9ydCB7IFBhdGllbnRDb250cm9sbGVyIH0gZnJvbSAnLi9wYXRpZW50LmNvbnRyb2xsZXInXG5pbXBvcnQgeyBQYXRpZW50U2VydmljZSB9IGZyb20gJy4vcGF0aWVudC5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1R5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbUGF0aWVudEVudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtQYXRpZW50Q29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW1BhdGllbnRTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgUGF0aWVudE1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEh0dHBTdGF0dXMsIEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCB7IEVxdWFsLCBMaWtlLCBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBQYXRpZW50RW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvcGF0aWVudC5lbnRpdHknXG5pbXBvcnQgeyBFUGF0aWVudEVycm9yIH0gZnJvbSAnLi4vLi4vZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0nXG5pbXBvcnQgeyBDcmVhdGVQYXRpZW50RHRvLCBVcGRhdGVQYXRpZW50RHRvIH0gZnJvbSAnLi9wYXRpZW50LmR0bydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFBhdGllbnRTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoQEluamVjdFJlcG9zaXRvcnkoUGF0aWVudEVudGl0eSkgcHJpdmF0ZSBwYXRpZW50UmVwb3NpdG9yeTogUmVwb3NpdG9yeTxQYXRpZW50RW50aXR5PikgeyB9XG5cblx0YXN5bmMgZmluZEFsbChjbGluaWNJZDogbnVtYmVyKTogUHJvbWlzZTxQYXRpZW50RW50aXR5W10+IHtcblx0XHRjb25zdCBwYXRpZW50TGlzdCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuZmluZCh7IHdoZXJlOiB7IGNsaW5pY0lkIH0gfSlcblx0XHRyZXR1cm4gcGF0aWVudExpc3Rcblx0fVxuXG5cdGFzeW5jIGNyZWF0ZShjbGluaWNJZDogbnVtYmVyLCBjcmVhdGVQYXRpZW50RHRvOiBDcmVhdGVQYXRpZW50RHRvKTogUHJvbWlzZTxQYXRpZW50RW50aXR5PiB7XG5cdFx0Y29uc3QgcGF0aWVudCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuc2F2ZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdC4uLmNyZWF0ZVBhdGllbnREdG8sXG5cdFx0fSlcblx0XHRyZXR1cm4gcGF0aWVudFxuXHR9XG5cblx0YXN5bmMgZmluZE9uZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0Y29uc3QgcGF0aWVudCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuZmluZE9uZUJ5KHsgY2xpbmljSWQsIGlkIH0pXG5cdFx0cmV0dXJuIHBhdGllbnRcblx0fVxuXG5cdGFzeW5jIGZpbmRCeVBob25lKGNsaW5pY0lkOiBudW1iZXIsIHBob25lOiBzdHJpbmcpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHtcblx0XHRcdHdoZXJlOiB7XG5cdFx0XHRcdGNsaW5pY0lkOiBFcXVhbChjbGluaWNJZCksXG5cdFx0XHRcdHBob25lOiBMaWtlKGAke3Bob25lfSVgKSxcblx0XHRcdH0sXG5cdFx0XHRza2lwOiAwLFxuXHRcdFx0dGFrZTogMTAsXG5cdFx0fSlcblx0XHRyZXR1cm4gcGF0aWVudExpc3Rcblx0fVxuXHRhc3luYyBmaW5kQnlGdWxsTmFtZShjbGluaWNJZDogbnVtYmVyLCBmdWxsTmFtZTogc3RyaW5nKTogUHJvbWlzZTxQYXRpZW50RW50aXR5W10+IHtcblx0XHRjb25zdCBwYXRpZW50TGlzdCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuZmluZCh7XG5cdFx0XHR3aGVyZToge1xuXHRcdFx0XHRjbGluaWNJZDogRXF1YWwoY2xpbmljSWQpLFxuXHRcdFx0XHRmdWxsTmFtZTogTGlrZShgJHtmdWxsTmFtZX0lYCksXG5cdFx0XHR9LFxuXHRcdFx0c2tpcDogMCxcblx0XHRcdHRha2U6IDEwLFxuXHRcdH0pXG5cdFx0cmV0dXJuIHBhdGllbnRMaXN0XG5cdH1cblxuXHRhc3luYyB1cGRhdGUoY2xpbmljSWQ6IG51bWJlciwgaWQ6IG51bWJlciwgdXBkYXRlUGF0aWVudER0bzogVXBkYXRlUGF0aWVudER0bykge1xuXHRcdGNvbnN0IGZpbmRQYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kT25lQnkoeyBjbGluaWNJZCwgaWQgfSlcblx0XHRpZiAoIWZpbmRQYXRpZW50KSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUGF0aWVudEVycm9yLk5vdEV4aXN0cywgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHR9XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkudXBkYXRlKHsgY2xpbmljSWQsIGlkIH0sIHVwZGF0ZVBhdGllbnREdG8pXG5cdH1cblxuXHRhc3luYyByZW1vdmUoY2xpbmljSWQ6IG51bWJlciwgaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LnNvZnREZWxldGUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZCxcblx0XHR9KVxuXHR9XG5cblx0YXN5bmMgcmVzdG9yZShjbGluaWNJZDogbnVtYmVyLCBlbXBsb3llZUlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5yZXN0b3JlKHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0aWQ6IGVtcGxveWVlSWQsXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgRXhjbHVkZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgQ3JlYXRlRGF0ZUNvbHVtbiwgRGVsZXRlRGF0ZUNvbHVtbiwgUHJpbWFyeUdlbmVyYXRlZENvbHVtbiwgVXBkYXRlRGF0ZUNvbHVtbiB9IGZyb20gJ3R5cGVvcm0nXG5cbmV4cG9ydCBlbnVtIEVHZW5kZXIge1xuXHRNYWxlID0gJ01hbGUnLFxuXHRGZW1hbGUgPSAnRmVtYWxlJyxcbn1cblxuZXhwb3J0IGNsYXNzIEJhc2VFbnRpdHkge1xuXHRAUHJpbWFyeUdlbmVyYXRlZENvbHVtbih7IG5hbWU6ICdpZCcgfSlcblx0aWQ6IG51bWJlclxuXG5cdEBDcmVhdGVEYXRlQ29sdW1uKHsgbmFtZTogJ2NyZWF0ZWRfYXQnIH0pXG5cdGNyZWF0ZWRBdDogRGF0ZVxuXG5cdEBVcGRhdGVEYXRlQ29sdW1uKHsgbmFtZTogJ3VwZGF0ZWRfYXQnIH0pXG5cdHVwZGF0ZWRBdDogRGF0ZVxuXG5cdEBEZWxldGVEYXRlQ29sdW1uKHsgbmFtZTogJ2RlbGV0ZWRfYXQnIH0pXG5cdEBFeGNsdWRlKClcblx0ZGVsZXRlZEF0OiBEYXRlXG59XG4iLCJpbXBvcnQgeyBDb2x1bW4sIEVudGl0eSwgSW5kZXggfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuXG5ARW50aXR5KCdjbGluaWMnKVxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgQ2xpbmljRW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyB1bmlxdWU6IHRydWUsIGxlbmd0aDogMTAsIG51bGxhYmxlOiBmYWxzZSB9KVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgbnVsbGFibGU6IGZhbHNlIH0pXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ3RpbnlpbnQnLCBkZWZhdWx0OiAxIH0pXG5cdGxldmVsOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0bmFtZTogc3RyaW5nXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGFkZHJlc3M6IHN0cmluZ1xufVxuIiwiaW1wb3J0IHsgRXhjbHVkZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgQ29sdW1uLCBFbnRpdHksIEluZGV4LCBKb2luQ29sdW1uLCBNYW55VG9PbmUgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSwgRUdlbmRlciB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuL2NsaW5pYy5lbnRpdHknXG5cbmV4cG9ydCBlbnVtIEVFbXBsb3llZVJvbGUge1xuXHRPd25lciA9ICdPd25lcicsXG5cdEFkbWluID0gJ0FkbWluJyxcblx0VXNlciA9ICdVc2VyJyxcbn1cblxuZXhwb3J0IHR5cGUgVEVtcGxveWVlUm9sZSA9IGtleW9mIHR5cGVvZiBFRW1wbG95ZWVSb2xlXG5cbkBFbnRpdHkoJ2VtcGxveWVlJylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ3VzZXJuYW1lJ10sIHsgdW5pcXVlOiB0cnVlIH0pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBFbXBsb3llZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QE1hbnlUb09uZSh0eXBlID0+IENsaW5pY0VudGl0eSlcblx0QEpvaW5Db2x1bW4oeyBuYW1lOiAnY2xpbmljX2lkJywgcmVmZXJlbmNlZENvbHVtbk5hbWU6ICdpZCcgfSlcblx0Y2xpbmljOiBDbGluaWNFbnRpdHlcblxuXHRAQ29sdW1uKHsgbGVuZ3RoOiAxMCwgbnVsbGFibGU6IHRydWUgfSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QENvbHVtbigpXG5cdEBFeGNsdWRlKClcblx0cGFzc3dvcmQ6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IEVFbXBsb3llZVJvbGUsIGRlZmF1bHQ6IEVFbXBsb3llZVJvbGUuVXNlciB9KVxuXHRyb2xlOiBFRW1wbG95ZWVSb2xlXG5cblx0QENvbHVtbih7IG5hbWU6ICdmdWxsX25hbWUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRmdWxsTmFtZTogc3RyaW5nXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGJpcnRoZGF5OiBEYXRlXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUdlbmRlciwgbnVsbGFibGU6IHRydWUgfSlcblx0Z2VuZGVyOiBFR2VuZGVyXG59XG4iLCJpbXBvcnQgeyBFbnRpdHksIENvbHVtbiwgSW5kZXggfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuXG5ARW50aXR5KCdtZWRpY2luZScpXG5ASW5kZXgoWydjbGluaWNJZCcsICdpZCddLCB7IHVuaXF1ZTogdHJ1ZSB9KVxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgTWVkaWNpbmVFbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IG5hbWU6ICdjbGluaWNfaWQnIH0pXG5cdGNsaW5pY0lkOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2JyYW5kX25hbWUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRicmFuZE5hbWU6IHN0cmluZyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHTDqm4gYmnhu4d0IGTGsOG7o2NcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2NoZW1pY2FsX25hbWUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRjaGVtaWNhbE5hbWU6IHN0cmluZyAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHTDqm4gZ+G7kWNcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2NhbGN1bGF0aW9uX3VuaXQnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRjYWxjdWxhdGlvblVuaXQ6IHN0cmluZyAgICAgICAgICAgICAgICAgICAgICAgIC8vIMSRxqFuIHbhu4sgdMOtbmg6IGzhu40sIOG7kW5nLCB24buJXG5cblx0QENvbHVtbih7IG5hbWU6ICdpbWFnZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGltYWdlOiBzdHJpbmdcbn1cbiIsImltcG9ydCB7IEV4Y2x1ZGUgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IENvbHVtbiwgRW50aXR5LCBJbmRleCB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5LCBFR2VuZGVyIH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ3BhdGllbnQnKVxuQEluZGV4KFsnY2xpbmljSWQnLCAnZnVsbE5hbWUnXSlcbkBJbmRleChbJ2NsaW5pY0lkJywgJ3Bob25lJ10pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBQYXRpZW50RW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyBuYW1lOiAnY2xpbmljX2lkJyB9KVxuXHRARXhjbHVkZSgpXG5cdGNsaW5pY0lkOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2Z1bGxfbmFtZScgfSlcblx0ZnVsbE5hbWU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBsZW5ndGg6IDEwLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGJpcnRoZGF5OiBEYXRlXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUdlbmRlciwgbnVsbGFibGU6IHRydWUgfSlcblx0Z2VuZGVyOiBFR2VuZGVyXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGFkZHJlc3M6IHN0cmluZ1xufVxuIiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9heGlvc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vblwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vbi9kZWNvcmF0b3JzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uL2VudW1zXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb24vc2VyaWFsaXplclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbmZpZ1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvcmVcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9qd3RcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9zd2FnZ2VyXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdGVybWludXNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy90eXBlb3JtXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImJjcnlwdFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJjbGFzcy10cmFuc2Zvcm1lclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJjbGFzcy12YWxpZGF0b3JcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiZXhwcmVzc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJleHByZXNzLXJhdGUtbGltaXRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiaGVsbWV0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInJlcXVlc3QtaXBcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwicnhqc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJyeGpzL29wZXJhdG9yc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJ0eXBlb3JtXCIpOyIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0uY2FsbChtb2R1bGUuZXhwb3J0cywgbW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCJpbXBvcnQgeyBWYWxpZGF0aW9uRXJyb3IsIFZhbGlkYXRpb25QaXBlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnXG5pbXBvcnQgeyBOZXN0RmFjdG9yeSwgUmVmbGVjdG9yIH0gZnJvbSAnQG5lc3Rqcy9jb3JlJ1xuaW1wb3J0IHJhdGVMaW1pdCBmcm9tICdleHByZXNzLXJhdGUtbGltaXQnXG5pbXBvcnQgaGVsbWV0IGZyb20gJ2hlbG1ldCdcbmltcG9ydCAqIGFzIHJlcXVlc3RJcCBmcm9tICdyZXF1ZXN0LWlwJ1xuaW1wb3J0IHsgQXBwTW9kdWxlIH0gZnJvbSAnLi9hcHAubW9kdWxlJ1xuaW1wb3J0IHsgc2V0dXBTd2FnZ2VyIH0gZnJvbSAnLi9jb21tb24vc3dhZ2dlcidcbmltcG9ydCB7IEh0dHBFeGNlcHRpb25GaWx0ZXIgfSBmcm9tICcuL2V4Y2VwdGlvbi1maWx0ZXJzL2h0dHAtZXhjZXB0aW9uLmZpbHRlcidcbmltcG9ydCB7IFVua25vd25FeGNlcHRpb25GaWx0ZXIgfSBmcm9tICcuL2V4Y2VwdGlvbi1maWx0ZXJzL3Vua25vd24tZXhjZXB0aW9uLmZpbHRlcidcbmltcG9ydCB7IFZhbGlkYXRpb25FeGNlcHRpb24sIFZhbGlkYXRpb25FeGNlcHRpb25GaWx0ZXIgfSBmcm9tICcuL2V4Y2VwdGlvbi1maWx0ZXJzL3ZhbGlkYXRpb24tZXhjZXB0aW9uLmZpbHRlcidcbmltcG9ydCB7IFVzZXJSb2xlc0d1YXJkIH0gZnJvbSAnLi9ndWFyZHMvdXNlci1yb2xlcy5ndWFyZCdcbmltcG9ydCB7IEFjY2Vzc0xvZ0ludGVyY2VwdG9yIH0gZnJvbSAnLi9pbnRlcmNlcHRvci9hY2Nlc3MtbG9nLmludGVyY2VwdG9yJ1xuaW1wb3J0IHsgVGltZW91dEludGVyY2VwdG9yIH0gZnJvbSAnLi9pbnRlcmNlcHRvci90aW1lb3V0LmludGVyY2VwdG9yJ1xuXG5hc3luYyBmdW5jdGlvbiBib290c3RyYXAoKSB7XG5cdGNvbnN0IGFwcCA9IGF3YWl0IE5lc3RGYWN0b3J5LmNyZWF0ZShBcHBNb2R1bGUpXG5cdFxuXHRjb25zdCBjb25maWdTZXJ2aWNlID0gYXBwLmdldChDb25maWdTZXJ2aWNlKVxuXHRjb25zdCBQT1JUID0gY29uZmlnU2VydmljZS5nZXQoJ05FU1RKU19QT1JUJylcblx0Y29uc3QgSE9TVCA9IGNvbmZpZ1NlcnZpY2UuZ2V0KCdORVNUSlNfSE9TVCcpIHx8ICdsb2NhbGhvc3QnXG5cblx0YXBwLnVzZShoZWxtZXQoKSlcblx0YXBwLnVzZShyYXRlTGltaXQoe1xuXHRcdHdpbmRvd01zOiA2MCAqIDEwMDAsIC8vIDEgbWludXRlc1xuXHRcdG1heDogMTAwLCAvLyBsaW1pdCBlYWNoIElQIHRvIDEwMCByZXF1ZXN0cyBwZXIgd2luZG93TXNcblx0fSkpXG5cdGFwcC5lbmFibGVDb3JzKClcblxuXHRhcHAudXNlKHJlcXVlc3RJcC5tdygpKVxuXG5cdGFwcC51c2VHbG9iYWxJbnRlcmNlcHRvcnMoXG5cdFx0bmV3IEFjY2Vzc0xvZ0ludGVyY2VwdG9yKCksXG5cdFx0bmV3IFRpbWVvdXRJbnRlcmNlcHRvcigpXG5cdClcblx0YXBwLnVzZUdsb2JhbEZpbHRlcnMoXG5cdFx0bmV3IFVua25vd25FeGNlcHRpb25GaWx0ZXIoKSxcblx0XHRuZXcgSHR0cEV4Y2VwdGlvbkZpbHRlcigpLFxuXHRcdG5ldyBWYWxpZGF0aW9uRXhjZXB0aW9uRmlsdGVyKClcblx0KVxuXG5cdGFwcC51c2VHbG9iYWxHdWFyZHMobmV3IFVzZXJSb2xlc0d1YXJkKGFwcC5nZXQoUmVmbGVjdG9yKSkpXG5cblx0YXBwLnVzZUdsb2JhbFBpcGVzKG5ldyBWYWxpZGF0aW9uUGlwZSh7XG5cdFx0dmFsaWRhdGlvbkVycm9yOiB7IHRhcmdldDogZmFsc2UsIHZhbHVlOiB0cnVlIH0sXG5cdFx0c2tpcE1pc3NpbmdQcm9wZXJ0aWVzOiB0cnVlLFxuXHRcdGV4Y2VwdGlvbkZhY3Rvcnk6IChlcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdID0gW10pID0+IG5ldyBWYWxpZGF0aW9uRXhjZXB0aW9uKGVycm9ycyksXG5cdH0pKVxuXG5cdGlmIChjb25maWdTZXJ2aWNlLmdldCgnTk9ERV9FTlYnKSAhPT0gJ3Byb2R1Y3Rpb24nKSB7XG5cdFx0c2V0dXBTd2FnZ2VyKGFwcClcblx0fVxuXG5cdGF3YWl0IGFwcC5saXN0ZW4oUE9SVCwgKCkgPT4ge1xuXHRcdGNvbnNvbGUubG9nKGDwn5qAIFNlcnZlciBkb2N1bWVudDogaHR0cDovLyR7SE9TVH06JHtQT1JUfS9kb2N1bWVudGApXG5cdH0pXG59XG5ib290c3RyYXAoKVxuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9