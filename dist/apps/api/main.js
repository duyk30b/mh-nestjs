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
                clinic: newClinic,
                username,
                password: hashPassword,
                role: employee_entity_1.EEmployeeRole.Owner,
            });
            const newEmployee = await manager.save(snapEmployee);
            return newEmployee;
        });
        return employee;
    }
    async login(loginDto) {
        const employee = await this.dataSource.manager.findOne(employee_entity_1.default, {
            relations: { clinic: true },
            where: {
                username: loginDto.username,
                clinic: { phone: loginDto.cPhone },
            },
        });
        if (!employee)
            throw new common_1.HttpException(exception_enum_1.ELoginError.EmployeeDoesNotExist, common_1.HttpStatus.BAD_REQUEST);
        const checkPassword = await bcrypt.compare(loginDto.password, employee.password);
        if (!checkPassword)
            throw new common_1.HttpException(exception_enum_1.ELoginError.WrongPassword, common_1.HttpStatus.BAD_GATEWAY);
        return employee;
    }
    async grantAccessToken(refreshToken) {
        const { uid } = this.jwtExtendService.verifyRefreshToken(refreshToken);
        const employee = await this.dataSource.getRepository(employee_entity_1.default).findOne({
            relations: { clinic: true },
            where: { id: uid },
        });
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
        const pathStorage = process.platform === 'win32' ? 'C:\\' : '/';
        const thresholdPercent = process.platform === 'win32' ? 0.9 : 0.5;
        return this.health.check([
            () => this.http.pingCheck('nestjs-docs', 'https://medihome.vn/document'),
            () => this.db.pingCheck('database'),
            () => this.disk.checkStorage('storage', { path: pathStorage, thresholdPercent }),
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
    (0, typeorm_1.Column)({ type: 'date', nullable: true }),
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
    (0, typeorm_1.Column)({ type: 'date', nullable: true }),
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
__decorate([
    (0, typeorm_1.Column)({ name: 'health_history', type: 'text', nullable: true }),
    __metadata("design:type", String)
], PatientEntity.prototype, "healthHistory", void 0);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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O0lBQ0QsR0FBRyxDQUFDLGdCQUFnQixDQUNuQixJQUFJLGlEQUFzQixFQUFFLEVBQzVCLElBQUksMkNBQW1CLEVBQUUsRUFDekIsSUFBSSx1REFBeUIsRUFBRSxDQUMvQjtJQUVELEdBQUcsQ0FBQyxlQUFlLENBQUMsSUFBSSxpQ0FBYyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsZ0JBQVMsQ0FBQyxDQUFDLENBQUM7SUFFM0QsR0FBRyxDQUFDLGNBQWMsQ0FBQyxJQUFJLHVCQUFjLENBQUM7UUFDckMsZUFBZSxFQUFFLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxLQUFLLEVBQUUsSUFBSSxFQUFFO1FBQy9DLHFCQUFxQixFQUFFLElBQUk7UUFDM0IsZ0JBQWdCLEVBQUUsQ0FBQyxTQUE0QixFQUFFLEVBQUUsRUFBRSxDQUFDLElBQUksaURBQW1CLENBQUMsTUFBTSxDQUFDO0tBQ3JGLENBQUMsQ0FBQztJQUVILElBQUksYUFBYSxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsS0FBSyxZQUFZLEVBQUU7UUFDbkQsMEJBQVksRUFBQyxHQUFHLENBQUM7S0FDakI7SUFFRCxNQUFNLEdBQUcsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLEdBQUcsRUFBRTtRQUMzQixPQUFPLENBQUMsR0FBRyxDQUFDLDhCQUE4QixJQUFJLElBQUksSUFBSSxXQUFXLENBQUM7SUFDbkUsQ0FBQyxDQUFDO0FBQ0gsQ0FBQztBQUNELFNBQVMsRUFBRSIsInNvdXJjZXMiOlsid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9hcHAubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvY29tbW9uL3N3YWdnZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2Vudmlyb25tZW50cy50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2V4Y2VwdGlvbi1maWx0ZXJzL2h0dHAtZXhjZXB0aW9uLmZpbHRlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvdW5rbm93bi1leGNlcHRpb24uZmlsdGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy92YWxpZGF0aW9uLWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2d1YXJkcy91c2VyLXJvbGVzLmd1YXJkLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9pbnRlcmNlcHRvci9hY2Nlc3MtbG9nLmludGVyY2VwdG9yLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9pbnRlcmNlcHRvci90aW1lb3V0LmludGVyY2VwdG9yLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9taWRkbGV3YXJlcy9sb2dnZXIubWlkZGxld2FyZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbWlkZGxld2FyZXMvdmFsaWRhdGUtYWNjZXNzLXRva2VuLm1pZGRsZXdhcmUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvand0LWV4dGVuZC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvaGVhbHRoL2hlYWx0aC5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2hlYWx0aC9oZWFsdGgubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L3BhdGllbnQubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL3BhdGllbnQvcGF0aWVudC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vYmFzZS5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvbWVkaWNpbmUuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvcGF0aWVudC5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9heGlvc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9yc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL2VudW1zXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb24vZXhjZXB0aW9uc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL3NlcmlhbGl6ZXJcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbmZpZ1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29yZVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvand0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9zd2FnZ2VyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy90ZXJtaW51c1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvdHlwZW9ybVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImJjcnlwdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImNsYXNzLXRyYW5zZm9ybWVyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiY2xhc3MtdmFsaWRhdG9yXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiZXhwcmVzc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImV4cHJlc3MtcmF0ZS1saW1pdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImhlbG1ldFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInJlcXVlc3QtaXBcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJyeGpzXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwicnhqcy9vcGVyYXRvcnNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJ0eXBlb3JtXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IE1pZGRsZXdhcmVDb25zdW1lciwgTW9kdWxlLCBOZXN0TW9kdWxlLCBSZXF1ZXN0TWV0aG9kIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUsIENvbmZpZ1R5cGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IE1hcmlhZGJDb25maWcgfSBmcm9tICcuL2Vudmlyb25tZW50cydcbmltcG9ydCB7IExvZ2dlck1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL2xvZ2dlci5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgVmFsaWRhdGVBY2Nlc3NUb2tlbk1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmVzL3ZhbGlkYXRlLWFjY2Vzcy10b2tlbi5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlJ1xuaW1wb3J0IHsgQ2xpbmljTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlJ1xuaW1wb3J0IHsgRW1wbG95ZWVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlJ1xuaW1wb3J0IHsgSGVhbHRoTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2hlYWx0aC9oZWFsdGgubW9kdWxlJ1xuaW1wb3J0IHsgTWVkaWNpbmVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlJ1xuaW1wb3J0IHsgUGF0aWVudE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9wYXRpZW50L3BhdGllbnQubW9kdWxlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1xuXHRcdENvbmZpZ01vZHVsZS5mb3JSb290KHtcblx0XHRcdGVudkZpbGVQYXRoOiBbYC5lbnYuJHtwcm9jZXNzLmVudi5OT0RFX0VOViB8fCAnbG9jYWwnfWAsICcuZW52J10sXG5cdFx0XHRpc0dsb2JhbDogdHJ1ZSxcblx0XHR9KSxcblx0XHRUeXBlT3JtTW9kdWxlLmZvclJvb3RBc3luYyh7XG5cdFx0XHRpbXBvcnRzOiBbQ29uZmlnTW9kdWxlLmZvckZlYXR1cmUoTWFyaWFkYkNvbmZpZyldLFxuXHRcdFx0aW5qZWN0OiBbTWFyaWFkYkNvbmZpZy5LRVldLFxuXHRcdFx0dXNlRmFjdG9yeTogKG1hcmlhZGJDb25maWc6IENvbmZpZ1R5cGU8dHlwZW9mIE1hcmlhZGJDb25maWc+KSA9PiBtYXJpYWRiQ29uZmlnLFxuXHRcdFx0Ly8gaW5qZWN0OiBbQ29uZmlnU2VydmljZV0sXG5cdFx0XHQvLyB1c2VGYWN0b3J5OiAoY29uZmlnU2VydmljZTogQ29uZmlnU2VydmljZSkgPT4gY29uZmlnU2VydmljZS5nZXQoJ215c3FsJyksXG5cdFx0fSksXG5cdFx0SGVhbHRoTW9kdWxlLFxuXHRcdEF1dGhNb2R1bGUsXG5cdFx0RW1wbG95ZWVNb2R1bGUsXG5cdFx0UGF0aWVudE1vZHVsZSxcblx0XHRDbGluaWNNb2R1bGUsXG5cdFx0TWVkaWNpbmVNb2R1bGUsXG5cdF0sXG59KVxuZXhwb3J0IGNsYXNzIEFwcE1vZHVsZSBpbXBsZW1lbnRzIE5lc3RNb2R1bGUge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2UpIHsgfVxuXHRjb25maWd1cmUoY29uc3VtZXI6IE1pZGRsZXdhcmVDb25zdW1lcikge1xuXHRcdGNvbnN1bWVyLmFwcGx5KExvZ2dlck1pZGRsZXdhcmUpLmZvclJvdXRlcygnKicpXG5cblx0XHRjb25zdW1lci5hcHBseShWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSlcblx0XHRcdC5leGNsdWRlKFxuXHRcdFx0XHQnYXV0aC8oLiopJyxcblx0XHRcdFx0Jy8nLFxuXHRcdFx0XHR7IHBhdGg6ICdoZWFsdGgnLCBtZXRob2Q6IFJlcXVlc3RNZXRob2QuR0VUIH1cblx0XHRcdClcblx0XHRcdC5mb3JSb3V0ZXMoJyonKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBWYWxpZGF0b3JDb25zdHJhaW50LCBWYWxpZGF0b3JDb25zdHJhaW50SW50ZXJmYWNlLCBWYWxpZGF0aW9uQXJndW1lbnRzIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5AVmFsaWRhdG9yQ29uc3RyYWludCh7IG5hbWU6ICdpc1Bob25lJywgYXN5bmM6IGZhbHNlIH0pXG5leHBvcnQgY2xhc3MgSXNQaG9uZSBpbXBsZW1lbnRzIFZhbGlkYXRvckNvbnN0cmFpbnRJbnRlcmZhY2Uge1xuXHR2YWxpZGF0ZSh0ZXh0OiBzdHJpbmcsIGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRyZXR1cm4gLygoMDl8MDN8MDd8MDh8MDUpKyhbMC05XXs4fSlcXGIpL2cudGVzdCh0ZXh0KVxuXHR9XG5cblx0ZGVmYXVsdE1lc3NhZ2UoYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAnJHByb3BlcnR5IG11c3QgYmUgcmVhbCBudW1iZXJwaG9uZSAhJ1xuXHR9XG59XG5cbkBWYWxpZGF0b3JDb25zdHJhaW50KHsgbmFtZTogJ2lzR21haWwnLCBhc3luYzogZmFsc2UgfSlcbmV4cG9ydCBjbGFzcyBJc0dtYWlsIGltcGxlbWVudHMgVmFsaWRhdG9yQ29uc3RyYWludEludGVyZmFjZSB7XG5cdHZhbGlkYXRlKHRleHQ6IHN0cmluZywgYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAvXihbYS16QS1aMC05XXxcXC58LXxfKSsoQGdtYWlsLmNvbSkkLy50ZXN0KHRleHQpXG5cdH1cblxuXHRkZWZhdWx0TWVzc2FnZShhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0cmV0dXJuICckcHJvcGVydHkgbXVzdCBiZSBhIGdtYWlsIGFkZHJlc3MgISdcblx0fVxufVxuIiwiaW1wb3J0IHsgSU5lc3RBcHBsaWNhdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgU3dhZ2dlck1vZHVsZSwgRG9jdW1lbnRCdWlsZGVyIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuXG5leHBvcnQgY29uc3Qgc2V0dXBTd2FnZ2VyID0gKGFwcDogSU5lc3RBcHBsaWNhdGlvbikgPT4ge1xuXHRjb25zdCBjb25maWcgPSBuZXcgRG9jdW1lbnRCdWlsZGVyKClcblx0XHQuc2V0VGl0bGUoJ1NpbXBsZSBBUEknKVxuXHRcdC5zZXREZXNjcmlwdGlvbignTWVkaWhvbWUgQVBJIHVzZSBTd2FnZ2VyJylcblx0XHQuc2V0VmVyc2lvbignMS4wJylcblx0XHQuYWRkQmVhcmVyQXV0aChcblx0XHRcdHsgdHlwZTogJ2h0dHAnLCBkZXNjcmlwdGlvbjogJ0FjY2VzcyB0b2tlbicgfSxcblx0XHRcdCdhY2Nlc3MtdG9rZW4nXG5cdFx0KVxuXHRcdC5idWlsZCgpXG5cdGNvbnN0IGRvY3VtZW50ID0gU3dhZ2dlck1vZHVsZS5jcmVhdGVEb2N1bWVudChhcHAsIGNvbmZpZylcblx0U3dhZ2dlck1vZHVsZS5zZXR1cCgnZG9jdW1lbnQnLCBhcHAsIGRvY3VtZW50KVxufVxuIiwiaW1wb3J0IHsgcmVnaXN0ZXJBcyB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZU9wdGlvbnMgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5cbmV4cG9ydCBjb25zdCBKd3RDb25maWcgPSByZWdpc3RlckFzKCdqd3QnLCAoKSA9PiAoe1xuXHRhY2Nlc3NLZXk6IHByb2Nlc3MuZW52LkpXVF9BQ0NFU1NfS0VZLFxuXHRyZWZyZXNoS2V5OiBwcm9jZXNzLmVudi5KV1RfUkVGUkVTSF9LRVksXG5cdGFjY2Vzc1RpbWU6IE51bWJlcihwcm9jZXNzLmVudi5KV1RfQUNDRVNTX1RJTUUpLFxuXHRyZWZyZXNoVGltZTogTnVtYmVyKHByb2Nlc3MuZW52LkpXVF9SRUZSRVNIX1RJTUUpLFxufSkpXG5cbmV4cG9ydCBjb25zdCBNYXJpYWRiQ29uZmlnID0gcmVnaXN0ZXJBcygnbWFyaWFkYicsICgpOiBUeXBlT3JtTW9kdWxlT3B0aW9ucyA9PiAoe1xuXHR0eXBlOiAnbWFyaWFkYicsXG5cdGhvc3Q6IHByb2Nlc3MuZW52Lk1BUklBREJfSE9TVCxcblx0cG9ydDogcGFyc2VJbnQocHJvY2Vzcy5lbnYuTUFSSUFEQl9QT1JULCAxMCksXG5cdGRhdGFiYXNlOiBwcm9jZXNzLmVudi5NQVJJQURCX0RBVEFCQVNFLFxuXHR1c2VybmFtZTogcHJvY2Vzcy5lbnYuTUFSSUFEQl9VU0VSTkFNRSxcblx0cGFzc3dvcmQ6IHByb2Nlc3MuZW52Lk1BUklBREJfUEFTU1dPUkQsXG5cdGF1dG9Mb2FkRW50aXRpZXM6IHRydWUsXG5cdGxvZ2dpbmc6IHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicsXG5cdHN5bmNocm9uaXplOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ2xvY2FsJyxcbn0pKVxuIiwiZXhwb3J0IGVudW0gRUVycm9yIHtcblx0VW5rbm93biA9ICdBMDAuVU5LTk9XTidcbn1cblxuZXhwb3J0IGVudW0gRVZhbGlkYXRlRXJyb3Ige1xuXHRGYWlsZWQgPSAnVjAwLlZBTElEQVRFX0ZBSUxFRCdcbn1cblxuZXhwb3J0IGVudW0gRVJlZ2lzdGVyRXJyb3Ige1xuXHRFeGlzdEVtYWlsQW5kUGhvbmUgPSAnUjAxLkVYSVNUX0VNQUlMX0FORF9QSE9ORScsXG5cdEV4aXN0RW1haWwgPSAnUjAyLkVYSVNUX0VNQUlMJyxcblx0RXhpc3RQaG9uZSA9ICdSMDMuRVhJU1RfUEhPTkUnLFxuXHRFeGlzdFVzZXJuYW1lID0gJ1IwNC5FWElTVF9VU0VSTkFNRSdcbn1cblxuZXhwb3J0IGVudW0gRUxvZ2luRXJyb3Ige1xuXHRFbXBsb3llZURvZXNOb3RFeGlzdCA9ICdMMDEuRU1QTE9ZRUVfRE9FU19OT1RfRVhJU1QnLFxuXHRXcm9uZ1Bhc3N3b3JkID0gJ0wwMi5XUk9OR19QQVNTV09SRCdcbn1cblxuZXhwb3J0IGVudW0gRVRva2VuRXJyb3Ige1xuXHRFeHBpcmVkID0gJ1QwMS5FWFBJUkVEJyxcblx0SW52YWxpZCA9ICdUMDIuSU5WQUxJRCdcbn1cblxuZXhwb3J0IGVudW0gRUVtcGxveWVlRXJyb3Ige1xuXHRVc2VybmFtZUV4aXN0cyA9ICdVMDEuVVNFUk5BTUVfRVhJU1RTJyxcblx0Tm90RXhpc3RzID0gJ1UwMi5FTVBMT1lFRV9ET0VTX05PVF9FWElTVCdcbn1cblxuZXhwb3J0IGVudW0gRVBhdGllbnRFcnJvciB7XG5cdE5vdEV4aXN0cyA9ICdQMDEuUEFUSUVOVF9ET0VTX05PVF9FWElTVCdcbn1cbiIsImltcG9ydCB7IEV4Y2VwdGlvbkZpbHRlciwgQ2F0Y2gsIEFyZ3VtZW50c0hvc3QsIEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcblxuQENhdGNoKEh0dHBFeGNlcHRpb24pXG5leHBvcnQgY2xhc3MgSHR0cEV4Y2VwdGlvbkZpbHRlciBpbXBsZW1lbnRzIEV4Y2VwdGlvbkZpbHRlciB7XG5cdGNhdGNoKGV4Y2VwdGlvbjogSHR0cEV4Y2VwdGlvbiwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IGV4Y2VwdGlvbi5nZXRTdGF0dXMoKVxuXG5cdFx0cmVzcG9uc2Uuc3RhdHVzKGh0dHBTdGF0dXMpLmpzb24oe1xuXHRcdFx0aHR0cFN0YXR1cyxcblx0XHRcdG1lc3NhZ2U6IGV4Y2VwdGlvbi5nZXRSZXNwb25zZSgpLFxuXHRcdFx0cGF0aDogcmVxdWVzdC51cmwsXG5cdFx0XHR0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcmd1bWVudHNIb3N0LCBDYXRjaCwgRXhjZXB0aW9uRmlsdGVyLCBIdHRwU3RhdHVzLCBMb2dnZXIgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcblxuQENhdGNoKEVycm9yKVxuZXhwb3J0IGNsYXNzIFVua25vd25FeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ1NFUlZFUl9FUlJPUicpKSB7IH1cblxuXHRjYXRjaChleGNlcHRpb246IEVycm9yLCBob3N0OiBBcmd1bWVudHNIb3N0KSB7XG5cdFx0Y29uc3QgY3R4ID0gaG9zdC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlc3BvbnNlID0gY3R4LmdldFJlc3BvbnNlPFJlc3BvbnNlPigpXG5cdFx0Y29uc3QgcmVxdWVzdCA9IGN0eC5nZXRSZXF1ZXN0PFJlcXVlc3Q+KClcblx0XHRjb25zdCBodHRwU3RhdHVzID0gSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1JcblxuXHRcdHRoaXMubG9nZ2VyLmVycm9yKGV4Y2VwdGlvbi5zdGFjaylcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlOiBleGNlcHRpb24ubWVzc2FnZSxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXJndW1lbnRzSG9zdCwgQ2F0Y2gsIEV4Y2VwdGlvbkZpbHRlciwgSHR0cFN0YXR1cywgVmFsaWRhdGlvbkVycm9yIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBFVmFsaWRhdGVFcnJvciB9IGZyb20gJy4vZXhjZXB0aW9uLmVudW0nXG5cbmV4cG9ydCBjbGFzcyBWYWxpZGF0aW9uRXhjZXB0aW9uIGV4dGVuZHMgRXJyb3Ige1xuXHRwcml2YXRlIHJlYWRvbmx5IGVycm9yczogVmFsaWRhdGlvbkVycm9yW11cblx0Y29uc3RydWN0b3IodmFsaWRhdGlvbkVycm9yczogVmFsaWRhdGlvbkVycm9yW10gPSBbXSkge1xuXHRcdHN1cGVyKEVWYWxpZGF0ZUVycm9yLkZhaWxlZClcblx0XHR0aGlzLmVycm9ycyA9IHZhbGlkYXRpb25FcnJvcnNcblx0fVxuXHRnZXRNZXNzYWdlKCkge1xuXHRcdHJldHVybiB0aGlzLm1lc3NhZ2Vcblx0fVxuXHRnZXRFcnJvcnMoKSB7XG5cdFx0cmV0dXJuIHRoaXMuZXJyb3JzXG5cdH1cbn1cblxuQENhdGNoKFZhbGlkYXRpb25FeGNlcHRpb24pXG5leHBvcnQgY2xhc3MgVmFsaWRhdGlvbkV4Y2VwdGlvbkZpbHRlciBpbXBsZW1lbnRzIEV4Y2VwdGlvbkZpbHRlciB7XG5cdGNhdGNoKGV4Y2VwdGlvbjogVmFsaWRhdGlvbkV4Y2VwdGlvbiwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IEh0dHBTdGF0dXMuVU5QUk9DRVNTQUJMRV9FTlRJVFlcblx0XHRjb25zdCBtZXNzYWdlID0gZXhjZXB0aW9uLmdldE1lc3NhZ2UoKVxuXHRcdGNvbnN0IGVycm9ycyA9IGV4Y2VwdGlvbi5nZXRFcnJvcnMoKVxuXG5cdFx0cmVzcG9uc2Uuc3RhdHVzKGh0dHBTdGF0dXMpLmpzb24oe1xuXHRcdFx0aHR0cFN0YXR1cyxcblx0XHRcdG1lc3NhZ2UsXG5cdFx0XHRlcnJvcnMsXG5cdFx0XHRwYXRoOiByZXF1ZXN0LnVybCxcblx0XHRcdHRpbWVzdGFtcDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IENhbkFjdGl2YXRlLCBFeGVjdXRpb25Db250ZXh0LCBJbmplY3RhYmxlLCBTZXRNZXRhZGF0YSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVmbGVjdG9yIH0gZnJvbSAnQG5lc3Rqcy9jb3JlJ1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBURW1wbG95ZWVSb2xlIH0gZnJvbSAndHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuXG5leHBvcnQgY29uc3QgVXNlclJvbGVzID0gKC4uLnVzZXJSb2xlczogVEVtcGxveWVlUm9sZVtdKSA9PiBTZXRNZXRhZGF0YSgndXNlcl9yb2xlcycsIHVzZXJSb2xlcylcbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBVc2VyUm9sZXNHdWFyZCBpbXBsZW1lbnRzIENhbkFjdGl2YXRlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWZsZWN0b3I6IFJlZmxlY3RvcikgeyB9XG5cblx0Y2FuQWN0aXZhdGUoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCk6IGJvb2xlYW4gfCBQcm9taXNlPGJvb2xlYW4+IHwgT2JzZXJ2YWJsZTxib29sZWFuPiB7XG5cdFx0Y29uc3Qgcm9sZXMgPSB0aGlzLnJlZmxlY3Rvci5nZXQ8VEVtcGxveWVlUm9sZVtdPigndXNlcl9yb2xlcycsIGNvbnRleHQuZ2V0SGFuZGxlcigpKVxuXHRcdGlmICghcm9sZXMpIHJldHVybiB0cnVlXG5cblx0XHRjb25zdCByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4gPSBjb250ZXh0LnN3aXRjaFRvSHR0cCgpLmdldFJlcXVlc3QoKVxuXHRcdGNvbnN0IHsgcm9sZSB9ID0gcmVxdWVzdC50b2tlblBheWxvYWRcblx0XHRyZXR1cm4gcm9sZXMuaW5jbHVkZXMocm9sZSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQ2FsbEhhbmRsZXIsIEV4ZWN1dGlvbkNvbnRleHQsIEluamVjdGFibGUsIE5lc3RJbnRlcmNlcHRvciwgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcydcbmltcG9ydCB7IHRhcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQWNjZXNzTG9nSW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ0FDQ0VTU19MT0cnKSkgeyB9XG5cblx0aW50ZXJjZXB0KGNvbnRleHQ6IEV4ZWN1dGlvbkNvbnRleHQsIG5leHQ6IENhbGxIYW5kbGVyKTogT2JzZXJ2YWJsZTxhbnk+IHtcblx0XHRjb25zdCBzdGFydFRpbWUgPSBuZXcgRGF0ZSgpXG5cdFx0Y29uc3QgY3R4ID0gY29udGV4dC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVxdWVzdCgpXG5cblx0XHRjb25zdCB7IHVybCwgbWV0aG9kIH0gPSByZXF1ZXN0XG5cdFx0Y29uc3QgeyBzdGF0dXNDb2RlIH0gPSByZXNwb25zZVxuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxdWVzdClcblxuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUodGFwKCgpID0+IHtcblx0XHRcdGNvbnN0IG1zZyA9IGAke3N0YXJ0VGltZS50b0lTT1N0cmluZygpfSB8ICR7aXB9IHwgJHttZXRob2R9IHwgJHtzdGF0dXNDb2RlfSB8ICR7dXJsfSB8ICR7RGF0ZS5ub3coKSAtIHN0YXJ0VGltZS5nZXRUaW1lKCl9bXNgXG5cdFx0XHRyZXR1cm4gdGhpcy5sb2dnZXIubG9nKG1zZylcblx0XHR9KSlcblx0fVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmVzdEludGVyY2VwdG9yLCBFeGVjdXRpb25Db250ZXh0LCBDYWxsSGFuZGxlciwgUmVxdWVzdFRpbWVvdXRFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IE9ic2VydmFibGUsIHRocm93RXJyb3IsIFRpbWVvdXRFcnJvciB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBjYXRjaEVycm9yLCB0aW1lb3V0IH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBUaW1lb3V0SW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRpbnRlcmNlcHQoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCwgbmV4dDogQ2FsbEhhbmRsZXIpOiBPYnNlcnZhYmxlPGFueT4ge1xuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUoXG5cdFx0XHR0aW1lb3V0KDEwMDAwKSxcblx0XHRcdGNhdGNoRXJyb3IoZXJyID0+IHtcblx0XHRcdFx0aWYgKGVyciBpbnN0YW5jZW9mIFRpbWVvdXRFcnJvcikge1xuXHRcdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IG5ldyBSZXF1ZXN0VGltZW91dEV4Y2VwdGlvbigpKVxuXHRcdFx0XHR9XG5cdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IGVycilcblx0XHRcdH0pXG5cdFx0KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZXN0TWlkZGxld2FyZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gJ2V4cHJlc3MnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBMb2dnZXJNaWRkbGV3YXJlIGltcGxlbWVudHMgTmVzdE1pZGRsZXdhcmUge1xuXHR1c2UocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pIHtcblx0XHRjb25zb2xlLmxvZygnUmVxdWVzdC4uLicpXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUsIE5lc3RNaWRkbGV3YXJlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBOZXh0RnVuY3Rpb24sIFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcbmltcG9ydCB7IElKd3RQYXlsb2FkLCBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4uL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSBpbXBsZW1lbnRzIE5lc3RNaWRkbGV3YXJlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlKSB7IH1cblxuXHRhc3luYyB1c2UocmVxOiBSZXF1ZXN0VG9rZW4sIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikge1xuXHRcdGNvbnN0IGF1dGhvcml6YXRpb24gPSByZXEuaGVhZGVyKCdBdXRob3JpemF0aW9uJykgfHwgJydcblx0XHRjb25zdCBbLCBhY2Nlc3NUb2tlbl0gPSBhdXRob3JpemF0aW9uLnNwbGl0KCcgJylcblx0XHRjb25zdCBkZWNvZGU6IElKd3RQYXlsb2FkID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuKVxuXHRcdHJlcS50b2tlblBheWxvYWQgPSBkZWNvZGVcblx0XHRuZXh0KClcblx0fVxufVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgUGFyYW0sIFBvc3QsIFJlcSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IFJlcXVlc3QgfSBmcm9tICdleHByZXNzJ1xuaW1wb3J0IHsgZ2V0Q2xpZW50SXAgfSBmcm9tICdyZXF1ZXN0LWlwJ1xuaW1wb3J0IHsgTG9naW5EdG8sIFJlZnJlc2hUb2tlbkR0bywgUmVnaXN0ZXJEdG8gfSBmcm9tICcuL2F1dGguZHRvJ1xuaW1wb3J0IHsgQXV0aFNlcnZpY2UgfSBmcm9tICcuL2F1dGguc2VydmljZSdcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ0F1dGgnKVxuQENvbnRyb2xsZXIoJ2F1dGgnKVxuZXhwb3J0IGNsYXNzIEF1dGhDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSByZWFkb25seSBhdXRoU2VydmljZTogQXV0aFNlcnZpY2UsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlXG5cdCkgeyB9XG5cblx0QFBvc3QoJ3JlZ2lzdGVyJylcblx0YXN5bmMgcmVnaXN0ZXIoQEJvZHkoKSByZWdpc3RlckR0bzogUmVnaXN0ZXJEdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0KSB7XG5cdFx0Y29uc3QgaXAgPSBnZXRDbGllbnRJcChyZXF1ZXN0KVxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5yZWdpc3RlcihyZWdpc3RlckR0bylcblx0XHRjb25zdCB7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfSA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVUb2tlbkZyb21Vc2VyKGVtcGxveWVlKVxuXHRcdHJldHVybiB7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfVxuXHR9XG5cblx0QFBvc3QoJ2xvZ2luJylcblx0YXN5bmMgbG9naW4oQEJvZHkoKSBsb2dpbkR0bzogTG9naW5EdG8pIHtcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UubG9naW4obG9naW5EdG8pXG5cdFx0Y29uc3QgeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0gPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UuY3JlYXRlVG9rZW5Gcm9tVXNlcihlbXBsb3llZSlcblx0XHRyZXR1cm4geyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH1cblx0fVxuXG5cdEBQb3N0KCdsb2dvdXQnKVxuXHRsb2dvdXQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBQb3N0KCdjaGFuZ2UtcGFzc3dvcmQnKVxuXHRjaGFuZ2VQYXNzd29yZChAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQEJvZHkoKSB1cGRhdGVBdXRoRHRvOiBMb2dpbkR0bykge1xuXHRcdC8vIHJldHVybiB0aGlzLmF1dGhTZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZUF1dGhEdG8pXG5cdH1cblxuXHRAUG9zdCgnZm9yZ290LXBhc3N3b3JkJylcblx0Zm9yZ290UGFzc3dvcmQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS5yZW1vdmUoK2lkKVxuXHR9XG5cblx0QFBvc3QoJ3JlZnJlc2gtdG9rZW4nKVxuXHRhc3luYyBncmFudEFjY2Vzc1Rva2VuKEBCb2R5KCkgcmVmcmVzaFRva2VuRHRvOiBSZWZyZXNoVG9rZW5EdG8pIHtcblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UuZ3JhbnRBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW5EdG8ucmVmcmVzaFRva2VuKVxuXHRcdHJldHVybiB7IGFjY2Vzc1Rva2VuIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHkgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0RlZmluZWQsIExlbmd0aCwgTWluTGVuZ3RoLCBWYWxpZGF0ZSB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcbmltcG9ydCB7IElzR21haWwsIElzUGhvbmUgfSBmcm9tICcuLi8uLi9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbSdcblxuZXhwb3J0IGNsYXNzIFJlZ2lzdGVyRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2V4YW1wbGUtMkBnbWFpbC5jb20nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRAVmFsaWRhdGUoSXNHbWFpbClcblx0ZW1haWw6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICcwMzc2ODk5ODY2JyB9KVxuXHRASXNEZWZpbmVkKClcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnYWRtaW4nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIExvZ2luRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJzA5ODYwMjExOTAnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATGVuZ3RoKDEwLCAxMClcblx0Y1Bob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnYWRtaW4nIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFJlZnJlc2hUb2tlbkR0byB7XG5cdEBBcGlQcm9wZXJ0eSgpXG5cdEBJc0RlZmluZWQoKVxuXHRyZWZyZXNoVG9rZW46IHN0cmluZ1xufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEp3dE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvand0J1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgSnd0Q29uZmlnIH0gZnJvbSAnLi4vLi4vZW52aXJvbm1lbnRzJ1xuaW1wb3J0IHsgQXV0aENvbnRyb2xsZXIgfSBmcm9tICcuL2F1dGguY29udHJvbGxlcidcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHksIEVtcGxveWVlRW50aXR5XSksXG5cdFx0Q29uZmlnTW9kdWxlLmZvckZlYXR1cmUoSnd0Q29uZmlnKSxcblx0XHRKd3RNb2R1bGUsXG5cdF0sXG5cdGNvbnRyb2xsZXJzOiBbQXV0aENvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtBdXRoU2VydmljZSwgSnd0RXh0ZW5kU2VydmljZV0sXG5cdGV4cG9ydHM6IFtKd3RFeHRlbmRTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb24sIEh0dHBTdGF0dXMsIEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVFbXBsb3llZVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVMb2dpbkVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgTG9naW5EdG8sIFJlZ2lzdGVyRHRvIH0gZnJvbSAnLi9hdXRoLmR0bydcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlLFxuXHRcdHByaXZhdGUgand0RXh0ZW5kU2VydmljZTogSnd0RXh0ZW5kU2VydmljZVxuXHQpIHsgfVxuXG5cdGFzeW5jIHJlZ2lzdGVyKHJlZ2lzdGVyRHRvOiBSZWdpc3RlckR0byk6IFByb21pc2U8RW1wbG95ZWVFbnRpdHk+IHtcblx0XHRjb25zdCB7IGVtYWlsLCBwaG9uZSwgdXNlcm5hbWUsIHBhc3N3b3JkIH0gPSByZWdpc3RlckR0b1xuXHRcdGNvbnN0IGhhc2hQYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5oYXNoKHBhc3N3b3JkLCA1KVxuXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UudHJhbnNhY3Rpb24oYXN5bmMgKG1hbmFnZXIpID0+IHtcblx0XHRcdGNvbnN0IGZpbmRDbGluaWMgPSBhd2FpdCBtYW5hZ2VyLmZpbmRPbmUoQ2xpbmljRW50aXR5LCB7IHdoZXJlOiBbeyBlbWFpbCB9LCB7IHBob25lIH1dIH0pXG5cdFx0XHRpZiAoZmluZENsaW5pYykge1xuXHRcdFx0XHRpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwgJiYgZmluZENsaW5pYy5waG9uZSA9PT0gcGhvbmUpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsQW5kUGhvbmUsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZSBpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2UgaWYgKGZpbmRDbGluaWMucGhvbmUgPT09IHBob25lKSB7XG5cdFx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RQaG9uZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdFx0Y29uc3Qgc25hcENsaW5pYyA9IG1hbmFnZXIuY3JlYXRlKENsaW5pY0VudGl0eSwge1xuXHRcdFx0XHRwaG9uZSxcblx0XHRcdFx0ZW1haWwsXG5cdFx0XHRcdGxldmVsOiAxLFxuXHRcdFx0fSlcblx0XHRcdGNvbnN0IG5ld0NsaW5pYyA9IGF3YWl0IG1hbmFnZXIuc2F2ZShzbmFwQ2xpbmljKVxuXG5cdFx0XHRjb25zdCBzbmFwRW1wbG95ZWUgPSBtYW5hZ2VyLmNyZWF0ZShFbXBsb3llZUVudGl0eSwge1xuXHRcdFx0XHRjbGluaWNJZDogbmV3Q2xpbmljLmlkLFxuXHRcdFx0XHRjbGluaWM6IG5ld0NsaW5pYyxcblx0XHRcdFx0dXNlcm5hbWUsXG5cdFx0XHRcdHBhc3N3b3JkOiBoYXNoUGFzc3dvcmQsXG5cdFx0XHRcdHJvbGU6IEVFbXBsb3llZVJvbGUuT3duZXIsXG5cdFx0XHR9KVxuXHRcdFx0Y29uc3QgbmV3RW1wbG95ZWUgPSBhd2FpdCBtYW5hZ2VyLnNhdmUoc25hcEVtcGxveWVlKVxuXG5cdFx0XHRyZXR1cm4gbmV3RW1wbG95ZWVcblx0XHR9KVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBsb2dpbihsb2dpbkR0bzogTG9naW5EdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UubWFuYWdlci5maW5kT25lKEVtcGxveWVlRW50aXR5LCB7XG5cdFx0XHRyZWxhdGlvbnM6IHsgY2xpbmljOiB0cnVlIH0sXG5cdFx0XHR3aGVyZToge1xuXHRcdFx0XHR1c2VybmFtZTogbG9naW5EdG8udXNlcm5hbWUsXG5cdFx0XHRcdGNsaW5pYzogeyBwaG9uZTogbG9naW5EdG8uY1Bob25lIH0sXG5cdFx0XHR9LFxuXHRcdH0pXG5cdFx0aWYgKCFlbXBsb3llZSkgdGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuRW1wbG95ZWVEb2VzTm90RXhpc3QsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cblx0XHRjb25zdCBjaGVja1Bhc3N3b3JkID0gYXdhaXQgYmNyeXB0LmNvbXBhcmUobG9naW5EdG8ucGFzc3dvcmQsIGVtcGxveWVlLnBhc3N3b3JkKVxuXHRcdGlmICghY2hlY2tQYXNzd29yZCkgdGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuV3JvbmdQYXNzd29yZCwgSHR0cFN0YXR1cy5CQURfR0FURVdBWSlcblxuXHRcdHJldHVybiBlbXBsb3llZVxuXHR9XG5cblx0YXN5bmMgZ3JhbnRBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG5cdFx0Y29uc3QgeyB1aWQgfSA9IHRoaXMuand0RXh0ZW5kU2VydmljZS52ZXJpZnlSZWZyZXNoVG9rZW4ocmVmcmVzaFRva2VuKVxuXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UuZ2V0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSkuZmluZE9uZSh7XG5cdFx0XHRyZWxhdGlvbnM6IHsgY2xpbmljOiB0cnVlIH0sXG5cdFx0XHR3aGVyZTogeyBpZDogdWlkIH0sXG5cdFx0fSlcblxuXHRcdGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLmNyZWF0ZUFjY2Vzc1Rva2VuKGVtcGxveWVlKVxuXHRcdHJldHVybiBhY2Nlc3NUb2tlblxuXHR9XG59XG4iLCJpbXBvcnQgeyBIdHRwRXhjZXB0aW9uLCBIdHRwU3RhdHVzLCBJbmplY3QgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IENvbmZpZ1R5cGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEp3dFNlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2p3dCdcbmltcG9ydCBVc2VyRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgSUp3dFBheWxvYWQgfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgSnd0Q29uZmlnIH0gZnJvbSAnLi4vLi4vZW52aXJvbm1lbnRzJ1xuaW1wb3J0IHsgRUVycm9yLCBFVG9rZW5FcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuXG5leHBvcnQgY2xhc3MgSnd0RXh0ZW5kU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdEBJbmplY3QoSnd0Q29uZmlnLktFWSkgcHJpdmF0ZSBqd3RDb25maWc6IENvbmZpZ1R5cGU8dHlwZW9mIEp3dENvbmZpZz4sXG5cdFx0cHJpdmF0ZSByZWFkb25seSBqd3RTZXJ2aWNlOiBKd3RTZXJ2aWNlXG5cdCkgeyB9XG5cblx0Y3JlYXRlQWNjZXNzVG9rZW4odXNlcjogVXNlckVudGl0eSk6IHN0cmluZyB7XG5cdFx0Y29uc3QgdXNlclBheWxvYWQ6IElKd3RQYXlsb2FkID0ge1xuXHRcdFx0Y1Bob25lOiB1c2VyLmNsaW5pYy5waG9uZSxcblx0XHRcdGNpZDogdXNlci5jbGluaWMuaWQsXG5cdFx0XHR1aWQ6IHVzZXIuaWQsXG5cdFx0XHR1c2VybmFtZTogdXNlci51c2VybmFtZSxcblx0XHRcdHJvbGU6IHVzZXIucm9sZSxcblx0XHR9XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHVzZXJQYXlsb2FkLCB7XG5cdFx0XHRzZWNyZXQ6IHRoaXMuand0Q29uZmlnLmFjY2Vzc0tleSxcblx0XHRcdGV4cGlyZXNJbjogdGhpcy5qd3RDb25maWcuYWNjZXNzVGltZSxcblx0XHR9KVxuXHR9XG5cblx0Y3JlYXRlUmVmcmVzaFRva2VuKHVpZDogbnVtYmVyKTogc3RyaW5nIHtcblx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnNpZ24oeyB1aWQgfSwge1xuXHRcdFx0c2VjcmV0OiB0aGlzLmp3dENvbmZpZy5yZWZyZXNoS2V5LFxuXHRcdFx0ZXhwaXJlc0luOiB0aGlzLmp3dENvbmZpZy5yZWZyZXNoVGltZSxcblx0XHR9KVxuXHR9XG5cblx0Y3JlYXRlVG9rZW5Gcm9tVXNlcih1c2VyOiBVc2VyRW50aXR5KSB7XG5cdFx0Y29uc3QgYWNjZXNzVG9rZW4gPSB0aGlzLmNyZWF0ZUFjY2Vzc1Rva2VuKHVzZXIpXG5cdFx0Y29uc3QgcmVmcmVzaFRva2VuID0gdGhpcy5jcmVhdGVSZWZyZXNoVG9rZW4odXNlci5pZClcblx0XHRyZXR1cm4geyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH1cblx0fVxuXG5cdHZlcmlmeUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuOiBzdHJpbmcpOiBJSnd0UGF5bG9hZCB7XG5cdFx0dHJ5IHtcblx0XHRcdHJldHVybiB0aGlzLmp3dFNlcnZpY2UudmVyaWZ5KGFjY2Vzc1Rva2VuLCB7IHNlY3JldDogdGhpcy5qd3RDb25maWcuYWNjZXNzS2V5IH0pXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vd24sIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxuXG5cdHZlcmlmeVJlZnJlc2hUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZyk6IHsgdWlkOiBudW1iZXIgfSB7XG5cdFx0dHJ5IHtcblx0XHRcdHJldHVybiB0aGlzLmp3dFNlcnZpY2UudmVyaWZ5KHJlZnJlc2hUb2tlbiwgeyBzZWNyZXQ6IHRoaXMuand0Q29uZmlnLnJlZnJlc2hLZXkgfSlcblx0XHR9IGNhdGNoIChlcnJvcikge1xuXHRcdFx0aWYgKGVycm9yLm5hbWUgPT09ICdUb2tlbkV4cGlyZWRFcnJvcicpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVRva2VuRXJyb3IuRXhwaXJlZCwgSHR0cFN0YXR1cy5GT1JCSURERU4pXG5cdFx0XHR9IGVsc2UgaWYgKGVycm9yLm5hbWUgPT09ICdKc29uV2ViVG9rZW5FcnJvcicpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVRva2VuRXJyb3IuSW52YWxpZCwgSHR0cFN0YXR1cy5GT1JCSURERU4pXG5cdFx0XHR9XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFRXJyb3IuVW5rbm93biwgSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1IpXG5cdFx0fVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDb250cm9sbGVyLCBHZXQsIFBvc3QsIEJvZHksIFBhdGNoLCBQYXJhbSwgRGVsZXRlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDbGluaWNTZXJ2aWNlIH0gZnJvbSAnLi9jbGluaWMuc2VydmljZSdcbmltcG9ydCB7IENyZWF0ZUNsaW5pY0R0bywgVXBkYXRlQ2xpbmljRHRvIH0gZnJvbSAnLi9jbGluaWMuZHRvJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcblxuQEFwaVRhZ3MoJ0NsaW5pYycpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBDb250cm9sbGVyKCdjbGluaWMnKVxuZXhwb3J0IGNsYXNzIENsaW5pY0NvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGNsaW5pY1NlcnZpY2U6IENsaW5pY1NlcnZpY2UpIHsgfVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlQ2xpbmljRHRvOiBDcmVhdGVDbGluaWNEdG8pIHtcblx0XHRyZXR1cm4gJydcblx0fVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMuY2xpbmljU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBEZWxldGUoJzppZCcpXG5cdHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0VtYWlsLCBMZW5ndGggfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVDbGluaWNEdG8ge1xuXHRASXNFbWFpbCgpXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRATGVuZ3RoKDEwLCAxMClcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBMZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlQ2xpbmljRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlQ2xpbmljRHRvKSB7IH1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IHsgQ2xpbmljQ29udHJvbGxlciB9IGZyb20gJy4vY2xpbmljLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBDbGluaWNTZXJ2aWNlIH0gZnJvbSAnLi9jbGluaWMuc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW0NsaW5pY0VudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtDbGluaWNDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbQ2xpbmljU2VydmljZV0sXG5cdGV4cG9ydHM6IFtDbGluaWNTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQ2xpbmljTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCB7IERhdGFTb3VyY2UsIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2NsaW5pYy5lbnRpdHknXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDbGluaWNTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0QEluamVjdFJlcG9zaXRvcnkoQ2xpbmljRW50aXR5KSBwcml2YXRlIGNsaW5pY1JlcG9zaXRvcnk6IFJlcG9zaXRvcnk8Q2xpbmljRW50aXR5Pixcblx0XHRwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2Vcblx0KSB7IH1cblxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhbGwgY2xpbmljYFxuXHR9XG5cblx0ZmluZE9uZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxuXG5cdHVwZGF0ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiB1cGRhdGVzIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxuXG5cdHJlbW92ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZW1vdmVzIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxufVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgRGVsZXRlLCBHZXQsIFBhcmFtLCBQYXRjaCwgUG9zdCwgUmVxIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBVc2VJbnRlcmNlcHRvcnMgfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9kZWNvcmF0b3JzJ1xuaW1wb3J0IHsgQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IgfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9zZXJpYWxpemVyJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpUGFyYW0sIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8sIFVwZGF0ZUVtcGxveWVlRHRvIH0gZnJvbSAnLi9lbXBsb3llZS5kdG8nXG5pbXBvcnQgeyBFbXBsb3llZVNlcnZpY2UgfSBmcm9tICcuL2VtcGxveWVlLnNlcnZpY2UnXG5cbkBBcGlUYWdzKCdFbXBsb3llZScpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBVc2VJbnRlcmNlcHRvcnMoQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IpXG5AQ29udHJvbGxlcignZW1wbG95ZWUnKVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgZW1wbG95ZWVTZXJ2aWNlOiBFbXBsb3llZVNlcnZpY2UpIHsgfVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5maW5kQWxsKGNsaW5pY0lkKVxuXHR9XG5cblx0QFBvc3QoKVxuXHRjcmVhdGUoQEJvZHkoKSBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5jcmVhdGUoY2xpbmljSWQsIGNyZWF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5lbXBsb3llZVNlcnZpY2UuZmluZE9uZShjbGluaWNJZCwgK2lkKVxuXHR9XG5cblx0QFBhdGNoKCd1cGRhdGUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyB1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4sIEBCb2R5KCkgdXBkYXRlRW1wbG95ZWVEdG86IFVwZGF0ZUVtcGxveWVlRHRvKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLmVtcGxveWVlU2VydmljZS51cGRhdGUoY2xpbmljSWQsICtpZCwgdXBkYXRlRW1wbG95ZWVEdG8pXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBEZWxldGUoJ3JlbW92ZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5lbXBsb3llZVNlcnZpY2UucmVtb3ZlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBQYXRjaCgncmVzdG9yZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlc3RvcmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnJlc3RvcmUoY2xpbmljSWQsICtpZClcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcGlQcm9wZXJ0eSwgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0RlZmluZWQsIE1pbkxlbmd0aCB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcblxuZXhwb3J0IGNsYXNzIENyZWF0ZUVtcGxveWVlRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ25oYXRkdW9uZzIwMTknIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnTmfDtCBOaOG6rXQgRMawxqFuZycgfSlcblx0ZnVsbE5hbWU6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlRW1wbG95ZWVEdG8gZXh0ZW5kcyBQYXJ0aWFsVHlwZShDcmVhdGVFbXBsb3llZUR0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCBFbXBsb3llZUVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVtcGxveWVlQ29udHJvbGxlciB9IGZyb20gJy4vZW1wbG95ZWUuY29udHJvbGxlcidcbmltcG9ydCB7IEVtcGxveWVlU2VydmljZSB9IGZyb20gJy4vZW1wbG95ZWUuc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW0VtcGxveWVlRW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW0VtcGxveWVlQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0VtcGxveWVlU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSHR0cFN0YXR1cyB9IGZyb20gJ0BuZXN0anMvY29tbW9uL2VudW1zJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnMnXG5pbXBvcnQgeyBJbmplY3RSZXBvc2l0b3J5IH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0ICogYXMgYmNyeXB0IGZyb20gJ2JjcnlwdCdcbmltcG9ydCB7IHBsYWluVG9DbGFzcyB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgUmVwb3NpdG9yeSB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgRW1wbG95ZWVFbnRpdHksIHsgRUVtcGxveWVlUm9sZSB9IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgRUVtcGxveWVlRXJyb3IsIEVSZWdpc3RlckVycm9yIH0gZnJvbSAnLi4vLi4vZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0nXG5pbXBvcnQgeyBDcmVhdGVFbXBsb3llZUR0bywgVXBkYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2VtcGxveWVlLmR0bydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKEBJbmplY3RSZXBvc2l0b3J5KEVtcGxveWVlRW50aXR5KSBwcml2YXRlIGVtcGxveWVlUmVwb3NpdG9yeTogUmVwb3NpdG9yeTxFbXBsb3llZUVudGl0eT4pIHsgfVxuXG5cdGFzeW5jIGZpbmRBbGwoY2xpbmljSWQ6IG51bWJlcik6IFByb21pc2U8RW1wbG95ZWVFbnRpdHlbXT4ge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5maW5kKHsgd2hlcmU6IHsgY2xpbmljSWQgfSB9KVxuXHR9XG5cblx0YXN5bmMgY3JlYXRlKGNsaW5pY0lkOiBudW1iZXIsIGNyZWF0ZUVtcGxveWVlRHRvOiBDcmVhdGVFbXBsb3llZUR0byk6IFByb21pc2U8RW1wbG95ZWVFbnRpdHk+IHtcblx0XHRjb25zdCBmaW5kRW1wbG95ZWUgPSBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5maW5kT25lQnkoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHR1c2VybmFtZTogY3JlYXRlRW1wbG95ZWVEdG8udXNlcm5hbWUsXG5cdFx0fSlcblx0XHRpZiAoZmluZEVtcGxveWVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdFVzZXJuYW1lLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdH1cblx0XHRjb25zdCBzbmFwRW1wbG95ZWUgPSBwbGFpblRvQ2xhc3MoRW1wbG95ZWVFbnRpdHksIGNyZWF0ZUVtcGxveWVlRHRvKVxuXHRcdHNuYXBFbXBsb3llZS5wYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5oYXNoKGNyZWF0ZUVtcGxveWVlRHRvLnBhc3N3b3JkLCA1KVxuXHRcdHNuYXBFbXBsb3llZS5yb2xlID0gRUVtcGxveWVlUm9sZS5Vc2VyXG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LnNhdmUoY3JlYXRlRW1wbG95ZWVEdG8pXG5cdH1cblxuXHRhc3luYyBmaW5kT25lKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZE9uZUJ5KHsgY2xpbmljSWQsIGlkIH0pXG5cdH1cblxuXHRhc3luYyB1cGRhdGUoY2xpbmljSWQ6IG51bWJlciwgaWQ6IG51bWJlciwgdXBkYXRlRW1wbG95ZWVEdG86IFVwZGF0ZUVtcGxveWVlRHRvKSB7XG5cdFx0Y29uc3QgZmluZEVtcGxveWVlID0gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZE9uZUJ5KHsgY2xpbmljSWQsIGlkIH0pXG5cdFx0aWYgKCFmaW5kRW1wbG95ZWUpIHtcblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVFbXBsb3llZUVycm9yLk5vdEV4aXN0cywgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHR9XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LnVwZGF0ZSh7IGNsaW5pY0lkLCBpZCB9LCB1cGRhdGVFbXBsb3llZUR0bylcblx0fVxuXG5cdGFzeW5jIHJlbW92ZShjbGluaWNJZDogbnVtYmVyLCBlbXBsb3llZUlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuc29mdERlbGV0ZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkOiBlbXBsb3llZUlkLFxuXHRcdH0pXG5cdH1cblxuXHRhc3luYyByZXN0b3JlKGNsaW5pY0lkOiBudW1iZXIsIGVtcGxveWVlSWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5yZXN0b3JlKHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0aWQ6IGVtcGxveWVlSWQsXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQ29udHJvbGxlciwgR2V0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHtcblx0RGlza0hlYWx0aEluZGljYXRvciwgSGVhbHRoQ2hlY2ssIEhlYWx0aENoZWNrU2VydmljZSwgSHR0cEhlYWx0aEluZGljYXRvcixcblx0TWVtb3J5SGVhbHRoSW5kaWNhdG9yLCBUeXBlT3JtSGVhbHRoSW5kaWNhdG9yLFxufSBmcm9tICdAbmVzdGpzL3Rlcm1pbnVzJ1xuXG5AQXBpVGFncygnSGVhbHRoJylcbkBDb250cm9sbGVyKCdoZWFsdGgnKVxuZXhwb3J0IGNsYXNzIEhlYWx0aENvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihcblx0XHRwcml2YXRlIHJlYWRvbmx5IGhlYWx0aDogSGVhbHRoQ2hlY2tTZXJ2aWNlLFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgaHR0cDogSHR0cEhlYWx0aEluZGljYXRvcixcblx0XHRwcml2YXRlIHJlYWRvbmx5IGRiOiBUeXBlT3JtSGVhbHRoSW5kaWNhdG9yLFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgZGlzazogRGlza0hlYWx0aEluZGljYXRvcixcblx0XHRwcml2YXRlIHJlYWRvbmx5IG1lbW9yeTogTWVtb3J5SGVhbHRoSW5kaWNhdG9yXG5cdCkgeyB9XG5cblx0QEdldCgpXG5cdEBIZWFsdGhDaGVjaygpXG5cdGNoZWNrKCkge1xuXHRcdGNvbnN0IHBhdGhTdG9yYWdlID0gcHJvY2Vzcy5wbGF0Zm9ybSA9PT0gJ3dpbjMyJyA/ICdDOlxcXFwnIDogJy8nXG5cdFx0Y29uc3QgdGhyZXNob2xkUGVyY2VudCA9IHByb2Nlc3MucGxhdGZvcm0gPT09ICd3aW4zMicgPyAwLjkgOiAwLjVcblxuXHRcdHJldHVybiB0aGlzLmhlYWx0aC5jaGVjayhbXG5cdFx0XHQoKSA9PiB0aGlzLmh0dHAucGluZ0NoZWNrKCduZXN0anMtZG9jcycsICdodHRwczovL21lZGlob21lLnZuL2RvY3VtZW50JyksXG5cdFx0XHQoKSA9PiB0aGlzLmRiLnBpbmdDaGVjaygnZGF0YWJhc2UnKSxcblx0XHRcdCgpID0+IHRoaXMuZGlzay5jaGVja1N0b3JhZ2UoJ3N0b3JhZ2UnLCB7IHBhdGg6IHBhdGhTdG9yYWdlLCB0aHJlc2hvbGRQZXJjZW50IH0pLFxuXHRcdFx0KCkgPT4gdGhpcy5tZW1vcnkuY2hlY2tIZWFwKCdtZW1vcnlfaGVhcCcsIDE1MCAqIDEwMjQgKiAxMDI0KSxcblx0XHRcdCgpID0+IHRoaXMubWVtb3J5LmNoZWNrUlNTKCdtZW1vcnlfcnNzJywgMTUwICogMTAyNCAqIDEwMjQpLFxuXHRcdF0pXG5cdH1cbn1cbiIsImltcG9ydCB7IEh0dHBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2F4aW9zJ1xuaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUZXJtaW51c01vZHVsZSB9IGZyb20gJ0BuZXN0anMvdGVybWludXMnXG5pbXBvcnQgeyBIZWFsdGhDb250cm9sbGVyIH0gZnJvbSAnLi9oZWFsdGguY29udHJvbGxlcidcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUZXJtaW51c01vZHVsZSwgSHR0cE1vZHVsZV0sXG5cdGNvbnRyb2xsZXJzOiBbSGVhbHRoQ29udHJvbGxlcl0sXG59KVxuZXhwb3J0IGNsYXNzIEhlYWx0aE1vZHVsZSB7IH1cbiIsImV4cG9ydCBjbGFzcyBDcmVhdGVNZWRpY2luZUR0byB7fVxuIiwiaW1wb3J0IHsgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBDcmVhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vY3JlYXRlLW1lZGljaW5lLmR0bydcblxuZXhwb3J0IGNsYXNzIFVwZGF0ZU1lZGljaW5lRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlTWVkaWNpbmVEdG8pIHt9XG4iLCJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBEZWxldGUsIEdldCwgUGFyYW0sIFBhdGNoLCBQb3N0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlCZWFyZXJBdXRoLCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgTWVkaWNpbmVTZXJ2aWNlIH0gZnJvbSAnLi9tZWRpY2luZS5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnTWVkaWNpbmUnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignbWVkaWNpbmUnKVxuZXhwb3J0IGNsYXNzIE1lZGljaW5lQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgbWVkaWNpbmVTZXJ2aWNlOiBNZWRpY2luZVNlcnZpY2UpIHsgfVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlTWVkaWNpbmVEdG86IENyZWF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLmNyZWF0ZShjcmVhdGVNZWRpY2luZUR0bylcblx0fVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5maW5kQWxsKClcblx0fVxuXG5cdEBHZXQoJzppZCcpXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRAUGF0Y2goJzppZCcpXG5cdHVwZGF0ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQEJvZHkoKSB1cGRhdGVNZWRpY2luZUR0bzogVXBkYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UudXBkYXRlKCtpZCwgdXBkYXRlTWVkaWNpbmVEdG8pXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IE1lZGljaW5lRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvbWVkaWNpbmUuZW50aXR5J1xuaW1wb3J0IHsgTWVkaWNpbmVDb250cm9sbGVyIH0gZnJvbSAnLi9tZWRpY2luZS5jb250cm9sbGVyJ1xuaW1wb3J0IHsgTWVkaWNpbmVTZXJ2aWNlIH0gZnJvbSAnLi9tZWRpY2luZS5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1R5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbTWVkaWNpbmVFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbTWVkaWNpbmVDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbTWVkaWNpbmVTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgTWVkaWNpbmVNb2R1bGUgeyB9XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDcmVhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL2NyZWF0ZS1tZWRpY2luZS5kdG8nXG5pbXBvcnQgeyBVcGRhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL3VwZGF0ZS1tZWRpY2luZS5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBNZWRpY2luZVNlcnZpY2Uge1xuXHRjcmVhdGUoY3JlYXRlTWVkaWNpbmVEdG86IENyZWF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuICdUaGlzIGFjdGlvbiBhZGRzIGEgbmV3IG1lZGljaW5lJ1xuXHR9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIG1lZGljaW5lYFxuXHR9XG5cblx0ZmluZE9uZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGEgIyR7aWR9IG1lZGljaW5lYFxuXHR9XG5cblx0dXBkYXRlKGlkOiBudW1iZXIsIHVwZGF0ZU1lZGljaW5lRHRvOiBVcGRhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxuXG5cdHJlbW92ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZW1vdmVzIGEgIyR7aWR9IG1lZGljaW5lYFxuXHR9XG59XG4iLCJpbXBvcnQgeyBCb2R5LCBDbGFzc1NlcmlhbGl6ZXJJbnRlcmNlcHRvciwgQ29udHJvbGxlciwgRGVsZXRlLCBHZXQsIFBhcmFtLCBQYXRjaCwgUG9zdCwgUXVlcnksIFJlcSwgVXNlSW50ZXJjZXB0b3JzIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlCZWFyZXJBdXRoLCBBcGlQYXJhbSwgQXBpUXVlcnksIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgQ3JlYXRlUGF0aWVudER0bywgVXBkYXRlUGF0aWVudER0byB9IGZyb20gJy4vcGF0aWVudC5kdG8nXG5pbXBvcnQgeyBQYXRpZW50U2VydmljZSB9IGZyb20gJy4vcGF0aWVudC5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnUGF0aWVudCcpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBVc2VJbnRlcmNlcHRvcnMoQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IpXG5AQ29udHJvbGxlcigncGF0aWVudCcpXG5leHBvcnQgY2xhc3MgUGF0aWVudENvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IHBhdGllbnRTZXJ2aWNlOiBQYXRpZW50U2VydmljZSkgeyB9XG5cblx0QEdldCgpXG5cdGZpbmRBbGwoQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuZmluZEFsbChjbGluaWNJZClcblx0fVxuXG5cdEBHZXQoJ3NlYXJjaCcpXG5cdEBBcGlRdWVyeSh7IG5hbWU6ICdzZWFyY2hUZXh0JywgZXhhbXBsZTogJzA5ODYxMjM0NTYnIH0pXG5cdHNlYXJjaChAUXVlcnkoJ3NlYXJjaFRleHQnKSBzZWFyY2hUZXh0OiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGlmICgvXlxcZCskLy50ZXN0KHNlYXJjaFRleHQpKSB7XG5cdFx0XHRyZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS5maW5kQnlQaG9uZShjbGluaWNJZCwgc2VhcmNoVGV4dClcblx0XHR9XG5cdFx0cmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuZmluZEJ5RnVsbE5hbWUoY2xpbmljSWQsIHNlYXJjaFRleHQpXG5cdH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZVBhdGllbnREdG86IENyZWF0ZVBhdGllbnREdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmNyZWF0ZShjbGluaWNJZCwgY3JlYXRlUGF0aWVudER0bylcblx0fVxuXG5cdEBHZXQoJzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuZmluZE9uZShjbGluaWNJZCwgK2lkKVxuXHR9XG5cblx0QFBhdGNoKCd1cGRhdGUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyB1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlUGF0aWVudER0bzogVXBkYXRlUGF0aWVudER0bywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5wYXRpZW50U2VydmljZS51cGRhdGUoY2xpbmljSWQsICtpZCwgdXBkYXRlUGF0aWVudER0bylcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG5cblx0QERlbGV0ZSgncmVtb3ZlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgcmVtb3ZlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLnBhdGllbnRTZXJ2aWNlLnJlbW92ZShjbGluaWNJZCwgK2lkKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cblxuXHRAUGF0Y2goJ3Jlc3RvcmUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyByZXN0b3JlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLnBhdGllbnRTZXJ2aWNlLnJlc3RvcmUoY2xpbmljSWQsICtpZClcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcGlQcm9wZXJ0eU9wdGlvbmFsLCBQYXJ0aWFsVHlwZSB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IElzRGVmaW5lZCwgVmFsaWRhdGUgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5pbXBvcnQgeyBFR2VuZGVyIH0gZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9iYXNlLmVudGl0eSdcbmltcG9ydCB7IElzUGhvbmUgfSBmcm9tICcuLi8uLi9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbSdcblxuZXhwb3J0IGNsYXNzIENyZWF0ZVBhdGllbnREdG8ge1xuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICdQaOG6oW0gSG/DoG5nIE1haScgfSlcblx0QElzRGVmaW5lZCgpXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICcwOTg2MTIzNDU2JyB9KVxuXHRAVmFsaWRhdGUoSXNQaG9uZSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogRUdlbmRlci5GZW1hbGUgfSlcblx0Z2VuZGVyOiBFR2VuZGVyXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnVGjDoG5oIHBo4buRIEjDoCBO4buZaSAtLSBRdeG6rW4gTG9uZyBCacOqbiAtLSBQaMaw4budbmcgVGjhuqFjaCBCw6BuIC0tIHPhu5EgOCAtIHTDsmEgbmjDoCDEkOG6o28gQ+G6p3UgVuG7k25nJyB9KVxuXHRhZGRyZXNzOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICcxOTk4LTExLTI4VDAwOjAwOjAwLjAwMFonIH0pXG5cdGJpcnRoZGF5OiBEYXRlXG59XG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVQYXRpZW50RHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlUGF0aWVudER0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgUGF0aWVudEVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL3BhdGllbnQuZW50aXR5J1xuaW1wb3J0IHsgUGF0aWVudENvbnRyb2xsZXIgfSBmcm9tICcuL3BhdGllbnQuY29udHJvbGxlcidcbmltcG9ydCB7IFBhdGllbnRTZXJ2aWNlIH0gZnJvbSAnLi9wYXRpZW50LnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtQYXRpZW50RW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW1BhdGllbnRDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbUGF0aWVudFNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBQYXRpZW50TW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSHR0cFN0YXR1cywgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnMnXG5pbXBvcnQgeyBJbmplY3RSZXBvc2l0b3J5IH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IHsgRXF1YWwsIExpa2UsIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eSdcbmltcG9ydCB7IEVQYXRpZW50RXJyb3IgfSBmcm9tICcuLi8uLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcbmltcG9ydCB7IENyZWF0ZVBhdGllbnREdG8sIFVwZGF0ZVBhdGllbnREdG8gfSBmcm9tICcuL3BhdGllbnQuZHRvJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUGF0aWVudFNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShQYXRpZW50RW50aXR5KSBwcml2YXRlIHBhdGllbnRSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PFBhdGllbnRFbnRpdHk+KSB7IH1cblxuXHRhc3luYyBmaW5kQWxsKGNsaW5pY0lkOiBudW1iZXIpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHsgd2hlcmU6IHsgY2xpbmljSWQgfSB9KVxuXHRcdHJldHVybiBwYXRpZW50TGlzdFxuXHR9XG5cblx0YXN5bmMgY3JlYXRlKGNsaW5pY0lkOiBudW1iZXIsIGNyZWF0ZVBhdGllbnREdG86IENyZWF0ZVBhdGllbnREdG8pOiBQcm9taXNlPFBhdGllbnRFbnRpdHk+IHtcblx0XHRjb25zdCBwYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5zYXZlKHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0Li4uY3JlYXRlUGF0aWVudER0byxcblx0XHR9KVxuXHRcdHJldHVybiBwYXRpZW50XG5cdH1cblxuXHRhc3luYyBmaW5kT25lKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIpIHtcblx0XHRjb25zdCBwYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kT25lQnkoeyBjbGluaWNJZCwgaWQgfSlcblx0XHRyZXR1cm4gcGF0aWVudFxuXHR9XG5cblx0YXN5bmMgZmluZEJ5UGhvbmUoY2xpbmljSWQ6IG51bWJlciwgcGhvbmU6IHN0cmluZyk6IFByb21pc2U8UGF0aWVudEVudGl0eVtdPiB7XG5cdFx0Y29uc3QgcGF0aWVudExpc3QgPSBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LmZpbmQoe1xuXHRcdFx0d2hlcmU6IHtcblx0XHRcdFx0Y2xpbmljSWQ6IEVxdWFsKGNsaW5pY0lkKSxcblx0XHRcdFx0cGhvbmU6IExpa2UoYCR7cGhvbmV9JWApLFxuXHRcdFx0fSxcblx0XHRcdHNraXA6IDAsXG5cdFx0XHR0YWtlOiAxMCxcblx0XHR9KVxuXHRcdHJldHVybiBwYXRpZW50TGlzdFxuXHR9XG5cdGFzeW5jIGZpbmRCeUZ1bGxOYW1lKGNsaW5pY0lkOiBudW1iZXIsIGZ1bGxOYW1lOiBzdHJpbmcpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHtcblx0XHRcdHdoZXJlOiB7XG5cdFx0XHRcdGNsaW5pY0lkOiBFcXVhbChjbGluaWNJZCksXG5cdFx0XHRcdGZ1bGxOYW1lOiBMaWtlKGAke2Z1bGxOYW1lfSVgKSxcblx0XHRcdH0sXG5cdFx0XHRza2lwOiAwLFxuXHRcdFx0dGFrZTogMTAsXG5cdFx0fSlcblx0XHRyZXR1cm4gcGF0aWVudExpc3Rcblx0fVxuXG5cdGFzeW5jIHVwZGF0ZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyLCB1cGRhdGVQYXRpZW50RHRvOiBVcGRhdGVQYXRpZW50RHRvKSB7XG5cdFx0Y29uc3QgZmluZFBhdGllbnQgPSBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHRcdGlmICghZmluZFBhdGllbnQpIHtcblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVQYXRpZW50RXJyb3IuTm90RXhpc3RzLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdH1cblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS51cGRhdGUoeyBjbGluaWNJZCwgaWQgfSwgdXBkYXRlUGF0aWVudER0bylcblx0fVxuXG5cdGFzeW5jIHJlbW92ZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuc29mdERlbGV0ZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkLFxuXHRcdH0pXG5cdH1cblxuXHRhc3luYyByZXN0b3JlKGNsaW5pY0lkOiBudW1iZXIsIGVtcGxveWVlSWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LnJlc3RvcmUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDcmVhdGVEYXRlQ29sdW1uLCBEZWxldGVEYXRlQ29sdW1uLCBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLCBVcGRhdGVEYXRlQ29sdW1uIH0gZnJvbSAndHlwZW9ybSdcblxuZXhwb3J0IGVudW0gRUdlbmRlciB7XG5cdE1hbGUgPSAnTWFsZScsXG5cdEZlbWFsZSA9ICdGZW1hbGUnLFxufVxuXG5leHBvcnQgY2xhc3MgQmFzZUVudGl0eSB7XG5cdEBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uKHsgbmFtZTogJ2lkJyB9KVxuXHRpZDogbnVtYmVyXG5cblx0QENyZWF0ZURhdGVDb2x1bW4oeyBuYW1lOiAnY3JlYXRlZF9hdCcgfSlcblx0Y3JlYXRlZEF0OiBEYXRlXG5cblx0QFVwZGF0ZURhdGVDb2x1bW4oeyBuYW1lOiAndXBkYXRlZF9hdCcgfSlcblx0dXBkYXRlZEF0OiBEYXRlXG5cblx0QERlbGV0ZURhdGVDb2x1bW4oeyBuYW1lOiAnZGVsZXRlZF9hdCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRkZWxldGVkQXQ6IERhdGVcbn1cbiIsImltcG9ydCB7IENvbHVtbiwgRW50aXR5LCBJbmRleCB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5IH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ2NsaW5pYycpXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBDbGluaWNFbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgbGVuZ3RoOiAxMCwgbnVsbGFibGU6IGZhbHNlIH0pXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdW5pcXVlOiB0cnVlLCBudWxsYWJsZTogZmFsc2UgfSlcblx0ZW1haWw6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAndGlueWludCcsIGRlZmF1bHQ6IDEgfSlcblx0bGV2ZWw6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRuYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0YWRkcmVzczogc3RyaW5nXG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDb2x1bW4sIEVudGl0eSwgSW5kZXgsIEpvaW5Db2x1bW4sIE1hbnlUb09uZSB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5LCBFR2VuZGVyIH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4vY2xpbmljLmVudGl0eSdcblxuZXhwb3J0IGVudW0gRUVtcGxveWVlUm9sZSB7XG5cdE93bmVyID0gJ093bmVyJyxcblx0QWRtaW4gPSAnQWRtaW4nLFxuXHRVc2VyID0gJ1VzZXInLFxufVxuXG5leHBvcnQgdHlwZSBURW1wbG95ZWVSb2xlID0ga2V5b2YgdHlwZW9mIEVFbXBsb3llZVJvbGVcblxuQEVudGl0eSgnZW1wbG95ZWUnKVxuQEluZGV4KFsnY2xpbmljSWQnLCAndXNlcm5hbWUnXSwgeyB1bmlxdWU6IHRydWUgfSlcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIEVtcGxveWVlRW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyBuYW1lOiAnY2xpbmljX2lkJyB9KVxuXHRARXhjbHVkZSgpXG5cdGNsaW5pY0lkOiBudW1iZXJcblxuXHRATWFueVRvT25lKHR5cGUgPT4gQ2xpbmljRW50aXR5KVxuXHRASm9pbkNvbHVtbih7IG5hbWU6ICdjbGluaWNfaWQnLCByZWZlcmVuY2VkQ29sdW1uTmFtZTogJ2lkJyB9KVxuXHRjbGluaWM6IENsaW5pY0VudGl0eVxuXG5cdEBDb2x1bW4oeyBsZW5ndGg6IDEwLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QENvbHVtbigpXG5cdHVzZXJuYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKClcblx0QEV4Y2x1ZGUoKVxuXHRwYXNzd29yZDogc3RyaW5nXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUVtcGxveWVlUm9sZSwgZGVmYXVsdDogRUVtcGxveWVlUm9sZS5Vc2VyIH0pXG5cdHJvbGU6IEVFbXBsb3llZVJvbGVcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2Z1bGxfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ2RhdGUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRiaXJ0aGRheTogRGF0ZVxuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IEVHZW5kZXIsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGdlbmRlcjogRUdlbmRlclxufVxuIiwiaW1wb3J0IHsgRW50aXR5LCBDb2x1bW4sIEluZGV4IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHkgfSBmcm9tICcuLi9iYXNlLmVudGl0eSdcblxuQEVudGl0eSgnbWVkaWNpbmUnKVxuQEluZGV4KFsnY2xpbmljSWQnLCAnaWQnXSwgeyB1bmlxdWU6IHRydWUgfSlcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIE1lZGljaW5lRW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyBuYW1lOiAnY2xpbmljX2lkJyB9KVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QENvbHVtbih7IG5hbWU6ICdicmFuZF9uYW1lJywgbnVsbGFibGU6IHRydWUgfSlcblx0YnJhbmROYW1lOiBzdHJpbmcgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyB0w6puIGJp4buHdCBkxrDhu6NjXG5cblx0QENvbHVtbih7IG5hbWU6ICdjaGVtaWNhbF9uYW1lJywgbnVsbGFibGU6IHRydWUgfSlcblx0Y2hlbWljYWxOYW1lOiBzdHJpbmcgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyB0w6puIGfhu5FjXG5cblx0QENvbHVtbih7IG5hbWU6ICdjYWxjdWxhdGlvbl91bml0JywgbnVsbGFibGU6IHRydWUgfSlcblx0Y2FsY3VsYXRpb25Vbml0OiBzdHJpbmcgICAgICAgICAgICAgICAgICAgICAgICAvLyDEkcahbiB24buLIHTDrW5oOiBs4buNLCDhu5FuZywgduG7iVxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnaW1hZ2UnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRpbWFnZTogc3RyaW5nXG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDb2x1bW4sIEVudGl0eSwgSW5kZXggfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSwgRUdlbmRlciB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuXG5ARW50aXR5KCdwYXRpZW50JylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ2Z1bGxOYW1lJ10pXG5ASW5kZXgoWydjbGluaWNJZCcsICdwaG9uZSddKVxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgUGF0aWVudEVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QENvbHVtbih7IG5hbWU6ICdmdWxsX25hbWUnIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgbGVuZ3RoOiAxMCwgbnVsbGFibGU6IHRydWUgfSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZGF0ZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGJpcnRoZGF5OiBEYXRlXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUdlbmRlciwgbnVsbGFibGU6IHRydWUgfSlcblx0Z2VuZGVyOiBFR2VuZGVyXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGFkZHJlc3M6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnaGVhbHRoX2hpc3RvcnknLCB0eXBlOiAndGV4dCcsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGhlYWx0aEhpc3Rvcnk6IHN0cmluZyAvLyBUaeG7gW4gc+G7rSBi4buHbmhcbn1cbiIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvYXhpb3NcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9yc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vbi9lbnVtc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uL3NlcmlhbGl6ZXJcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvand0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvc3dhZ2dlclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3Rlcm1pbnVzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdHlwZW9ybVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJiY3J5cHRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdHJhbnNmb3JtZXJcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdmFsaWRhdG9yXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImV4cHJlc3NcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiZXhwcmVzcy1yYXRlLWxpbWl0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImhlbG1ldFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJyZXF1ZXN0LWlwXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInJ4anNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwicnhqcy9vcGVyYXRvcnNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwidHlwZW9ybVwiKTsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiaW1wb3J0IHsgVmFsaWRhdGlvbkVycm9yLCBWYWxpZGF0aW9uUGlwZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnU2VydmljZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgTmVzdEZhY3RvcnksIFJlZmxlY3RvciB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCByYXRlTGltaXQgZnJvbSAnZXhwcmVzcy1yYXRlLWxpbWl0J1xuaW1wb3J0IGhlbG1ldCBmcm9tICdoZWxtZXQnXG5pbXBvcnQgKiBhcyByZXF1ZXN0SXAgZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IEFwcE1vZHVsZSB9IGZyb20gJy4vYXBwLm1vZHVsZSdcbmltcG9ydCB7IHNldHVwU3dhZ2dlciB9IGZyb20gJy4vY29tbW9uL3N3YWdnZXInXG5pbXBvcnQgeyBIdHRwRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy9odHRwLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBVbmtub3duRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy91bmtub3duLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBWYWxpZGF0aW9uRXhjZXB0aW9uLCBWYWxpZGF0aW9uRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy92YWxpZGF0aW9uLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBVc2VyUm9sZXNHdWFyZCB9IGZyb20gJy4vZ3VhcmRzL3VzZXItcm9sZXMuZ3VhcmQnXG5pbXBvcnQgeyBBY2Nlc3NMb2dJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvYWNjZXNzLWxvZy5pbnRlcmNlcHRvcidcbmltcG9ydCB7IFRpbWVvdXRJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvdGltZW91dC5pbnRlcmNlcHRvcidcblxuYXN5bmMgZnVuY3Rpb24gYm9vdHN0cmFwKCkge1xuXHRjb25zdCBhcHAgPSBhd2FpdCBOZXN0RmFjdG9yeS5jcmVhdGUoQXBwTW9kdWxlKVxuXHRcblx0Y29uc3QgY29uZmlnU2VydmljZSA9IGFwcC5nZXQoQ29uZmlnU2VydmljZSlcblx0Y29uc3QgUE9SVCA9IGNvbmZpZ1NlcnZpY2UuZ2V0KCdORVNUSlNfUE9SVCcpXG5cdGNvbnN0IEhPU1QgPSBjb25maWdTZXJ2aWNlLmdldCgnTkVTVEpTX0hPU1QnKSB8fCAnbG9jYWxob3N0J1xuXG5cdGFwcC51c2UoaGVsbWV0KCkpXG5cdGFwcC51c2UocmF0ZUxpbWl0KHtcblx0XHR3aW5kb3dNczogNjAgKiAxMDAwLCAvLyAxIG1pbnV0ZXNcblx0XHRtYXg6IDEwMCwgLy8gbGltaXQgZWFjaCBJUCB0byAxMDAgcmVxdWVzdHMgcGVyIHdpbmRvd01zXG5cdH0pKVxuXHRhcHAuZW5hYmxlQ29ycygpXG5cblx0YXBwLnVzZShyZXF1ZXN0SXAubXcoKSlcblxuXHRhcHAudXNlR2xvYmFsSW50ZXJjZXB0b3JzKFxuXHRcdG5ldyBBY2Nlc3NMb2dJbnRlcmNlcHRvcigpLFxuXHRcdG5ldyBUaW1lb3V0SW50ZXJjZXB0b3IoKVxuXHQpXG5cdGFwcC51c2VHbG9iYWxGaWx0ZXJzKFxuXHRcdG5ldyBVbmtub3duRXhjZXB0aW9uRmlsdGVyKCksXG5cdFx0bmV3IEh0dHBFeGNlcHRpb25GaWx0ZXIoKSxcblx0XHRuZXcgVmFsaWRhdGlvbkV4Y2VwdGlvbkZpbHRlcigpXG5cdClcblxuXHRhcHAudXNlR2xvYmFsR3VhcmRzKG5ldyBVc2VyUm9sZXNHdWFyZChhcHAuZ2V0KFJlZmxlY3RvcikpKVxuXG5cdGFwcC51c2VHbG9iYWxQaXBlcyhuZXcgVmFsaWRhdGlvblBpcGUoe1xuXHRcdHZhbGlkYXRpb25FcnJvcjogeyB0YXJnZXQ6IGZhbHNlLCB2YWx1ZTogdHJ1ZSB9LFxuXHRcdHNraXBNaXNzaW5nUHJvcGVydGllczogdHJ1ZSxcblx0XHRleGNlcHRpb25GYWN0b3J5OiAoZXJyb3JzOiBWYWxpZGF0aW9uRXJyb3JbXSA9IFtdKSA9PiBuZXcgVmFsaWRhdGlvbkV4Y2VwdGlvbihlcnJvcnMpLFxuXHR9KSlcblxuXHRpZiAoY29uZmlnU2VydmljZS5nZXQoJ05PREVfRU5WJykgIT09ICdwcm9kdWN0aW9uJykge1xuXHRcdHNldHVwU3dhZ2dlcihhcHApXG5cdH1cblxuXHRhd2FpdCBhcHAubGlzdGVuKFBPUlQsICgpID0+IHtcblx0XHRjb25zb2xlLmxvZyhg8J+agCBTZXJ2ZXIgZG9jdW1lbnQ6IGh0dHA6Ly8ke0hPU1R9OiR7UE9SVH0vZG9jdW1lbnRgKVxuXHR9KVxufVxuYm9vdHN0cmFwKClcbiJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==