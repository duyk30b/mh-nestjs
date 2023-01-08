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
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const environments_1 = __webpack_require__(/*! ./environments */ "./apps/api/src/environments.ts");
const logger_middleware_1 = __webpack_require__(/*! ./middleware/logger.middleware */ "./apps/api/src/middleware/logger.middleware.ts");
const validate_access_token_middleware_1 = __webpack_require__(/*! ./middleware/validate-access-token.middleware */ "./apps/api/src/middleware/validate-access-token.middleware.ts");
const admission_module_1 = __webpack_require__(/*! ./modules/admission/admission.module */ "./apps/api/src/modules/admission/admission.module.ts");
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
            admission_module_1.AdmissionModule,
            employee_module_1.EmployeeModule,
            patient_module_1.PatientModule,
            clinic_module_1.ClinicModule,
            medicine_module_1.MedicineModule,
        ],
        providers: [
            {
                provide: core_1.APP_INTERCEPTOR,
                useClass: common_1.ClassSerializerInterceptor,
            },
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
        if (typeof text !== 'string' || text.length !== 10)
            return false;
        return /((09|03|07|08|05)+([0-9]{8})\b)/g.test(text);
    }
    defaultMessage(args) {
        return '$property must be real phone number !';
    }
};
IsPhone = __decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'isPhone', async: false })
], IsPhone);
exports.IsPhone = IsPhone;
let IsGmail = class IsGmail {
    validate(text, args) {
        if (typeof text !== 'string')
            return false;
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

/***/ "./apps/api/src/middleware/logger.middleware.ts":
/*!******************************************************!*\
  !*** ./apps/api/src/middleware/logger.middleware.ts ***!
  \******************************************************/
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

/***/ "./apps/api/src/middleware/validate-access-token.middleware.ts":
/*!*********************************************************************!*\
  !*** ./apps/api/src/middleware/validate-access-token.middleware.ts ***!
  \*********************************************************************/
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
const request_ip_1 = __webpack_require__(/*! request-ip */ "request-ip");
const jwt_extend_service_1 = __webpack_require__(/*! ../modules/auth/jwt-extend.service */ "./apps/api/src/modules/auth/jwt-extend.service.ts");
let ValidateAccessTokenMiddleware = class ValidateAccessTokenMiddleware {
    constructor(jwtExtendService) {
        this.jwtExtendService = jwtExtendService;
    }
    async use(req, res, next) {
        const ip = (0, request_ip_1.getClientIp)(req);
        const authorization = req.header('Authorization') || '';
        const [, accessToken] = authorization.split(' ');
        const decode = this.jwtExtendService.verifyAccessToken(accessToken, ip);
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

/***/ "./apps/api/src/modules/admission/admission.controller.ts":
/*!****************************************************************!*\
  !*** ./apps/api/src/modules/admission/admission.controller.ts ***!
  \****************************************************************/
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
exports.AdmissionController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const constants_1 = __webpack_require__(/*! ../../common/constants */ "./apps/api/src/common/constants.ts");
const admission_dto_1 = __webpack_require__(/*! ./admission.dto */ "./apps/api/src/modules/admission/admission.dto.ts");
const admission_service_1 = __webpack_require__(/*! ./admission.service */ "./apps/api/src/modules/admission/admission.service.ts");
let AdmissionController = class AdmissionController {
    constructor(admissionService) {
        this.admissionService = admissionService;
    }
    findAll() {
        return this.admissionService.findAll();
    }
    findOne(id) {
        return this.admissionService.findOne(+id);
    }
    create(createAdmissionDto, request) {
        const clinicId = request.tokenPayload.cid;
        return this.admissionService.create(clinicId, createAdmissionDto);
    }
    update(id, updateAdmissionDto) {
        return this.admissionService.update(+id, updateAdmissionDto);
    }
    remove(id) {
        return this.admissionService.remove(+id);
    }
};
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], AdmissionController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], AdmissionController.prototype, "findOne", null);
__decorate([
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof admission_dto_1.CreateAdmissionDto !== "undefined" && admission_dto_1.CreateAdmissionDto) === "function" ? _b : Object, typeof (_c = typeof constants_1.RequestToken !== "undefined" && constants_1.RequestToken) === "function" ? _c : Object]),
    __metadata("design:returntype", void 0)
], AdmissionController.prototype, "create", null);
__decorate([
    (0, common_1.Patch)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_d = typeof admission_dto_1.UpdateAdmissionDto !== "undefined" && admission_dto_1.UpdateAdmissionDto) === "function" ? _d : Object]),
    __metadata("design:returntype", void 0)
], AdmissionController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], AdmissionController.prototype, "remove", null);
AdmissionController = __decorate([
    (0, swagger_1.ApiTags)('Admission'),
    (0, common_1.SerializeOptions)({ excludeExtraneousValues: true, exposeUnsetFields: false }),
    (0, swagger_1.ApiBearerAuth)('access-token'),
    (0, common_1.Controller)('admission'),
    __metadata("design:paramtypes", [typeof (_a = typeof admission_service_1.AdmissionService !== "undefined" && admission_service_1.AdmissionService) === "function" ? _a : Object])
], AdmissionController);
exports.AdmissionController = AdmissionController;


/***/ }),

/***/ "./apps/api/src/modules/admission/admission.dto.ts":
/*!*********************************************************!*\
  !*** ./apps/api/src/modules/admission/admission.dto.ts ***!
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
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateAdmissionDto = exports.CreateAdmissionDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const base_entity_1 = __webpack_require__(/*! ../../../../../typeorm/base.entity */ "./typeorm/base.entity.ts");
const patient_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/patient.entity */ "./typeorm/entities/patient.entity.ts");
class PatientDto {
}
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ name: 'patient_id', example: '' }),
    (0, class_transformer_1.Expose)({ name: 'patient_id' }),
    (0, class_transformer_1.Type)(() => Number),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], PatientDto.prototype, "patientId", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ name: 'full_name', example: 'Nguyễn Thị Ánh' }),
    (0, class_transformer_1.Expose)({ name: 'full_name' }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], PatientDto.prototype, "fullName", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: '0987445223' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], PatientDto.prototype, "phone", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: '1927-04-28T00:00:00.000Z' }),
    (0, class_transformer_1.Expose)(),
    (0, class_transformer_1.Type)(() => Date),
    (0, class_validator_1.IsDate)(),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], PatientDto.prototype, "birthday", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ enum: base_entity_1.EGender, example: base_entity_1.EGender.Female }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsEnum)(base_entity_1.EGender),
    __metadata("design:type", typeof (_b = typeof base_entity_1.EGender !== "undefined" && base_entity_1.EGender) === "function" ? _b : Object)
], PatientDto.prototype, "gender", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: 'Tỉnh Hà Tĩnh -- Huyện Đức Thọ -- Xã Lâm Trung Thủy -- Thôn Phan Thắng' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], PatientDto.prototype, "address", void 0);
class CreateAdmissionDto {
}
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ type: PatientDto }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.ValidateNested)({ each: true }),
    (0, class_transformer_1.Type)(() => PatientDto),
    __metadata("design:type", typeof (_c = typeof patient_entity_1.default !== "undefined" && patient_entity_1.default) === "function" ? _c : Object)
], CreateAdmissionDto.prototype, "patient", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: 'Sốt cao ngày thứ 3' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreateAdmissionDto.prototype, "reason", void 0);
exports.CreateAdmissionDto = CreateAdmissionDto;
class UpdateAdmissionDto extends (0, swagger_1.PartialType)(CreateAdmissionDto) {
}
exports.UpdateAdmissionDto = UpdateAdmissionDto;


/***/ }),

/***/ "./apps/api/src/modules/admission/admission.module.ts":
/*!************************************************************!*\
  !*** ./apps/api/src/modules/admission/admission.module.ts ***!
  \************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AdmissionModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const admission_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/admission.entity */ "./typeorm/entities/admission.entity.ts");
const admission_controller_1 = __webpack_require__(/*! ./admission.controller */ "./apps/api/src/modules/admission/admission.controller.ts");
const admission_service_1 = __webpack_require__(/*! ./admission.service */ "./apps/api/src/modules/admission/admission.service.ts");
let AdmissionModule = class AdmissionModule {
};
AdmissionModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([admission_entity_1.default])],
        controllers: [admission_controller_1.AdmissionController],
        providers: [admission_service_1.AdmissionService],
    })
], AdmissionModule);
exports.AdmissionModule = AdmissionModule;


/***/ }),

/***/ "./apps/api/src/modules/admission/admission.service.ts":
/*!*************************************************************!*\
  !*** ./apps/api/src/modules/admission/admission.service.ts ***!
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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AdmissionService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const admission_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/admission.entity */ "./typeorm/entities/admission.entity.ts");
let AdmissionService = class AdmissionService {
    constructor(admissionRepository) {
        this.admissionRepository = admissionRepository;
    }
    findAll() {
        return `This action returns all admission`;
    }
    findOne(id) {
        return `This action returns a #${id} admission`;
    }
    create(clinicId, createAdmissionDto) {
        return 'This action adds a new admission';
    }
    update(id, updateAdmissionDto) {
        return `This action updates a #${id} admission`;
    }
    remove(id) {
        return `This action removes a #${id} admission`;
    }
};
AdmissionService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(admission_entity_1.default)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object])
], AdmissionService);
exports.AdmissionService = AdmissionService;


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
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m;
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
        const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee, ip);
        return new auth_dto_1.TokensResponse({ accessToken, refreshToken });
    }
    async login(loginDto, request) {
        console.log('🚀 ~ file: auth.controller.ts:33 ~ AuthController ~ login ~ loginDto', loginDto);
        const ip = (0, request_ip_1.getClientIp)(request);
        const employee = await this.authService.login(loginDto);
        const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee, ip);
        return new auth_dto_1.TokensResponse({ accessToken, refreshToken });
    }
    logout(id) {
    }
    changePassword(id, updateAuthDto) {
    }
    forgotPassword(id) {
    }
    async grantAccessToken(refreshTokenDto, request) {
        const ip = (0, request_ip_1.getClientIp)(request);
        const accessToken = await this.authService.grantAccessToken(refreshTokenDto.refreshToken, ip);
        return new auth_dto_1.TokensResponse({ accessToken });
    }
};
__decorate([
    (0, common_1.Post)('register'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof auth_dto_1.RegisterDto !== "undefined" && auth_dto_1.RegisterDto) === "function" ? _c : Object, typeof (_d = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _d : Object]),
    __metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_f = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _f : Object, typeof (_g = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _g : Object]),
    __metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
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
    __metadata("design:paramtypes", [String, typeof (_j = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _j : Object]),
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
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_k = typeof auth_dto_1.RefreshTokenDto !== "undefined" && auth_dto_1.RefreshTokenDto) === "function" ? _k : Object, typeof (_l = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _l : Object]),
    __metadata("design:returntype", typeof (_m = typeof Promise !== "undefined" && Promise) === "function" ? _m : Object)
], AuthController.prototype, "grantAccessToken", null);
AuthController = __decorate([
    (0, swagger_1.ApiTags)('Auth'),
    (0, common_1.SerializeOptions)({ excludeExtraneousValues: true, exposeUnsetFields: false }),
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
exports.TokensResponse = exports.RefreshTokenDto = exports.LoginDto = exports.RegisterDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const class_validator_custom_1 = __webpack_require__(/*! ../../common/class-validator.custom */ "./apps/api/src/common/class-validator.custom.ts");
class RegisterDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'example-2@gmail.com' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsGmail),
    __metadata("design:type", String)
], RegisterDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: '0376899866' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsPhone),
    __metadata("design:type", String)
], RegisterDto.prototype, "phone", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'admin' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], RegisterDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], RegisterDto.prototype, "password", void 0);
exports.RegisterDto = RegisterDto;
class LoginDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ name: 'c_phone', example: '0986021190' }),
    (0, class_transformer_1.Expose)({ name: 'c_phone' }),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Validate)(class_validator_custom_1.IsPhone),
    __metadata("design:type", String)
], LoginDto.prototype, "cPhone", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'admin' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginDto.prototype, "username", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({ example: 'Abc@123456' }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], LoginDto.prototype, "password", void 0);
exports.LoginDto = LoginDto;
class RefreshTokenDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ name: 'refresh_token' }),
    (0, class_transformer_1.Expose)({ name: 'refresh_token' }),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], RefreshTokenDto.prototype, "refreshToken", void 0);
exports.RefreshTokenDto = RefreshTokenDto;
class TokensResponse {
    constructor(partial) {
        Object.assign(this, partial);
    }
}
__decorate([
    (0, class_transformer_1.Expose)({ name: 'access_token' }),
    __metadata("design:type", String)
], TokensResponse.prototype, "accessToken", void 0);
__decorate([
    (0, class_transformer_1.Expose)({ name: 'refresh_token' }),
    __metadata("design:type", String)
], TokensResponse.prototype, "refreshToken", void 0);
exports.TokensResponse = TokensResponse;


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
    async grantAccessToken(refreshToken, ip) {
        const { uid } = this.jwtExtendService.verifyRefreshToken(refreshToken, ip);
        const employee = await this.dataSource.getRepository(employee_entity_1.default).findOne({
            relations: { clinic: true },
            where: { id: uid },
        });
        const accessToken = this.jwtExtendService.createAccessToken(employee, ip);
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
    createAccessToken(user, ip) {
        const userPayload = {
            ip,
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
    createRefreshToken(uid, ip) {
        return this.jwtService.sign({ uid, ip }, {
            secret: this.jwtConfig.refreshKey,
            expiresIn: this.jwtConfig.refreshTime,
        });
    }
    createTokenFromUser(user, ip) {
        const accessToken = this.createAccessToken(user, ip);
        const refreshToken = this.createRefreshToken(user.id, ip);
        return { accessToken, refreshToken };
    }
    verifyAccessToken(accessToken, ip) {
        try {
            const jwtPayload = this.jwtService.verify(accessToken, { secret: this.jwtConfig.accessKey });
            if (jwtPayload.ip !== ip) {
                throw new common_1.HttpException(exception_enum_1.ETokenError.Invalid, common_1.HttpStatus.UNAUTHORIZED);
            }
            return jwtPayload;
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
    verifyRefreshToken(refreshToken, ip) {
        try {
            const jwtPayload = this.jwtService.verify(refreshToken, { secret: this.jwtConfig.refreshKey });
            if (jwtPayload.ip !== ip) {
                throw new common_1.HttpException(exception_enum_1.ETokenError.Invalid, common_1.HttpStatus.UNAUTHORIZED);
            }
            return jwtPayload;
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
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
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
    (0, class_validator_1.IsEnum)(base_entity_1.EGender),
    __metadata("design:type", typeof (_a = typeof base_entity_1.EGender !== "undefined" && base_entity_1.EGender) === "function" ? _a : Object)
], CreatePatientDto.prototype, "gender", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: 'Thành phố Hà Nội -- Quận Long Biên -- Phường Thạch Bàn -- số 8 - tòa nhà Đảo Cầu Vồng' }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], CreatePatientDto.prototype, "address", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: '1998-11-28T00:00:00.000Z' }),
    (0, class_transformer_1.Type)(() => Date),
    (0, class_validator_1.IsDate)(),
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

/***/ "./typeorm/entities/admission.entity.ts":
/*!**********************************************!*\
  !*** ./typeorm/entities/admission.entity.ts ***!
  \**********************************************/
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
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../base.entity */ "./typeorm/base.entity.ts");
let AdmissionEntity = class AdmissionEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ name: 'clinic_id' }),
    (0, class_transformer_1.Exclude)(),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "clinicId", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'patient_id' }),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "patientId", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'reason', nullable: true }),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "reason", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'medical_record', type: 'text' }),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "medicalRecord", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "diagnosis", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'tinyint', unsigned: true, nullable: true }),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "pulse", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'float', precision: 3, scale: 1, nullable: true }),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "temperature", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'blood_pressure', length: 10, nullable: true }),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "bloodPressure", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'respiratory_rate', type: 'tinyint', nullable: true }),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "respiratoryRate", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'tinyint', nullable: true }),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "spO2", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "note", void 0);
AdmissionEntity = __decorate([
    (0, typeorm_1.Entity)('admission')
], AdmissionEntity);
exports["default"] = AdmissionEntity;


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
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        transformOptions: {
            exposeUnsetFields: false,
        },
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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cC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2NvbW1vbi9jbGFzcy12YWxpZGF0b3IuY3VzdG9tLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9jb21tb24vc3dhZ2dlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZW52aXJvbm1lbnRzLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvaHR0cC1leGNlcHRpb24uZmlsdGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy91bmtub3duLWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2V4Y2VwdGlvbi1maWx0ZXJzL3ZhbGlkYXRpb24tZXhjZXB0aW9uLmZpbHRlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZ3VhcmRzL3VzZXItcm9sZXMuZ3VhcmQudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2ludGVyY2VwdG9yL2FjY2Vzcy1sb2cuaW50ZXJjZXB0b3IudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2ludGVyY2VwdG9yL3RpbWVvdXQuaW50ZXJjZXB0b3IudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21pZGRsZXdhcmUvbG9nZ2VyLm1pZGRsZXdhcmUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21pZGRsZXdhcmUvdmFsaWRhdGUtYWNjZXNzLXRva2VuLm1pZGRsZXdhcmUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYWRtaXNzaW9uL2FkbWlzc2lvbi5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2FkbWlzc2lvbi9hZG1pc3Npb24uZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2FkbWlzc2lvbi9hZG1pc3Npb24ubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2FkbWlzc2lvbi9hZG1pc3Npb24uc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGguY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGguZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvY2xpbmljL2NsaW5pYy5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9oZWFsdGgvaGVhbHRoLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvaGVhbHRoL2hlYWx0aC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvbWVkaWNpbmUvZHRvL2NyZWF0ZS1tZWRpY2luZS5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvbWVkaWNpbmUvZHRvL3VwZGF0ZS1tZWRpY2luZS5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9tZWRpY2luZS5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L3BhdGllbnQuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L3BhdGllbnQuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL3BhdGllbnQvcGF0aWVudC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9iYXNlLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2VudGl0aWVzL2FkbWlzc2lvbi5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvbWVkaWNpbmUuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvcGF0aWVudC5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9heGlvc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9yc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL2VudW1zXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb24vZXhjZXB0aW9uc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL3NlcmlhbGl6ZXJcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbmZpZ1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29yZVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvand0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9zd2FnZ2VyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy90ZXJtaW51c1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvdHlwZW9ybVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImJjcnlwdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImNsYXNzLXRyYW5zZm9ybWVyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiY2xhc3MtdmFsaWRhdG9yXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiZXhwcmVzc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImV4cHJlc3MtcmF0ZS1saW1pdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImhlbG1ldFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInJlcXVlc3QtaXBcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJyeGpzXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwicnhqcy9vcGVyYXRvcnNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJ0eXBlb3JtXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tYWluLnRzIl0sInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yLCBNaWRkbGV3YXJlQ29uc3VtZXIsIE1vZHVsZSwgTmVzdE1vZHVsZSwgUmVxdWVzdE1ldGhvZCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlLCBDb25maWdUeXBlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnXG5pbXBvcnQgeyBBUFBfSU5URVJDRVBUT1IgfSBmcm9tICdAbmVzdGpzL2NvcmUnXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IHsgRGF0YVNvdXJjZSB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBNYXJpYWRiQ29uZmlnIH0gZnJvbSAnLi9lbnZpcm9ubWVudHMnXG5pbXBvcnQgeyBMb2dnZXJNaWRkbGV3YXJlIH0gZnJvbSAnLi9taWRkbGV3YXJlL2xvZ2dlci5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgVmFsaWRhdGVBY2Nlc3NUb2tlbk1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmUvdmFsaWRhdGUtYWNjZXNzLXRva2VuLm1pZGRsZXdhcmUnXG5pbXBvcnQgeyBBZG1pc3Npb25Nb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvYWRtaXNzaW9uL2FkbWlzc2lvbi5tb2R1bGUnXG5pbXBvcnQgeyBBdXRoTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2F1dGgvYXV0aC5tb2R1bGUnXG5pbXBvcnQgeyBDbGluaWNNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvY2xpbmljL2NsaW5pYy5tb2R1bGUnXG5pbXBvcnQgeyBFbXBsb3llZU1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5tb2R1bGUnXG5pbXBvcnQgeyBIZWFsdGhNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvaGVhbHRoL2hlYWx0aC5tb2R1bGUnXG5pbXBvcnQgeyBNZWRpY2luZU1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9tZWRpY2luZS9tZWRpY2luZS5tb2R1bGUnXG5pbXBvcnQgeyBQYXRpZW50TW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL3BhdGllbnQvcGF0aWVudC5tb2R1bGUnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbXG5cdFx0Q29uZmlnTW9kdWxlLmZvclJvb3Qoe1xuXHRcdFx0ZW52RmlsZVBhdGg6IFtgLmVudi4ke3Byb2Nlc3MuZW52Lk5PREVfRU5WIHx8ICdsb2NhbCd9YCwgJy5lbnYnXSxcblx0XHRcdGlzR2xvYmFsOiB0cnVlLFxuXHRcdH0pLFxuXHRcdFR5cGVPcm1Nb2R1bGUuZm9yUm9vdEFzeW5jKHtcblx0XHRcdGltcG9ydHM6IFtDb25maWdNb2R1bGUuZm9yRmVhdHVyZShNYXJpYWRiQ29uZmlnKV0sXG5cdFx0XHRpbmplY3Q6IFtNYXJpYWRiQ29uZmlnLktFWV0sXG5cdFx0XHR1c2VGYWN0b3J5OiAobWFyaWFkYkNvbmZpZzogQ29uZmlnVHlwZTx0eXBlb2YgTWFyaWFkYkNvbmZpZz4pID0+IG1hcmlhZGJDb25maWcsXG5cdFx0XHQvLyBpbmplY3Q6IFtDb25maWdTZXJ2aWNlXSxcblx0XHRcdC8vIHVzZUZhY3Rvcnk6IChjb25maWdTZXJ2aWNlOiBDb25maWdTZXJ2aWNlKSA9PiBjb25maWdTZXJ2aWNlLmdldCgnbXlzcWwnKSxcblx0XHR9KSxcblx0XHRIZWFsdGhNb2R1bGUsXG5cdFx0QXV0aE1vZHVsZSxcblx0XHRBZG1pc3Npb25Nb2R1bGUsXG5cdFx0RW1wbG95ZWVNb2R1bGUsXG5cdFx0UGF0aWVudE1vZHVsZSxcblx0XHRDbGluaWNNb2R1bGUsXG5cdFx0TWVkaWNpbmVNb2R1bGUsXG5cdF0sXG5cdHByb3ZpZGVyczogW1xuXHRcdHtcblx0XHRcdHByb3ZpZGU6IEFQUF9JTlRFUkNFUFRPUixcblx0XHRcdHVzZUNsYXNzOiBDbGFzc1NlcmlhbGl6ZXJJbnRlcmNlcHRvcixcblx0XHR9LFxuXHRdLFxufSlcbmV4cG9ydCBjbGFzcyBBcHBNb2R1bGUgaW1wbGVtZW50cyBOZXN0TW9kdWxlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlKSB7IH1cblx0Y29uZmlndXJlKGNvbnN1bWVyOiBNaWRkbGV3YXJlQ29uc3VtZXIpIHtcblx0XHRjb25zdW1lci5hcHBseShMb2dnZXJNaWRkbGV3YXJlKS5mb3JSb3V0ZXMoJyonKVxuXG5cdFx0Y29uc3VtZXIuYXBwbHkoVmFsaWRhdGVBY2Nlc3NUb2tlbk1pZGRsZXdhcmUpXG5cdFx0XHQuZXhjbHVkZShcblx0XHRcdFx0J2F1dGgvKC4qKScsXG5cdFx0XHRcdCcvJyxcblx0XHRcdFx0eyBwYXRoOiAnaGVhbHRoJywgbWV0aG9kOiBSZXF1ZXN0TWV0aG9kLkdFVCB9XG5cdFx0XHQpXG5cdFx0XHQuZm9yUm91dGVzKCcqJylcblx0fVxufVxuIiwiaW1wb3J0IHsgVmFsaWRhdG9yQ29uc3RyYWludCwgVmFsaWRhdG9yQ29uc3RyYWludEludGVyZmFjZSwgVmFsaWRhdGlvbkFyZ3VtZW50cyB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcblxuQFZhbGlkYXRvckNvbnN0cmFpbnQoeyBuYW1lOiAnaXNQaG9uZScsIGFzeW5jOiBmYWxzZSB9KVxuZXhwb3J0IGNsYXNzIElzUGhvbmUgaW1wbGVtZW50cyBWYWxpZGF0b3JDb25zdHJhaW50SW50ZXJmYWNlIHtcblx0dmFsaWRhdGUodGV4dDogc3RyaW5nLCBhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0aWYgKHR5cGVvZiB0ZXh0ICE9PSAnc3RyaW5nJyB8fCB0ZXh0Lmxlbmd0aCAhPT0gMTApIHJldHVybiBmYWxzZVxuXHRcdHJldHVybiAvKCgwOXwwM3wwN3wwOHwwNSkrKFswLTldezh9KVxcYikvZy50ZXN0KHRleHQpXG5cdH1cblxuXHRkZWZhdWx0TWVzc2FnZShhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0cmV0dXJuICckcHJvcGVydHkgbXVzdCBiZSByZWFsIHBob25lIG51bWJlciAhJ1xuXHR9XG59XG5cbkBWYWxpZGF0b3JDb25zdHJhaW50KHsgbmFtZTogJ2lzR21haWwnLCBhc3luYzogZmFsc2UgfSlcbmV4cG9ydCBjbGFzcyBJc0dtYWlsIGltcGxlbWVudHMgVmFsaWRhdG9yQ29uc3RyYWludEludGVyZmFjZSB7XG5cdHZhbGlkYXRlKHRleHQ6IHN0cmluZywgYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdGlmICh0eXBlb2YgdGV4dCAhPT0gJ3N0cmluZycpIHJldHVybiBmYWxzZVxuXHRcdHJldHVybiAvXihbYS16QS1aMC05XXxcXC58LXxfKSsoQGdtYWlsLmNvbSkkLy50ZXN0KHRleHQpXG5cdH1cblxuXHRkZWZhdWx0TWVzc2FnZShhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0cmV0dXJuICckcHJvcGVydHkgbXVzdCBiZSBhIGdtYWlsIGFkZHJlc3MgISdcblx0fVxufVxuIiwiaW1wb3J0IHsgSU5lc3RBcHBsaWNhdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgU3dhZ2dlck1vZHVsZSwgRG9jdW1lbnRCdWlsZGVyIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuXG5leHBvcnQgY29uc3Qgc2V0dXBTd2FnZ2VyID0gKGFwcDogSU5lc3RBcHBsaWNhdGlvbikgPT4ge1xuXHRjb25zdCBjb25maWcgPSBuZXcgRG9jdW1lbnRCdWlsZGVyKClcblx0XHQuc2V0VGl0bGUoJ1NpbXBsZSBBUEknKVxuXHRcdC5zZXREZXNjcmlwdGlvbignTWVkaWhvbWUgQVBJIHVzZSBTd2FnZ2VyJylcblx0XHQuc2V0VmVyc2lvbignMS4wJylcblx0XHQuYWRkQmVhcmVyQXV0aChcblx0XHRcdHsgdHlwZTogJ2h0dHAnLCBkZXNjcmlwdGlvbjogJ0FjY2VzcyB0b2tlbicgfSxcblx0XHRcdCdhY2Nlc3MtdG9rZW4nXG5cdFx0KVxuXHRcdC5idWlsZCgpXG5cdGNvbnN0IGRvY3VtZW50ID0gU3dhZ2dlck1vZHVsZS5jcmVhdGVEb2N1bWVudChhcHAsIGNvbmZpZylcblx0U3dhZ2dlck1vZHVsZS5zZXR1cCgnZG9jdW1lbnQnLCBhcHAsIGRvY3VtZW50KVxufVxuIiwiaW1wb3J0IHsgcmVnaXN0ZXJBcyB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZU9wdGlvbnMgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5cbmV4cG9ydCBjb25zdCBKd3RDb25maWcgPSByZWdpc3RlckFzKCdqd3QnLCAoKSA9PiAoe1xuXHRhY2Nlc3NLZXk6IHByb2Nlc3MuZW52LkpXVF9BQ0NFU1NfS0VZLFxuXHRyZWZyZXNoS2V5OiBwcm9jZXNzLmVudi5KV1RfUkVGUkVTSF9LRVksXG5cdGFjY2Vzc1RpbWU6IE51bWJlcihwcm9jZXNzLmVudi5KV1RfQUNDRVNTX1RJTUUpLFxuXHRyZWZyZXNoVGltZTogTnVtYmVyKHByb2Nlc3MuZW52LkpXVF9SRUZSRVNIX1RJTUUpLFxufSkpXG5cbmV4cG9ydCBjb25zdCBNYXJpYWRiQ29uZmlnID0gcmVnaXN0ZXJBcygnbWFyaWFkYicsICgpOiBUeXBlT3JtTW9kdWxlT3B0aW9ucyA9PiAoe1xuXHR0eXBlOiAnbWFyaWFkYicsXG5cdGhvc3Q6IHByb2Nlc3MuZW52Lk1BUklBREJfSE9TVCxcblx0cG9ydDogcGFyc2VJbnQocHJvY2Vzcy5lbnYuTUFSSUFEQl9QT1JULCAxMCksXG5cdGRhdGFiYXNlOiBwcm9jZXNzLmVudi5NQVJJQURCX0RBVEFCQVNFLFxuXHR1c2VybmFtZTogcHJvY2Vzcy5lbnYuTUFSSUFEQl9VU0VSTkFNRSxcblx0cGFzc3dvcmQ6IHByb2Nlc3MuZW52Lk1BUklBREJfUEFTU1dPUkQsXG5cdGF1dG9Mb2FkRW50aXRpZXM6IHRydWUsXG5cdGxvZ2dpbmc6IHByb2Nlc3MuZW52Lk5PREVfRU5WICE9PSAncHJvZHVjdGlvbicsXG5cdHN5bmNocm9uaXplOiBwcm9jZXNzLmVudi5OT0RFX0VOViA9PT0gJ2xvY2FsJyxcbn0pKVxuIiwiZXhwb3J0IGVudW0gRUVycm9yIHtcblx0VW5rbm93biA9ICdBMDAuVU5LTk9XTidcbn1cblxuZXhwb3J0IGVudW0gRVZhbGlkYXRlRXJyb3Ige1xuXHRGYWlsZWQgPSAnVjAwLlZBTElEQVRFX0ZBSUxFRCdcbn1cblxuZXhwb3J0IGVudW0gRVJlZ2lzdGVyRXJyb3Ige1xuXHRFeGlzdEVtYWlsQW5kUGhvbmUgPSAnUjAxLkVYSVNUX0VNQUlMX0FORF9QSE9ORScsXG5cdEV4aXN0RW1haWwgPSAnUjAyLkVYSVNUX0VNQUlMJyxcblx0RXhpc3RQaG9uZSA9ICdSMDMuRVhJU1RfUEhPTkUnLFxuXHRFeGlzdFVzZXJuYW1lID0gJ1IwNC5FWElTVF9VU0VSTkFNRSdcbn1cblxuZXhwb3J0IGVudW0gRUxvZ2luRXJyb3Ige1xuXHRFbXBsb3llZURvZXNOb3RFeGlzdCA9ICdMMDEuRU1QTE9ZRUVfRE9FU19OT1RfRVhJU1QnLFxuXHRXcm9uZ1Bhc3N3b3JkID0gJ0wwMi5XUk9OR19QQVNTV09SRCdcbn1cblxuZXhwb3J0IGVudW0gRVRva2VuRXJyb3Ige1xuXHRFeHBpcmVkID0gJ1QwMS5FWFBJUkVEJyxcblx0SW52YWxpZCA9ICdUMDIuSU5WQUxJRCdcbn1cblxuZXhwb3J0IGVudW0gRUVtcGxveWVlRXJyb3Ige1xuXHRVc2VybmFtZUV4aXN0cyA9ICdVMDEuVVNFUk5BTUVfRVhJU1RTJyxcblx0Tm90RXhpc3RzID0gJ1UwMi5FTVBMT1lFRV9ET0VTX05PVF9FWElTVCdcbn1cblxuZXhwb3J0IGVudW0gRVBhdGllbnRFcnJvciB7XG5cdE5vdEV4aXN0cyA9ICdQMDEuUEFUSUVOVF9ET0VTX05PVF9FWElTVCdcbn1cbiIsImltcG9ydCB7IEV4Y2VwdGlvbkZpbHRlciwgQ2F0Y2gsIEFyZ3VtZW50c0hvc3QsIEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcblxuQENhdGNoKEh0dHBFeGNlcHRpb24pXG5leHBvcnQgY2xhc3MgSHR0cEV4Y2VwdGlvbkZpbHRlciBpbXBsZW1lbnRzIEV4Y2VwdGlvbkZpbHRlciB7XG5cdGNhdGNoKGV4Y2VwdGlvbjogSHR0cEV4Y2VwdGlvbiwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IGV4Y2VwdGlvbi5nZXRTdGF0dXMoKVxuXG5cdFx0cmVzcG9uc2Uuc3RhdHVzKGh0dHBTdGF0dXMpLmpzb24oe1xuXHRcdFx0aHR0cFN0YXR1cyxcblx0XHRcdG1lc3NhZ2U6IGV4Y2VwdGlvbi5nZXRSZXNwb25zZSgpLFxuXHRcdFx0cGF0aDogcmVxdWVzdC51cmwsXG5cdFx0XHR0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcmd1bWVudHNIb3N0LCBDYXRjaCwgRXhjZXB0aW9uRmlsdGVyLCBIdHRwU3RhdHVzLCBMb2dnZXIgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlcXVlc3QsIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcblxuQENhdGNoKEVycm9yKVxuZXhwb3J0IGNsYXNzIFVua25vd25FeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ1NFUlZFUl9FUlJPUicpKSB7IH1cblxuXHRjYXRjaChleGNlcHRpb246IEVycm9yLCBob3N0OiBBcmd1bWVudHNIb3N0KSB7XG5cdFx0Y29uc3QgY3R4ID0gaG9zdC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlc3BvbnNlID0gY3R4LmdldFJlc3BvbnNlPFJlc3BvbnNlPigpXG5cdFx0Y29uc3QgcmVxdWVzdCA9IGN0eC5nZXRSZXF1ZXN0PFJlcXVlc3Q+KClcblx0XHRjb25zdCBodHRwU3RhdHVzID0gSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1JcblxuXHRcdHRoaXMubG9nZ2VyLmVycm9yKGV4Y2VwdGlvbi5zdGFjaylcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlOiBleGNlcHRpb24ubWVzc2FnZSxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXJndW1lbnRzSG9zdCwgQ2F0Y2gsIEV4Y2VwdGlvbkZpbHRlciwgSHR0cFN0YXR1cywgVmFsaWRhdGlvbkVycm9yIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBFVmFsaWRhdGVFcnJvciB9IGZyb20gJy4vZXhjZXB0aW9uLmVudW0nXG5cbmV4cG9ydCBjbGFzcyBWYWxpZGF0aW9uRXhjZXB0aW9uIGV4dGVuZHMgRXJyb3Ige1xuXHRwcml2YXRlIHJlYWRvbmx5IGVycm9yczogVmFsaWRhdGlvbkVycm9yW11cblx0Y29uc3RydWN0b3IodmFsaWRhdGlvbkVycm9yczogVmFsaWRhdGlvbkVycm9yW10gPSBbXSkge1xuXHRcdHN1cGVyKEVWYWxpZGF0ZUVycm9yLkZhaWxlZClcblx0XHR0aGlzLmVycm9ycyA9IHZhbGlkYXRpb25FcnJvcnNcblx0fVxuXHRnZXRNZXNzYWdlKCkge1xuXHRcdHJldHVybiB0aGlzLm1lc3NhZ2Vcblx0fVxuXHRnZXRFcnJvcnMoKSB7XG5cdFx0cmV0dXJuIHRoaXMuZXJyb3JzXG5cdH1cbn1cblxuQENhdGNoKFZhbGlkYXRpb25FeGNlcHRpb24pXG5leHBvcnQgY2xhc3MgVmFsaWRhdGlvbkV4Y2VwdGlvbkZpbHRlciBpbXBsZW1lbnRzIEV4Y2VwdGlvbkZpbHRlciB7XG5cdGNhdGNoKGV4Y2VwdGlvbjogVmFsaWRhdGlvbkV4Y2VwdGlvbiwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IEh0dHBTdGF0dXMuVU5QUk9DRVNTQUJMRV9FTlRJVFlcblx0XHRjb25zdCBtZXNzYWdlID0gZXhjZXB0aW9uLmdldE1lc3NhZ2UoKVxuXHRcdGNvbnN0IGVycm9ycyA9IGV4Y2VwdGlvbi5nZXRFcnJvcnMoKVxuXG5cdFx0cmVzcG9uc2Uuc3RhdHVzKGh0dHBTdGF0dXMpLmpzb24oe1xuXHRcdFx0aHR0cFN0YXR1cyxcblx0XHRcdG1lc3NhZ2UsXG5cdFx0XHRlcnJvcnMsXG5cdFx0XHRwYXRoOiByZXF1ZXN0LnVybCxcblx0XHRcdHRpbWVzdGFtcDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IENhbkFjdGl2YXRlLCBFeGVjdXRpb25Db250ZXh0LCBJbmplY3RhYmxlLCBTZXRNZXRhZGF0YSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVmbGVjdG9yIH0gZnJvbSAnQG5lc3Rqcy9jb3JlJ1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBURW1wbG95ZWVSb2xlIH0gZnJvbSAndHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuXG5leHBvcnQgY29uc3QgVXNlclJvbGVzID0gKC4uLnVzZXJSb2xlczogVEVtcGxveWVlUm9sZVtdKSA9PiBTZXRNZXRhZGF0YSgndXNlcl9yb2xlcycsIHVzZXJSb2xlcylcbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBVc2VyUm9sZXNHdWFyZCBpbXBsZW1lbnRzIENhbkFjdGl2YXRlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWZsZWN0b3I6IFJlZmxlY3RvcikgeyB9XG5cblx0Y2FuQWN0aXZhdGUoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCk6IGJvb2xlYW4gfCBQcm9taXNlPGJvb2xlYW4+IHwgT2JzZXJ2YWJsZTxib29sZWFuPiB7XG5cdFx0Y29uc3Qgcm9sZXMgPSB0aGlzLnJlZmxlY3Rvci5nZXQ8VEVtcGxveWVlUm9sZVtdPigndXNlcl9yb2xlcycsIGNvbnRleHQuZ2V0SGFuZGxlcigpKVxuXHRcdGlmICghcm9sZXMpIHJldHVybiB0cnVlXG5cblx0XHRjb25zdCByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4gPSBjb250ZXh0LnN3aXRjaFRvSHR0cCgpLmdldFJlcXVlc3QoKVxuXHRcdGNvbnN0IHsgcm9sZSB9ID0gcmVxdWVzdC50b2tlblBheWxvYWRcblx0XHRyZXR1cm4gcm9sZXMuaW5jbHVkZXMocm9sZSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQ2FsbEhhbmRsZXIsIEV4ZWN1dGlvbkNvbnRleHQsIEluamVjdGFibGUsIE5lc3RJbnRlcmNlcHRvciwgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcydcbmltcG9ydCB7IHRhcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQWNjZXNzTG9nSW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ0FDQ0VTU19MT0cnKSkgeyB9XG5cblx0aW50ZXJjZXB0KGNvbnRleHQ6IEV4ZWN1dGlvbkNvbnRleHQsIG5leHQ6IENhbGxIYW5kbGVyKTogT2JzZXJ2YWJsZTxhbnk+IHtcblx0XHRjb25zdCBzdGFydFRpbWUgPSBuZXcgRGF0ZSgpXG5cdFx0Y29uc3QgY3R4ID0gY29udGV4dC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVxdWVzdCgpXG5cblx0XHRjb25zdCB7IHVybCwgbWV0aG9kIH0gPSByZXF1ZXN0XG5cdFx0Y29uc3QgeyBzdGF0dXNDb2RlIH0gPSByZXNwb25zZVxuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxdWVzdClcblxuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUodGFwKCgpID0+IHtcblx0XHRcdGNvbnN0IG1zZyA9IGAke3N0YXJ0VGltZS50b0lTT1N0cmluZygpfSB8ICR7aXB9IHwgJHttZXRob2R9IHwgJHtzdGF0dXNDb2RlfSB8ICR7dXJsfSB8ICR7RGF0ZS5ub3coKSAtIHN0YXJ0VGltZS5nZXRUaW1lKCl9bXNgXG5cdFx0XHRyZXR1cm4gdGhpcy5sb2dnZXIubG9nKG1zZylcblx0XHR9KSlcblx0fVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmVzdEludGVyY2VwdG9yLCBFeGVjdXRpb25Db250ZXh0LCBDYWxsSGFuZGxlciwgUmVxdWVzdFRpbWVvdXRFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IE9ic2VydmFibGUsIHRocm93RXJyb3IsIFRpbWVvdXRFcnJvciB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBjYXRjaEVycm9yLCB0aW1lb3V0IH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBUaW1lb3V0SW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRpbnRlcmNlcHQoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCwgbmV4dDogQ2FsbEhhbmRsZXIpOiBPYnNlcnZhYmxlPGFueT4ge1xuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUoXG5cdFx0XHR0aW1lb3V0KDEwMDAwKSxcblx0XHRcdGNhdGNoRXJyb3IoZXJyID0+IHtcblx0XHRcdFx0aWYgKGVyciBpbnN0YW5jZW9mIFRpbWVvdXRFcnJvcikge1xuXHRcdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IG5ldyBSZXF1ZXN0VGltZW91dEV4Y2VwdGlvbigpKVxuXHRcdFx0XHR9XG5cdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IGVycilcblx0XHRcdH0pXG5cdFx0KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZXN0TWlkZGxld2FyZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gJ2V4cHJlc3MnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBMb2dnZXJNaWRkbGV3YXJlIGltcGxlbWVudHMgTmVzdE1pZGRsZXdhcmUge1xuXHR1c2UocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pIHtcblx0XHRjb25zb2xlLmxvZygnUmVxdWVzdC4uLicpXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUsIE5lc3RNaWRkbGV3YXJlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBOZXh0RnVuY3Rpb24sIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcbmltcG9ydCB7IGdldENsaWVudElwIH0gZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IElKd3RQYXlsb2FkLCBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4uL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSBpbXBsZW1lbnRzIE5lc3RNaWRkbGV3YXJlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlKSB7IH1cblxuXHRhc3luYyB1c2UocmVxOiBSZXF1ZXN0VG9rZW4sIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikge1xuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxKVxuXHRcdGNvbnN0IGF1dGhvcml6YXRpb24gPSByZXEuaGVhZGVyKCdBdXRob3JpemF0aW9uJykgfHwgJydcblx0XHRjb25zdCBbLCBhY2Nlc3NUb2tlbl0gPSBhdXRob3JpemF0aW9uLnNwbGl0KCcgJylcblx0XHRjb25zdCBkZWNvZGU6IElKd3RQYXlsb2FkID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuLCBpcClcblx0XHRyZXEudG9rZW5QYXlsb2FkID0gZGVjb2RlXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFJlcSwgU2VyaWFsaXplT3B0aW9ucyB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IFJlcXVlc3RUb2tlbiB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnXG5pbXBvcnQgeyBDcmVhdGVBZG1pc3Npb25EdG8sIFVwZGF0ZUFkbWlzc2lvbkR0byB9IGZyb20gJy4vYWRtaXNzaW9uLmR0bydcbmltcG9ydCB7IEFkbWlzc2lvblNlcnZpY2UgfSBmcm9tICcuL2FkbWlzc2lvbi5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnQWRtaXNzaW9uJylcbkBTZXJpYWxpemVPcHRpb25zKHsgZXhjbHVkZUV4dHJhbmVvdXNWYWx1ZXM6IHRydWUsIGV4cG9zZVVuc2V0RmllbGRzOiBmYWxzZSB9KVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignYWRtaXNzaW9uJylcbmV4cG9ydCBjbGFzcyBBZG1pc3Npb25Db250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBhZG1pc3Npb25TZXJ2aWNlOiBBZG1pc3Npb25TZXJ2aWNlKSB7IH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5hZG1pc3Npb25TZXJ2aWNlLmZpbmRBbGwoKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmFkbWlzc2lvblNlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZUFkbWlzc2lvbkR0bzogQ3JlYXRlQWRtaXNzaW9uRHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5hZG1pc3Npb25TZXJ2aWNlLmNyZWF0ZShjbGluaWNJZCwgY3JlYXRlQWRtaXNzaW9uRHRvKVxuXHR9XG5cblx0QFBhdGNoKCc6aWQnKVxuXHR1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlQWRtaXNzaW9uRHRvOiBVcGRhdGVBZG1pc3Npb25EdG8pIHtcblx0XHRyZXR1cm4gdGhpcy5hZG1pc3Npb25TZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZUFkbWlzc2lvbkR0bylcblx0fVxuXG5cdEBEZWxldGUoJzppZCcpXG5cdHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmFkbWlzc2lvblNlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHlPcHRpb25hbCwgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBFeHBvc2UsIFR5cGUgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IElzRGF0ZSwgSXNFbnVtLCBJc051bWJlciwgSXNTdHJpbmcsIFZhbGlkYXRlTmVzdGVkIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuaW1wb3J0IHsgRUdlbmRlciB9IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vYmFzZS5lbnRpdHknXG5pbXBvcnQgUGF0aWVudEVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL3BhdGllbnQuZW50aXR5J1xuXG5jbGFzcyBQYXRpZW50RHRvIHtcblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBuYW1lOiAncGF0aWVudF9pZCcsIGV4YW1wbGU6ICcnIH0pXG5cdEBFeHBvc2UoeyBuYW1lOiAncGF0aWVudF9pZCcgfSlcblx0QFR5cGUoKCkgPT4gTnVtYmVyKVxuXHRASXNOdW1iZXIoKVxuXHRwYXRpZW50SWQ6IG51bWJlclxuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgbmFtZTogJ2Z1bGxfbmFtZScsIGV4YW1wbGU6ICdOZ3V54buFbiBUaOG7iyDDgW5oJyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ2Z1bGxfbmFtZScgfSlcblx0QElzU3RyaW5nKClcblx0ZnVsbE5hbWU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogJzA5ODc0NDUyMjMnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNTdHJpbmcoKVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnMTkyNy0wNC0yOFQwMDowMDowMC4wMDBaJyB9KVxuXHRARXhwb3NlKClcblx0QFR5cGUoKCkgPT4gRGF0ZSlcblx0QElzRGF0ZSgpXG5cdGJpcnRoZGF5OiBEYXRlXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBlbnVtOiBFR2VuZGVyLCBleGFtcGxlOiBFR2VuZGVyLkZlbWFsZSB9KVxuXHRARXhwb3NlKClcblx0QElzRW51bShFR2VuZGVyKVxuXHRnZW5kZXI6IEVHZW5kZXJcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICdU4buJbmggSMOgIFTEqW5oIC0tIEh1eeG7h24gxJDhu6ljIFRo4buNIC0tIFjDoyBMw6JtIFRydW5nIFRo4buneSAtLSBUaMO0biBQaGFuIFRo4bqvbmcnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNTdHJpbmcoKVxuXHRhZGRyZXNzOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIENyZWF0ZUFkbWlzc2lvbkR0byB7XG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgdHlwZTogUGF0aWVudER0byB9KVxuXHRARXhwb3NlKClcblx0QFZhbGlkYXRlTmVzdGVkKHsgZWFjaDogdHJ1ZSB9KVxuXHRAVHlwZSgoKSA9PiBQYXRpZW50RHRvKVxuXHRwYXRpZW50OiBQYXRpZW50RW50aXR5XG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnU+G7kXQgY2FvIG5nw6B5IHRo4bupIDMnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNTdHJpbmcoKVxuXHRyZWFzb246IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlQWRtaXNzaW9uRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlQWRtaXNzaW9uRHRvKSB7IH1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBBZG1pc3Npb25FbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9hZG1pc3Npb24uZW50aXR5J1xuaW1wb3J0IHsgQWRtaXNzaW9uQ29udHJvbGxlciB9IGZyb20gJy4vYWRtaXNzaW9uLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBBZG1pc3Npb25TZXJ2aWNlIH0gZnJvbSAnLi9hZG1pc3Npb24uc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW0FkbWlzc2lvbkVudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtBZG1pc3Npb25Db250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbQWRtaXNzaW9uU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIEFkbWlzc2lvbk1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEluamVjdFJlcG9zaXRvcnkgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBBZG1pc3Npb25FbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9hZG1pc3Npb24uZW50aXR5J1xuaW1wb3J0IHsgQ3JlYXRlQWRtaXNzaW9uRHRvLCBVcGRhdGVBZG1pc3Npb25EdG8gfSBmcm9tICcuL2FkbWlzc2lvbi5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBZG1pc3Npb25TZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoQEluamVjdFJlcG9zaXRvcnkoQWRtaXNzaW9uRW50aXR5KSBwcml2YXRlIGFkbWlzc2lvblJlcG9zaXRvcnk6IFJlcG9zaXRvcnk8QWRtaXNzaW9uRW50aXR5PikgeyB9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIGFkbWlzc2lvbmBcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBhZG1pc3Npb25gXG5cdH1cblx0Y3JlYXRlKGNsaW5pY0lkOiBudW1iZXIsIGNyZWF0ZUFkbWlzc2lvbkR0bzogQ3JlYXRlQWRtaXNzaW9uRHRvKSB7XG5cdFx0cmV0dXJuICdUaGlzIGFjdGlvbiBhZGRzIGEgbmV3IGFkbWlzc2lvbidcblx0fVxuXHR1cGRhdGUoaWQ6IG51bWJlciwgdXBkYXRlQWRtaXNzaW9uRHRvOiBVcGRhdGVBZG1pc3Npb25EdG8pIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHVwZGF0ZXMgYSAjJHtpZH0gYWRtaXNzaW9uYFxuXHR9XG5cblx0cmVtb3ZlKGlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJlbW92ZXMgYSAjJHtpZH0gYWRtaXNzaW9uYFxuXHR9XG59XG4iLCJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBQYXJhbSwgUG9zdCwgUmVxLCBTZXJpYWxpemVPcHRpb25zIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdCB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBMb2dpbkR0bywgUmVmcmVzaFRva2VuRHRvLCBSZWdpc3RlckR0bywgVG9rZW5zUmVzcG9uc2UgfSBmcm9tICcuL2F1dGguZHRvJ1xuaW1wb3J0IHsgQXV0aFNlcnZpY2UgfSBmcm9tICcuL2F1dGguc2VydmljZSdcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ0F1dGgnKVxuQFNlcmlhbGl6ZU9wdGlvbnMoeyBleGNsdWRlRXh0cmFuZW91c1ZhbHVlczogdHJ1ZSwgZXhwb3NlVW5zZXRGaWVsZHM6IGZhbHNlIH0pXG5AQ29udHJvbGxlcignYXV0aCcpXG5leHBvcnQgY2xhc3MgQXV0aENvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihcblx0XHRwcml2YXRlIHJlYWRvbmx5IGF1dGhTZXJ2aWNlOiBBdXRoU2VydmljZSxcblx0XHRwcml2YXRlIHJlYWRvbmx5IGp3dEV4dGVuZFNlcnZpY2U6IEp3dEV4dGVuZFNlcnZpY2Vcblx0KSB7IH1cblxuXHRAUG9zdCgncmVnaXN0ZXInKVxuXHRhc3luYyByZWdpc3RlcihAQm9keSgpIHJlZ2lzdGVyRHRvOiBSZWdpc3RlckR0bywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3QpOiBQcm9taXNlPFRva2Vuc1Jlc3BvbnNlPiB7XG5cdFx0Y29uc3QgaXAgPSBnZXRDbGllbnRJcChyZXF1ZXN0KVxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5yZWdpc3RlcihyZWdpc3RlckR0bylcblx0XHRjb25zdCB7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfSA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVUb2tlbkZyb21Vc2VyKGVtcGxveWVlLCBpcClcblx0XHRyZXR1cm4gbmV3IFRva2Vuc1Jlc3BvbnNlKHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9KVxuXHR9XG5cblx0QFBvc3QoJ2xvZ2luJylcblx0YXN5bmMgbG9naW4oQEJvZHkoKSBsb2dpbkR0bzogTG9naW5EdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0KTogUHJvbWlzZTxUb2tlbnNSZXNwb25zZT4ge1xuXHRcdGNvbnNvbGUubG9nKCfwn5qAIH4gZmlsZTogYXV0aC5jb250cm9sbGVyLnRzOjMzIH4gQXV0aENvbnRyb2xsZXIgfiBsb2dpbiB+IGxvZ2luRHRvJywgbG9naW5EdG8pXG5cdFx0Y29uc3QgaXAgPSBnZXRDbGllbnRJcChyZXF1ZXN0KVxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5sb2dpbihsb2dpbkR0bylcblx0XHRjb25zdCB7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfSA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVUb2tlbkZyb21Vc2VyKGVtcGxveWVlLCBpcClcblx0XHRyZXR1cm4gbmV3IFRva2Vuc1Jlc3BvbnNlKHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9KVxuXHR9XG5cblx0QFBvc3QoJ2xvZ291dCcpXG5cdGxvZ291dChAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdC8vIHJldHVybiB0aGlzLmF1dGhTZXJ2aWNlLmZpbmRPbmUoK2lkKVxuXHR9XG5cblx0QFBvc3QoJ2NoYW5nZS1wYXNzd29yZCcpXG5cdGNoYW5nZVBhc3N3b3JkKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAQm9keSgpIHVwZGF0ZUF1dGhEdG86IExvZ2luRHRvKSB7XG5cdFx0Ly8gcmV0dXJuIHRoaXMuYXV0aFNlcnZpY2UudXBkYXRlKCtpZCwgdXBkYXRlQXV0aER0bylcblx0fVxuXG5cdEBQb3N0KCdmb3Jnb3QtcGFzc3dvcmQnKVxuXHRmb3Jnb3RQYXNzd29yZChAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdC8vIHJldHVybiB0aGlzLmF1dGhTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cblxuXHRAUG9zdCgncmVmcmVzaC10b2tlbicpXG5cdGFzeW5jIGdyYW50QWNjZXNzVG9rZW4oQEJvZHkoKSByZWZyZXNoVG9rZW5EdG86IFJlZnJlc2hUb2tlbkR0bywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3QpOiBQcm9taXNlPFRva2Vuc1Jlc3BvbnNlPiB7XG5cdFx0Y29uc3QgaXAgPSBnZXRDbGllbnRJcChyZXF1ZXN0KVxuXHRcdGNvbnN0IGFjY2Vzc1Rva2VuID0gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5ncmFudEFjY2Vzc1Rva2VuKHJlZnJlc2hUb2tlbkR0by5yZWZyZXNoVG9rZW4sIGlwKVxuXHRcdHJldHVybiBuZXcgVG9rZW5zUmVzcG9uc2UoeyBhY2Nlc3NUb2tlbiB9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcGlQcm9wZXJ0eSB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IEV4cG9zZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgSXNOb3RFbXB0eSwgTWluTGVuZ3RoLCBWYWxpZGF0ZSB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcbmltcG9ydCB7IElzR21haWwsIElzUGhvbmUgfSBmcm9tICcuLi8uLi9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbSdcblxuZXhwb3J0IGNsYXNzIFJlZ2lzdGVyRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2V4YW1wbGUtMkBnbWFpbC5jb20nIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBWYWxpZGF0ZShJc0dtYWlsKVxuXHRlbWFpbDogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJzAzNzY4OTk4NjYnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBWYWxpZGF0ZShJc1Bob25lKVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2FkbWluJyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBNaW5MZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgTG9naW5EdG8ge1xuXHRAQXBpUHJvcGVydHkoeyBuYW1lOiAnY19waG9uZScsIGV4YW1wbGU6ICcwOTg2MDIxMTkwJyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ2NfcGhvbmUnIH0pXG5cdEBJc05vdEVtcHR5KClcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdGNQaG9uZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2FkbWluJyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBNaW5MZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgUmVmcmVzaFRva2VuRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgbmFtZTogJ3JlZnJlc2hfdG9rZW4nIH0pXG5cdEBFeHBvc2UoeyBuYW1lOiAncmVmcmVzaF90b2tlbicgfSlcblx0QElzTm90RW1wdHkoKVxuXHRyZWZyZXNoVG9rZW46IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVG9rZW5zUmVzcG9uc2Uge1xuXHRARXhwb3NlKHsgbmFtZTogJ2FjY2Vzc190b2tlbicgfSlcblx0YWNjZXNzVG9rZW46IHN0cmluZ1xuXG5cdEBFeHBvc2UoeyBuYW1lOiAncmVmcmVzaF90b2tlbicgfSlcblx0cmVmcmVzaFRva2VuOiBzdHJpbmdcblxuXHRjb25zdHJ1Y3RvcihwYXJ0aWFsOiBQYXJ0aWFsPFRva2Vuc1Jlc3BvbnNlPikge1xuXHRcdE9iamVjdC5hc3NpZ24odGhpcywgcGFydGlhbClcblx0fVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEp3dE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvand0J1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgSnd0Q29uZmlnIH0gZnJvbSAnLi4vLi4vZW52aXJvbm1lbnRzJ1xuaW1wb3J0IHsgQXV0aENvbnRyb2xsZXIgfSBmcm9tICcuL2F1dGguY29udHJvbGxlcidcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHksIEVtcGxveWVlRW50aXR5XSksXG5cdFx0Q29uZmlnTW9kdWxlLmZvckZlYXR1cmUoSnd0Q29uZmlnKSxcblx0XHRKd3RNb2R1bGUsXG5cdF0sXG5cdGNvbnRyb2xsZXJzOiBbQXV0aENvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtBdXRoU2VydmljZSwgSnd0RXh0ZW5kU2VydmljZV0sXG5cdGV4cG9ydHM6IFtKd3RFeHRlbmRTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb24sIEh0dHBTdGF0dXMsIEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVFbXBsb3llZVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVMb2dpbkVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgTG9naW5EdG8sIFJlZ2lzdGVyRHRvIH0gZnJvbSAnLi9hdXRoLmR0bydcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEF1dGhTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlLFxuXHRcdHByaXZhdGUgand0RXh0ZW5kU2VydmljZTogSnd0RXh0ZW5kU2VydmljZVxuXHQpIHsgfVxuXG5cdGFzeW5jIHJlZ2lzdGVyKHJlZ2lzdGVyRHRvOiBSZWdpc3RlckR0byk6IFByb21pc2U8RW1wbG95ZWVFbnRpdHk+IHtcblx0XHRjb25zdCB7IGVtYWlsLCBwaG9uZSwgdXNlcm5hbWUsIHBhc3N3b3JkIH0gPSByZWdpc3RlckR0b1xuXHRcdGNvbnN0IGhhc2hQYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5oYXNoKHBhc3N3b3JkLCA1KVxuXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UudHJhbnNhY3Rpb24oYXN5bmMgKG1hbmFnZXIpID0+IHtcblx0XHRcdGNvbnN0IGZpbmRDbGluaWMgPSBhd2FpdCBtYW5hZ2VyLmZpbmRPbmUoQ2xpbmljRW50aXR5LCB7IHdoZXJlOiBbeyBlbWFpbCB9LCB7IHBob25lIH1dIH0pXG5cdFx0XHRpZiAoZmluZENsaW5pYykge1xuXHRcdFx0XHRpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwgJiYgZmluZENsaW5pYy5waG9uZSA9PT0gcGhvbmUpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsQW5kUGhvbmUsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZSBpZiAoZmluZENsaW5pYy5lbWFpbCA9PT0gZW1haWwpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdEVtYWlsLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2UgaWYgKGZpbmRDbGluaWMucGhvbmUgPT09IHBob25lKSB7XG5cdFx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RQaG9uZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdFx0Y29uc3Qgc25hcENsaW5pYyA9IG1hbmFnZXIuY3JlYXRlKENsaW5pY0VudGl0eSwge1xuXHRcdFx0XHRwaG9uZSxcblx0XHRcdFx0ZW1haWwsXG5cdFx0XHRcdGxldmVsOiAxLFxuXHRcdFx0fSlcblx0XHRcdGNvbnN0IG5ld0NsaW5pYyA9IGF3YWl0IG1hbmFnZXIuc2F2ZShzbmFwQ2xpbmljKVxuXG5cdFx0XHRjb25zdCBzbmFwRW1wbG95ZWUgPSBtYW5hZ2VyLmNyZWF0ZShFbXBsb3llZUVudGl0eSwge1xuXHRcdFx0XHRjbGluaWNJZDogbmV3Q2xpbmljLmlkLFxuXHRcdFx0XHRjbGluaWM6IG5ld0NsaW5pYyxcblx0XHRcdFx0dXNlcm5hbWUsXG5cdFx0XHRcdHBhc3N3b3JkOiBoYXNoUGFzc3dvcmQsXG5cdFx0XHRcdHJvbGU6IEVFbXBsb3llZVJvbGUuT3duZXIsXG5cdFx0XHR9KVxuXHRcdFx0Y29uc3QgbmV3RW1wbG95ZWUgPSBhd2FpdCBtYW5hZ2VyLnNhdmUoc25hcEVtcGxveWVlKVxuXG5cdFx0XHRyZXR1cm4gbmV3RW1wbG95ZWVcblx0XHR9KVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBsb2dpbihsb2dpbkR0bzogTG9naW5EdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UubWFuYWdlci5maW5kT25lKEVtcGxveWVlRW50aXR5LCB7XG5cdFx0XHRyZWxhdGlvbnM6IHsgY2xpbmljOiB0cnVlIH0sXG5cdFx0XHR3aGVyZToge1xuXHRcdFx0XHR1c2VybmFtZTogbG9naW5EdG8udXNlcm5hbWUsXG5cdFx0XHRcdGNsaW5pYzogeyBwaG9uZTogbG9naW5EdG8uY1Bob25lIH0sXG5cdFx0XHR9LFxuXHRcdH0pXG5cdFx0aWYgKCFlbXBsb3llZSkgdGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuRW1wbG95ZWVEb2VzTm90RXhpc3QsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cblx0XHRjb25zdCBjaGVja1Bhc3N3b3JkID0gYXdhaXQgYmNyeXB0LmNvbXBhcmUobG9naW5EdG8ucGFzc3dvcmQsIGVtcGxveWVlLnBhc3N3b3JkKVxuXHRcdGlmICghY2hlY2tQYXNzd29yZCkgdGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuV3JvbmdQYXNzd29yZCwgSHR0cFN0YXR1cy5CQURfR0FURVdBWSlcblxuXHRcdHJldHVybiBlbXBsb3llZVxuXHR9XG5cblx0YXN5bmMgZ3JhbnRBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZywgaXA6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG5cdFx0Y29uc3QgeyB1aWQgfSA9IHRoaXMuand0RXh0ZW5kU2VydmljZS52ZXJpZnlSZWZyZXNoVG9rZW4ocmVmcmVzaFRva2VuLCBpcClcblxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5kYXRhU291cmNlLmdldFJlcG9zaXRvcnkoRW1wbG95ZWVFbnRpdHkpLmZpbmRPbmUoe1xuXHRcdFx0cmVsYXRpb25zOiB7IGNsaW5pYzogdHJ1ZSB9LFxuXHRcdFx0d2hlcmU6IHsgaWQ6IHVpZCB9LFxuXHRcdH0pXG5cblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVBY2Nlc3NUb2tlbihlbXBsb3llZSwgaXApXG5cdFx0cmV0dXJuIGFjY2Vzc1Rva2VuXG5cdH1cbn1cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb24sIEh0dHBTdGF0dXMsIEluamVjdCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnVHlwZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgSnd0U2VydmljZSB9IGZyb20gJ0BuZXN0anMvand0J1xuaW1wb3J0IFVzZXJFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBJSnd0UGF5bG9hZCB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnXG5pbXBvcnQgeyBKd3RDb25maWcgfSBmcm9tICcuLi8uLi9lbnZpcm9ubWVudHMnXG5pbXBvcnQgeyBFRXJyb3IsIEVUb2tlbkVycm9yIH0gZnJvbSAnLi4vLi4vZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0nXG5cbmV4cG9ydCBjbGFzcyBKd3RFeHRlbmRTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0QEluamVjdChKd3RDb25maWcuS0VZKSBwcml2YXRlIGp3dENvbmZpZzogQ29uZmlnVHlwZTx0eXBlb2YgSnd0Q29uZmlnPixcblx0XHRwcml2YXRlIHJlYWRvbmx5IGp3dFNlcnZpY2U6IEp3dFNlcnZpY2Vcblx0KSB7IH1cblxuXHRjcmVhdGVBY2Nlc3NUb2tlbih1c2VyOiBVc2VyRW50aXR5LCBpcDogc3RyaW5nKTogc3RyaW5nIHtcblx0XHRjb25zdCB1c2VyUGF5bG9hZDogSUp3dFBheWxvYWQgPSB7XG5cdFx0XHRpcCxcblx0XHRcdGNQaG9uZTogdXNlci5jbGluaWMucGhvbmUsXG5cdFx0XHRjaWQ6IHVzZXIuY2xpbmljLmlkLFxuXHRcdFx0dWlkOiB1c2VyLmlkLFxuXHRcdFx0dXNlcm5hbWU6IHVzZXIudXNlcm5hbWUsXG5cdFx0XHRyb2xlOiB1c2VyLnJvbGUsXG5cdFx0fVxuXHRcdHJldHVybiB0aGlzLmp3dFNlcnZpY2Uuc2lnbih1c2VyUGF5bG9hZCwge1xuXHRcdFx0c2VjcmV0OiB0aGlzLmp3dENvbmZpZy5hY2Nlc3NLZXksXG5cdFx0XHRleHBpcmVzSW46IHRoaXMuand0Q29uZmlnLmFjY2Vzc1RpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVJlZnJlc2hUb2tlbih1aWQ6IG51bWJlciwgaXA6IHN0cmluZyk6IHN0cmluZyB7XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHsgdWlkLCBpcCB9LCB7XG5cdFx0XHRzZWNyZXQ6IHRoaXMuand0Q29uZmlnLnJlZnJlc2hLZXksXG5cdFx0XHRleHBpcmVzSW46IHRoaXMuand0Q29uZmlnLnJlZnJlc2hUaW1lLFxuXHRcdH0pXG5cdH1cblxuXHRjcmVhdGVUb2tlbkZyb21Vc2VyKHVzZXI6IFVzZXJFbnRpdHksIGlwOiBzdHJpbmcpIHtcblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IHRoaXMuY3JlYXRlQWNjZXNzVG9rZW4odXNlciwgaXApXG5cdFx0Y29uc3QgcmVmcmVzaFRva2VuID0gdGhpcy5jcmVhdGVSZWZyZXNoVG9rZW4odXNlci5pZCwgaXApXG5cdFx0cmV0dXJuIHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9XG5cdH1cblxuXHR2ZXJpZnlBY2Nlc3NUb2tlbihhY2Nlc3NUb2tlbjogc3RyaW5nLCBpcDogc3RyaW5nKTogSUp3dFBheWxvYWQge1xuXHRcdHRyeSB7XG5cdFx0XHRjb25zdCBqd3RQYXlsb2FkOiBJSnd0UGF5bG9hZCA9IHRoaXMuand0U2VydmljZS52ZXJpZnkoYWNjZXNzVG9rZW4sIHsgc2VjcmV0OiB0aGlzLmp3dENvbmZpZy5hY2Nlc3NLZXkgfSlcblx0XHRcdGlmIChqd3RQYXlsb2FkLmlwICE9PSBpcCkge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5JbnZhbGlkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH1cblx0XHRcdHJldHVybiBqd3RQYXlsb2FkXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vd24sIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxuXG5cdHZlcmlmeVJlZnJlc2hUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZywgaXA6IHN0cmluZyk6IHsgdWlkOiBudW1iZXIgfSB7XG5cdFx0dHJ5IHtcblx0XHRcdGNvbnN0IGp3dFBheWxvYWQgPSB0aGlzLmp3dFNlcnZpY2UudmVyaWZ5KHJlZnJlc2hUb2tlbiwgeyBzZWNyZXQ6IHRoaXMuand0Q29uZmlnLnJlZnJlc2hLZXkgfSlcblx0XHRcdGlmIChqd3RQYXlsb2FkLmlwICE9PSBpcCkge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5JbnZhbGlkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH1cblx0XHRcdHJldHVybiBqd3RQYXlsb2FkXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vd24sIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQ29udHJvbGxlciwgR2V0LCBQb3N0LCBCb2R5LCBQYXRjaCwgUGFyYW0sIERlbGV0ZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5pbXBvcnQgeyBDcmVhdGVDbGluaWNEdG8sIFVwZGF0ZUNsaW5pY0R0byB9IGZyb20gJy4vY2xpbmljLmR0bydcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5cbkBBcGlUYWdzKCdDbGluaWMnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignY2xpbmljJylcbmV4cG9ydCBjbGFzcyBDbGluaWNDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBjbGluaWNTZXJ2aWNlOiBDbGluaWNTZXJ2aWNlKSB7IH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZUNsaW5pY0R0bzogQ3JlYXRlQ2xpbmljRHRvKSB7XG5cdFx0cmV0dXJuICcnXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLmZpbmRBbGwoKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNFbWFpbCwgTGVuZ3RoIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5leHBvcnQgY2xhc3MgQ3JlYXRlQ2xpbmljRHRvIHtcblx0QElzRW1haWwoKVxuXHRlbWFpbDogc3RyaW5nXG5cblx0QExlbmd0aCgxMCwgMTApXG5cdHBob25lOiBzdHJpbmdcblxuXHRATGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUNsaW5pY0R0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZUNsaW5pY0R0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCB7IENsaW5pY0NvbnRyb2xsZXIgfSBmcm9tICcuL2NsaW5pYy5jb250cm9sbGVyJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbQ2xpbmljQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0NsaW5pY1NlcnZpY2VdLFxuXHRleHBvcnRzOiBbQ2xpbmljU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIENsaW5pY01vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEluamVjdFJlcG9zaXRvcnkgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlLCBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ2xpbmljU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdEBJbmplY3RSZXBvc2l0b3J5KENsaW5pY0VudGl0eSkgcHJpdmF0ZSBjbGluaWNSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PENsaW5pY0VudGl0eT4sXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlXG5cdCkgeyB9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIGNsaW5pY2Bcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHR1cGRhdGUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFJlcSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVXNlSW50ZXJjZXB0b3JzIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9ycydcbmltcG9ydCB7IENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vc2VyaWFsaXplcidcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVBhcmFtLCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IENyZWF0ZUVtcGxveWVlRHRvLCBVcGRhdGVFbXBsb3llZUR0byB9IGZyb20gJy4vZW1wbG95ZWUuZHRvJ1xuaW1wb3J0IHsgRW1wbG95ZWVTZXJ2aWNlIH0gZnJvbSAnLi9lbXBsb3llZS5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnRW1wbG95ZWUnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AVXNlSW50ZXJjZXB0b3JzKENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yKVxuQENvbnRyb2xsZXIoJ2VtcGxveWVlJylcbmV4cG9ydCBjbGFzcyBFbXBsb3llZUNvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGVtcGxveWVlU2VydmljZTogRW1wbG95ZWVTZXJ2aWNlKSB7IH1cblxuXHRAR2V0KClcblx0ZmluZEFsbChAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5lbXBsb3llZVNlcnZpY2UuZmluZEFsbChjbGluaWNJZClcblx0fVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlRW1wbG95ZWVEdG86IENyZWF0ZUVtcGxveWVlRHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5lbXBsb3llZVNlcnZpY2UuY3JlYXRlKGNsaW5pY0lkLCBjcmVhdGVFbXBsb3llZUR0bylcblx0fVxuXG5cdEBHZXQoJzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLmZpbmRPbmUoY2xpbmljSWQsICtpZClcblx0fVxuXG5cdEBQYXRjaCgndXBkYXRlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgdXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuLCBAQm9keSgpIHVwZGF0ZUVtcGxveWVlRHRvOiBVcGRhdGVFbXBsb3llZUR0bykge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5lbXBsb3llZVNlcnZpY2UudXBkYXRlKGNsaW5pY0lkLCAraWQsIHVwZGF0ZUVtcGxveWVlRHRvKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cblxuXHRARGVsZXRlKCdyZW1vdmUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyByZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnJlbW92ZShjbGluaWNJZCwgK2lkKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cblxuXHRAUGF0Y2goJ3Jlc3RvcmUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyByZXN0b3JlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLmVtcGxveWVlU2VydmljZS5yZXN0b3JlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHksIFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNEZWZpbmVkLCBNaW5MZW5ndGggfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVFbXBsb3llZUR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICduaGF0ZHVvbmcyMDE5JyB9KVxuXHRASXNEZWZpbmVkKClcblx0dXNlcm5hbWU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdBYmNAMTIzNDU2JyB9KVxuXHRASXNEZWZpbmVkKClcblx0QE1pbkxlbmd0aCg2KVxuXHRwYXNzd29yZDogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ05nw7QgTmjhuq10IETGsMahbmcnIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUVtcGxveWVlRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlRW1wbG95ZWVEdG8pIHsgfVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2NsaW5pYy5lbnRpdHknXG5pbXBvcnQgRW1wbG95ZWVFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBFbXBsb3llZUNvbnRyb2xsZXIgfSBmcm9tICcuL2VtcGxveWVlLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBFbXBsb3llZVNlcnZpY2UgfSBmcm9tICcuL2VtcGxveWVlLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtFbXBsb3llZUVudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtFbXBsb3llZUNvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtFbXBsb3llZVNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBFbXBsb3llZU1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEh0dHBTdGF0dXMgfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9lbnVtcydcbmltcG9ydCB7IEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBwbGFpblRvQ2xhc3MgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVFbXBsb3llZVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVFbXBsb3llZUVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8sIFVwZGF0ZUVtcGxveWVlRHRvIH0gZnJvbSAnLi9lbXBsb3llZS5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBFbXBsb3llZVNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSkgcHJpdmF0ZSBlbXBsb3llZVJlcG9zaXRvcnk6IFJlcG9zaXRvcnk8RW1wbG95ZWVFbnRpdHk+KSB7IH1cblxuXHRhc3luYyBmaW5kQWxsKGNsaW5pY0lkOiBudW1iZXIpOiBQcm9taXNlPEVtcGxveWVlRW50aXR5W10+IHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZCh7IHdoZXJlOiB7IGNsaW5pY0lkIH0gfSlcblx0fVxuXG5cdGFzeW5jIGNyZWF0ZShjbGluaWNJZDogbnVtYmVyLCBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZmluZEVtcGxveWVlID0gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZE9uZUJ5KHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0dXNlcm5hbWU6IGNyZWF0ZUVtcGxveWVlRHRvLnVzZXJuYW1lLFxuXHRcdH0pXG5cdFx0aWYgKGZpbmRFbXBsb3llZSkge1xuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RVc2VybmFtZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHR9XG5cdFx0Y29uc3Qgc25hcEVtcGxveWVlID0gcGxhaW5Ub0NsYXNzKEVtcGxveWVlRW50aXR5LCBjcmVhdGVFbXBsb3llZUR0bylcblx0XHRzbmFwRW1wbG95ZWUucGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaChjcmVhdGVFbXBsb3llZUR0by5wYXNzd29yZCwgNSlcblx0XHRzbmFwRW1wbG95ZWUucm9sZSA9IEVFbXBsb3llZVJvbGUuVXNlclxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5zYXZlKGNyZWF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0YXN5bmMgZmluZE9uZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHR9XG5cblx0YXN5bmMgdXBkYXRlKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIsIHVwZGF0ZUVtcGxveWVlRHRvOiBVcGRhdGVFbXBsb3llZUR0bykge1xuXHRcdGNvbnN0IGZpbmRFbXBsb3llZSA9IGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHRcdGlmICghZmluZEVtcGxveWVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFRW1wbG95ZWVFcnJvci5Ob3RFeGlzdHMsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0fVxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS51cGRhdGUoeyBjbGluaWNJZCwgaWQgfSwgdXBkYXRlRW1wbG95ZWVEdG8pXG5cdH1cblxuXHRhc3luYyByZW1vdmUoY2xpbmljSWQ6IG51bWJlciwgZW1wbG95ZWVJZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LnNvZnREZWxldGUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG5cblx0YXN5bmMgcmVzdG9yZShjbGluaWNJZDogbnVtYmVyLCBlbXBsb3llZUlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkucmVzdG9yZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkOiBlbXBsb3llZUlkLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IENvbnRyb2xsZXIsIEdldCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7XG5cdERpc2tIZWFsdGhJbmRpY2F0b3IsIEhlYWx0aENoZWNrLCBIZWFsdGhDaGVja1NlcnZpY2UsIEh0dHBIZWFsdGhJbmRpY2F0b3IsXG5cdE1lbW9yeUhlYWx0aEluZGljYXRvciwgVHlwZU9ybUhlYWx0aEluZGljYXRvcixcbn0gZnJvbSAnQG5lc3Rqcy90ZXJtaW51cydcblxuQEFwaVRhZ3MoJ0hlYWx0aCcpXG5AQ29udHJvbGxlcignaGVhbHRoJylcbmV4cG9ydCBjbGFzcyBIZWFsdGhDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSByZWFkb25seSBoZWFsdGg6IEhlYWx0aENoZWNrU2VydmljZSxcblx0XHRwcml2YXRlIHJlYWRvbmx5IGh0dHA6IEh0dHBIZWFsdGhJbmRpY2F0b3IsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBkYjogVHlwZU9ybUhlYWx0aEluZGljYXRvcixcblx0XHRwcml2YXRlIHJlYWRvbmx5IGRpc2s6IERpc2tIZWFsdGhJbmRpY2F0b3IsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBtZW1vcnk6IE1lbW9yeUhlYWx0aEluZGljYXRvclxuXHQpIHsgfVxuXG5cdEBHZXQoKVxuXHRASGVhbHRoQ2hlY2soKVxuXHRjaGVjaygpIHtcblx0XHRjb25zdCBwYXRoU3RvcmFnZSA9IHByb2Nlc3MucGxhdGZvcm0gPT09ICd3aW4zMicgPyAnQzpcXFxcJyA6ICcvJ1xuXHRcdGNvbnN0IHRocmVzaG9sZFBlcmNlbnQgPSBwcm9jZXNzLnBsYXRmb3JtID09PSAnd2luMzInID8gMC45IDogMC41XG5cblx0XHRyZXR1cm4gdGhpcy5oZWFsdGguY2hlY2soW1xuXHRcdFx0KCkgPT4gdGhpcy5odHRwLnBpbmdDaGVjaygnbmVzdGpzLWRvY3MnLCAnaHR0cHM6Ly9tZWRpaG9tZS52bi9kb2N1bWVudCcpLFxuXHRcdFx0KCkgPT4gdGhpcy5kYi5waW5nQ2hlY2soJ2RhdGFiYXNlJyksXG5cdFx0XHQoKSA9PiB0aGlzLmRpc2suY2hlY2tTdG9yYWdlKCdzdG9yYWdlJywgeyBwYXRoOiBwYXRoU3RvcmFnZSwgdGhyZXNob2xkUGVyY2VudCB9KSxcblx0XHRcdCgpID0+IHRoaXMubWVtb3J5LmNoZWNrSGVhcCgnbWVtb3J5X2hlYXAnLCAxNTAgKiAxMDI0ICogMTAyNCksXG5cdFx0XHQoKSA9PiB0aGlzLm1lbW9yeS5jaGVja1JTUygnbWVtb3J5X3JzcycsIDE1MCAqIDEwMjQgKiAxMDI0KSxcblx0XHRdKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBIdHRwTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9heGlvcydcbmltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVGVybWludXNNb2R1bGUgfSBmcm9tICdAbmVzdGpzL3Rlcm1pbnVzJ1xuaW1wb3J0IHsgSGVhbHRoQ29udHJvbGxlciB9IGZyb20gJy4vaGVhbHRoLmNvbnRyb2xsZXInXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVGVybWludXNNb2R1bGUsIEh0dHBNb2R1bGVdLFxuXHRjb250cm9sbGVyczogW0hlYWx0aENvbnRyb2xsZXJdLFxufSlcbmV4cG9ydCBjbGFzcyBIZWFsdGhNb2R1bGUgeyB9XG4iLCJleHBvcnQgY2xhc3MgQ3JlYXRlTWVkaWNpbmVEdG8ge31cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2NyZWF0ZS1tZWRpY2luZS5kdG8nXG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVNZWRpY2luZUR0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZU1lZGljaW5lRHRvKSB7fVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgRGVsZXRlLCBHZXQsIFBhcmFtLCBQYXRjaCwgUG9zdCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IENyZWF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vY3JlYXRlLW1lZGljaW5lLmR0bydcbmltcG9ydCB7IFVwZGF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlLW1lZGljaW5lLmR0bydcbmltcG9ydCB7IE1lZGljaW5lU2VydmljZSB9IGZyb20gJy4vbWVkaWNpbmUuc2VydmljZSdcblxuQEFwaVRhZ3MoJ01lZGljaW5lJylcbkBBcGlCZWFyZXJBdXRoKCdhY2Nlc3MtdG9rZW4nKVxuQENvbnRyb2xsZXIoJ21lZGljaW5lJylcbmV4cG9ydCBjbGFzcyBNZWRpY2luZUNvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IG1lZGljaW5lU2VydmljZTogTWVkaWNpbmVTZXJ2aWNlKSB7IH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZU1lZGljaW5lRHRvOiBDcmVhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5jcmVhdGUoY3JlYXRlTWVkaWNpbmVEdG8pXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLmZpbmRPbmUoK2lkKVxuXHR9XG5cblx0QFBhdGNoKCc6aWQnKVxuXHR1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlTWVkaWNpbmVEdG86IFVwZGF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZU1lZGljaW5lRHRvKVxuXHR9XG5cblx0QERlbGV0ZSgnOmlkJylcblx0cmVtb3ZlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBNZWRpY2luZUVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL21lZGljaW5lLmVudGl0eSdcbmltcG9ydCB7IE1lZGljaW5lQ29udHJvbGxlciB9IGZyb20gJy4vbWVkaWNpbmUuY29udHJvbGxlcidcbmltcG9ydCB7IE1lZGljaW5lU2VydmljZSB9IGZyb20gJy4vbWVkaWNpbmUuc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW01lZGljaW5lRW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW01lZGljaW5lQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW01lZGljaW5lU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIE1lZGljaW5lTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTWVkaWNpbmVTZXJ2aWNlIHtcblx0Y3JlYXRlKGNyZWF0ZU1lZGljaW5lRHRvOiBDcmVhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiAnVGhpcyBhY3Rpb24gYWRkcyBhIG5ldyBtZWRpY2luZSdcblx0fVxuXG5cdGZpbmRBbGwoKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGFsbCBtZWRpY2luZWBcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxuXG5cdHVwZGF0ZShpZDogbnVtYmVyLCB1cGRhdGVNZWRpY2luZUR0bzogVXBkYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHVwZGF0ZXMgYSAjJHtpZH0gbWVkaWNpbmVgXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxufVxuIiwiaW1wb3J0IHsgQm9keSwgQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IsIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFF1ZXJ5LCBSZXEsIFVzZUludGVyY2VwdG9ycyB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpUGFyYW0sIEFwaVF1ZXJ5LCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IENyZWF0ZVBhdGllbnREdG8sIFVwZGF0ZVBhdGllbnREdG8gfSBmcm9tICcuL3BhdGllbnQuZHRvJ1xuaW1wb3J0IHsgUGF0aWVudFNlcnZpY2UgfSBmcm9tICcuL3BhdGllbnQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ1BhdGllbnQnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AVXNlSW50ZXJjZXB0b3JzKENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yKVxuQENvbnRyb2xsZXIoJ3BhdGllbnQnKVxuZXhwb3J0IGNsYXNzIFBhdGllbnRDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBwYXRpZW50U2VydmljZTogUGF0aWVudFNlcnZpY2UpIHsgfVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRBbGwoY2xpbmljSWQpXG5cdH1cblxuXHRAR2V0KCdzZWFyY2gnKVxuXHRAQXBpUXVlcnkoeyBuYW1lOiAnc2VhcmNoVGV4dCcsIGV4YW1wbGU6ICcwOTg2MTIzNDU2JyB9KVxuXHRzZWFyY2goQFF1ZXJ5KCdzZWFyY2hUZXh0Jykgc2VhcmNoVGV4dDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRpZiAoL15cXGQrJC8udGVzdChzZWFyY2hUZXh0KSkge1xuXHRcdFx0cmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuZmluZEJ5UGhvbmUoY2xpbmljSWQsIHNlYXJjaFRleHQpXG5cdFx0fVxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRCeUZ1bGxOYW1lKGNsaW5pY0lkLCBzZWFyY2hUZXh0KVxuXHR9XG5cblx0QFBvc3QoKVxuXHRjcmVhdGUoQEJvZHkoKSBjcmVhdGVQYXRpZW50RHRvOiBDcmVhdGVQYXRpZW50RHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS5jcmVhdGUoY2xpbmljSWQsIGNyZWF0ZVBhdGllbnREdG8pXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRPbmUoY2xpbmljSWQsICtpZClcblx0fVxuXG5cdEBQYXRjaCgndXBkYXRlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgdXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAQm9keSgpIHVwZGF0ZVBhdGllbnREdG86IFVwZGF0ZVBhdGllbnREdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMucGF0aWVudFNlcnZpY2UudXBkYXRlKGNsaW5pY0lkLCAraWQsIHVwZGF0ZVBhdGllbnREdG8pXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBEZWxldGUoJ3JlbW92ZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5wYXRpZW50U2VydmljZS5yZW1vdmUoY2xpbmljSWQsICtpZClcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG5cblx0QFBhdGNoKCdyZXN0b3JlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgcmVzdG9yZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5wYXRpZW50U2VydmljZS5yZXN0b3JlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHlPcHRpb25hbCwgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBUeXBlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBJc0RhdGUsIElzRGVmaW5lZCwgSXNFbnVtLCBJc1N0cmluZywgVmFsaWRhdGUgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5pbXBvcnQgeyBFR2VuZGVyIH0gZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9iYXNlLmVudGl0eSdcbmltcG9ydCB7IElzUGhvbmUgfSBmcm9tICcuLi8uLi9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbSdcblxuZXhwb3J0IGNsYXNzIENyZWF0ZVBhdGllbnREdG8ge1xuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICdQaOG6oW0gSG/DoG5nIE1haScgfSlcblx0QElzRGVmaW5lZCgpXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICcwOTg2MTIzNDU2JyB9KVxuXHRAVmFsaWRhdGUoSXNQaG9uZSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogRUdlbmRlci5GZW1hbGUgfSlcblx0QElzRW51bShFR2VuZGVyKVxuXHRnZW5kZXI6IEVHZW5kZXJcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICdUaMOgbmggcGjhu5EgSMOgIE7hu5lpIC0tIFF14bqtbiBMb25nIEJpw6puIC0tIFBoxrDhu51uZyBUaOG6oWNoIELDoG4gLS0gc+G7kSA4IC0gdMOyYSBuaMOgIMSQ4bqjbyBD4bqndSBW4buTbmcnIH0pXG5cdEBJc1N0cmluZygpXG5cdGFkZHJlc3M6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogJzE5OTgtMTEtMjhUMDA6MDA6MDAuMDAwWicgfSlcblx0QFR5cGUoKCkgPT4gRGF0ZSlcblx0QElzRGF0ZSgpXG5cdGJpcnRoZGF5OiBEYXRlXG59XG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVQYXRpZW50RHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlUGF0aWVudER0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgUGF0aWVudEVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL3BhdGllbnQuZW50aXR5J1xuaW1wb3J0IHsgUGF0aWVudENvbnRyb2xsZXIgfSBmcm9tICcuL3BhdGllbnQuY29udHJvbGxlcidcbmltcG9ydCB7IFBhdGllbnRTZXJ2aWNlIH0gZnJvbSAnLi9wYXRpZW50LnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtQYXRpZW50RW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW1BhdGllbnRDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbUGF0aWVudFNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBQYXRpZW50TW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSHR0cFN0YXR1cywgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnMnXG5pbXBvcnQgeyBJbmplY3RSZXBvc2l0b3J5IH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IHsgRXF1YWwsIExpa2UsIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eSdcbmltcG9ydCB7IEVQYXRpZW50RXJyb3IgfSBmcm9tICcuLi8uLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcbmltcG9ydCB7IENyZWF0ZVBhdGllbnREdG8sIFVwZGF0ZVBhdGllbnREdG8gfSBmcm9tICcuL3BhdGllbnQuZHRvJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUGF0aWVudFNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShQYXRpZW50RW50aXR5KSBwcml2YXRlIHBhdGllbnRSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PFBhdGllbnRFbnRpdHk+KSB7IH1cblxuXHRhc3luYyBmaW5kQWxsKGNsaW5pY0lkOiBudW1iZXIpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHsgd2hlcmU6IHsgY2xpbmljSWQgfSB9KVxuXHRcdHJldHVybiBwYXRpZW50TGlzdFxuXHR9XG5cblx0YXN5bmMgY3JlYXRlKGNsaW5pY0lkOiBudW1iZXIsIGNyZWF0ZVBhdGllbnREdG86IENyZWF0ZVBhdGllbnREdG8pOiBQcm9taXNlPFBhdGllbnRFbnRpdHk+IHtcblx0XHRjb25zdCBwYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5zYXZlKHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0Li4uY3JlYXRlUGF0aWVudER0byxcblx0XHR9KVxuXHRcdHJldHVybiBwYXRpZW50XG5cdH1cblxuXHRhc3luYyBmaW5kT25lKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIpIHtcblx0XHRjb25zdCBwYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kT25lQnkoeyBjbGluaWNJZCwgaWQgfSlcblx0XHRyZXR1cm4gcGF0aWVudFxuXHR9XG5cblx0YXN5bmMgZmluZEJ5UGhvbmUoY2xpbmljSWQ6IG51bWJlciwgcGhvbmU6IHN0cmluZyk6IFByb21pc2U8UGF0aWVudEVudGl0eVtdPiB7XG5cdFx0Y29uc3QgcGF0aWVudExpc3QgPSBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LmZpbmQoe1xuXHRcdFx0d2hlcmU6IHtcblx0XHRcdFx0Y2xpbmljSWQ6IEVxdWFsKGNsaW5pY0lkKSxcblx0XHRcdFx0cGhvbmU6IExpa2UoYCR7cGhvbmV9JWApLFxuXHRcdFx0fSxcblx0XHRcdHNraXA6IDAsXG5cdFx0XHR0YWtlOiAxMCxcblx0XHR9KVxuXHRcdHJldHVybiBwYXRpZW50TGlzdFxuXHR9XG5cdGFzeW5jIGZpbmRCeUZ1bGxOYW1lKGNsaW5pY0lkOiBudW1iZXIsIGZ1bGxOYW1lOiBzdHJpbmcpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHtcblx0XHRcdHdoZXJlOiB7XG5cdFx0XHRcdGNsaW5pY0lkOiBFcXVhbChjbGluaWNJZCksXG5cdFx0XHRcdGZ1bGxOYW1lOiBMaWtlKGAke2Z1bGxOYW1lfSVgKSxcblx0XHRcdH0sXG5cdFx0XHRza2lwOiAwLFxuXHRcdFx0dGFrZTogMTAsXG5cdFx0fSlcblx0XHRyZXR1cm4gcGF0aWVudExpc3Rcblx0fVxuXG5cdGFzeW5jIHVwZGF0ZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyLCB1cGRhdGVQYXRpZW50RHRvOiBVcGRhdGVQYXRpZW50RHRvKSB7XG5cdFx0Y29uc3QgZmluZFBhdGllbnQgPSBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHRcdGlmICghZmluZFBhdGllbnQpIHtcblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVQYXRpZW50RXJyb3IuTm90RXhpc3RzLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdH1cblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS51cGRhdGUoeyBjbGluaWNJZCwgaWQgfSwgdXBkYXRlUGF0aWVudER0bylcblx0fVxuXG5cdGFzeW5jIHJlbW92ZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuc29mdERlbGV0ZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkLFxuXHRcdH0pXG5cdH1cblxuXHRhc3luYyByZXN0b3JlKGNsaW5pY0lkOiBudW1iZXIsIGVtcGxveWVlSWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LnJlc3RvcmUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDcmVhdGVEYXRlQ29sdW1uLCBEZWxldGVEYXRlQ29sdW1uLCBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLCBVcGRhdGVEYXRlQ29sdW1uIH0gZnJvbSAndHlwZW9ybSdcblxuZXhwb3J0IGVudW0gRUdlbmRlciB7XG5cdE1hbGUgPSAnTWFsZScsXG5cdEZlbWFsZSA9ICdGZW1hbGUnLFxufVxuXG5leHBvcnQgY2xhc3MgQmFzZUVudGl0eSB7XG5cdEBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uKHsgbmFtZTogJ2lkJyB9KVxuXHRpZDogbnVtYmVyXG5cblx0QENyZWF0ZURhdGVDb2x1bW4oeyBuYW1lOiAnY3JlYXRlZF9hdCcgfSlcblx0Y3JlYXRlZEF0OiBEYXRlXG5cblx0QFVwZGF0ZURhdGVDb2x1bW4oeyBuYW1lOiAndXBkYXRlZF9hdCcgfSlcblx0dXBkYXRlZEF0OiBEYXRlXG5cblx0QERlbGV0ZURhdGVDb2x1bW4oeyBuYW1lOiAnZGVsZXRlZF9hdCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRkZWxldGVkQXQ6IERhdGVcbn1cbiIsImltcG9ydCB7IEV4Y2x1ZGUgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IENvbHVtbiwgRW50aXR5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHkgfSBmcm9tICcuLi9iYXNlLmVudGl0eSdcblxuQEVudGl0eSgnYWRtaXNzaW9uJylcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIEFkbWlzc2lvbkVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QENvbHVtbih7IG5hbWU6ICdwYXRpZW50X2lkJyB9KVxuXHRwYXRpZW50SWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAncmVhc29uJywgbnVsbGFibGU6IHRydWUgfSlcblx0cmVhc29uOiBzdHJpbmcgLy8gTMO9IGRvIHbDoG8gdmnhu4duXG5cblx0QENvbHVtbih7IG5hbWU6ICdtZWRpY2FsX3JlY29yZCcsIHR5cGU6ICd0ZXh0JyB9KVxuXHRtZWRpY2FsUmVjb3JkOiBzdHJpbmcgLy8gVMOzbSB0xIN0IGLhu4duaCDDoW5cblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0ZGlhZ25vc2lzOiBzdHJpbmcgLy8gQ2jhuqluIMSRb8OhblxuXG5cdEBDb2x1bW4oeyB0eXBlOiAndGlueWludCcsIHVuc2lnbmVkOiB0cnVlLCBudWxsYWJsZTogdHJ1ZSB9KSAgICAgICAgICAgICAgIC8vIC0tLS0tIHRpbnlpbnRfdW5zaWduZWQ6IDAgLT4gMjU2XG5cdHB1bHNlOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgdHlwZTogJ2Zsb2F0JywgcHJlY2lzaW9uOiAzLCBzY2FsZTogMSwgbnVsbGFibGU6IHRydWUgfSlcblx0dGVtcGVyYXR1cmU6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnYmxvb2RfcHJlc3N1cmUnLCBsZW5ndGg6IDEwLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRibG9vZFByZXNzdXJlOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgbmFtZTogJ3Jlc3BpcmF0b3J5X3JhdGUnLCB0eXBlOiAndGlueWludCcsIG51bGxhYmxlOiB0cnVlIH0pICAgICAvLyAtLS0tLSB0aW55aW50OiAtMTI4IC0+IDEyN1xuXHRyZXNwaXJhdG9yeVJhdGU6IG51bWJlclxuXG5cdEBDb2x1bW4oeyB0eXBlOiAndGlueWludCcsIG51bGxhYmxlOiB0cnVlIH0pXG5cdHNwTzI6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRub3RlOiBzdHJpbmcgLy8gR2hpIGNow7pcbn1cbiIsImltcG9ydCB7IENvbHVtbiwgRW50aXR5LCBJbmRleCB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5IH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ2NsaW5pYycpXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBDbGluaWNFbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgbGVuZ3RoOiAxMCwgbnVsbGFibGU6IGZhbHNlIH0pXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdW5pcXVlOiB0cnVlLCBudWxsYWJsZTogZmFsc2UgfSlcblx0ZW1haWw6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAndGlueWludCcsIGRlZmF1bHQ6IDEgfSlcblx0bGV2ZWw6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRuYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0YWRkcmVzczogc3RyaW5nXG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDb2x1bW4sIEVudGl0eSwgSW5kZXgsIEpvaW5Db2x1bW4sIE1hbnlUb09uZSB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5LCBFR2VuZGVyIH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4vY2xpbmljLmVudGl0eSdcblxuZXhwb3J0IGVudW0gRUVtcGxveWVlUm9sZSB7XG5cdE93bmVyID0gJ093bmVyJyxcblx0QWRtaW4gPSAnQWRtaW4nLFxuXHRVc2VyID0gJ1VzZXInLFxufVxuXG5leHBvcnQgdHlwZSBURW1wbG95ZWVSb2xlID0ga2V5b2YgdHlwZW9mIEVFbXBsb3llZVJvbGVcblxuQEVudGl0eSgnZW1wbG95ZWUnKVxuQEluZGV4KFsnY2xpbmljSWQnLCAndXNlcm5hbWUnXSwgeyB1bmlxdWU6IHRydWUgfSlcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIEVtcGxveWVlRW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyBuYW1lOiAnY2xpbmljX2lkJyB9KVxuXHRARXhjbHVkZSgpXG5cdGNsaW5pY0lkOiBudW1iZXJcblxuXHRATWFueVRvT25lKHR5cGUgPT4gQ2xpbmljRW50aXR5KVxuXHRASm9pbkNvbHVtbih7IG5hbWU6ICdjbGluaWNfaWQnLCByZWZlcmVuY2VkQ29sdW1uTmFtZTogJ2lkJyB9KVxuXHRjbGluaWM6IENsaW5pY0VudGl0eVxuXG5cdEBDb2x1bW4oeyBsZW5ndGg6IDEwLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QENvbHVtbigpXG5cdHVzZXJuYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKClcblx0QEV4Y2x1ZGUoKVxuXHRwYXNzd29yZDogc3RyaW5nXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUVtcGxveWVlUm9sZSwgZGVmYXVsdDogRUVtcGxveWVlUm9sZS5Vc2VyIH0pXG5cdHJvbGU6IEVFbXBsb3llZVJvbGVcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2Z1bGxfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ2RhdGUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRiaXJ0aGRheTogRGF0ZVxuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IEVHZW5kZXIsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGdlbmRlcjogRUdlbmRlclxufVxuIiwiaW1wb3J0IHsgRW50aXR5LCBDb2x1bW4sIEluZGV4IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHkgfSBmcm9tICcuLi9iYXNlLmVudGl0eSdcblxuQEVudGl0eSgnbWVkaWNpbmUnKVxuQEluZGV4KFsnY2xpbmljSWQnLCAnaWQnXSwgeyB1bmlxdWU6IHRydWUgfSlcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIE1lZGljaW5lRW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyBuYW1lOiAnY2xpbmljX2lkJyB9KVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QENvbHVtbih7IG5hbWU6ICdicmFuZF9uYW1lJywgbnVsbGFibGU6IHRydWUgfSlcblx0YnJhbmROYW1lOiBzdHJpbmcgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyB0w6puIGJp4buHdCBkxrDhu6NjXG5cblx0QENvbHVtbih7IG5hbWU6ICdjaGVtaWNhbF9uYW1lJywgbnVsbGFibGU6IHRydWUgfSlcblx0Y2hlbWljYWxOYW1lOiBzdHJpbmcgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyB0w6puIGfhu5FjXG5cblx0QENvbHVtbih7IG5hbWU6ICdjYWxjdWxhdGlvbl91bml0JywgbnVsbGFibGU6IHRydWUgfSlcblx0Y2FsY3VsYXRpb25Vbml0OiBzdHJpbmcgICAgICAgICAgICAgICAgICAgICAgICAvLyDEkcahbiB24buLIHTDrW5oOiBs4buNLCDhu5FuZywgduG7iVxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnaW1hZ2UnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRpbWFnZTogc3RyaW5nXG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDb2x1bW4sIEVudGl0eSwgSW5kZXggfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSwgRUdlbmRlciB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuXG5ARW50aXR5KCdwYXRpZW50JylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ2Z1bGxOYW1lJ10pXG5ASW5kZXgoWydjbGluaWNJZCcsICdwaG9uZSddKVxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgUGF0aWVudEVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QENvbHVtbih7IG5hbWU6ICdmdWxsX25hbWUnIH0pXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgbGVuZ3RoOiAxMCwgbnVsbGFibGU6IHRydWUgfSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZGF0ZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGJpcnRoZGF5OiBEYXRlXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUdlbmRlciwgbnVsbGFibGU6IHRydWUgfSlcblx0Z2VuZGVyOiBFR2VuZGVyXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGFkZHJlc3M6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnaGVhbHRoX2hpc3RvcnknLCB0eXBlOiAndGV4dCcsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGhlYWx0aEhpc3Rvcnk6IHN0cmluZyAvLyBUaeG7gW4gc+G7rSBi4buHbmhcbn1cbiIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvYXhpb3NcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb24vZGVjb3JhdG9yc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vbi9lbnVtc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uL3NlcmlhbGl6ZXJcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvand0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvc3dhZ2dlclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3Rlcm1pbnVzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdHlwZW9ybVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJiY3J5cHRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdHJhbnNmb3JtZXJcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdmFsaWRhdG9yXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImV4cHJlc3NcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiZXhwcmVzcy1yYXRlLWxpbWl0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImhlbG1ldFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJyZXF1ZXN0LWlwXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInJ4anNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwicnhqcy9vcGVyYXRvcnNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwidHlwZW9ybVwiKTsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiaW1wb3J0IHsgVmFsaWRhdGlvbkVycm9yLCBWYWxpZGF0aW9uUGlwZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnU2VydmljZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgTmVzdEZhY3RvcnksIFJlZmxlY3RvciB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCByYXRlTGltaXQgZnJvbSAnZXhwcmVzcy1yYXRlLWxpbWl0J1xuaW1wb3J0IGhlbG1ldCBmcm9tICdoZWxtZXQnXG5pbXBvcnQgKiBhcyByZXF1ZXN0SXAgZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IEFwcE1vZHVsZSB9IGZyb20gJy4vYXBwLm1vZHVsZSdcbmltcG9ydCB7IHNldHVwU3dhZ2dlciB9IGZyb20gJy4vY29tbW9uL3N3YWdnZXInXG5pbXBvcnQgeyBIdHRwRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy9odHRwLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBVbmtub3duRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy91bmtub3duLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBWYWxpZGF0aW9uRXhjZXB0aW9uLCBWYWxpZGF0aW9uRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy92YWxpZGF0aW9uLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBVc2VyUm9sZXNHdWFyZCB9IGZyb20gJy4vZ3VhcmRzL3VzZXItcm9sZXMuZ3VhcmQnXG5pbXBvcnQgeyBBY2Nlc3NMb2dJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvYWNjZXNzLWxvZy5pbnRlcmNlcHRvcidcbmltcG9ydCB7IFRpbWVvdXRJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvdGltZW91dC5pbnRlcmNlcHRvcidcblxuYXN5bmMgZnVuY3Rpb24gYm9vdHN0cmFwKCkge1xuXHRjb25zdCBhcHAgPSBhd2FpdCBOZXN0RmFjdG9yeS5jcmVhdGUoQXBwTW9kdWxlKVxuXG5cdGNvbnN0IGNvbmZpZ1NlcnZpY2UgPSBhcHAuZ2V0KENvbmZpZ1NlcnZpY2UpXG5cdGNvbnN0IFBPUlQgPSBjb25maWdTZXJ2aWNlLmdldCgnTkVTVEpTX1BPUlQnKVxuXHRjb25zdCBIT1NUID0gY29uZmlnU2VydmljZS5nZXQoJ05FU1RKU19IT1NUJykgfHwgJ2xvY2FsaG9zdCdcblxuXHRhcHAudXNlKGhlbG1ldCgpKVxuXHRhcHAudXNlKHJhdGVMaW1pdCh7XG5cdFx0d2luZG93TXM6IDYwICogMTAwMCwgLy8gMSBtaW51dGVzXG5cdFx0bWF4OiAxMDAsIC8vIGxpbWl0IGVhY2ggSVAgdG8gMTAwIHJlcXVlc3RzIHBlciB3aW5kb3dNc1xuXHR9KSlcblx0YXBwLmVuYWJsZUNvcnMoKVxuXG5cdGFwcC51c2UocmVxdWVzdElwLm13KCkpXG5cblx0YXBwLnVzZUdsb2JhbEludGVyY2VwdG9ycyhcblx0XHRuZXcgQWNjZXNzTG9nSW50ZXJjZXB0b3IoKSxcblx0XHRuZXcgVGltZW91dEludGVyY2VwdG9yKClcblx0KVxuXHRhcHAudXNlR2xvYmFsRmlsdGVycyhcblx0XHRuZXcgVW5rbm93bkV4Y2VwdGlvbkZpbHRlcigpLFxuXHRcdG5ldyBIdHRwRXhjZXB0aW9uRmlsdGVyKCksXG5cdFx0bmV3IFZhbGlkYXRpb25FeGNlcHRpb25GaWx0ZXIoKVxuXHQpXG5cblx0YXBwLnVzZUdsb2JhbEd1YXJkcyhuZXcgVXNlclJvbGVzR3VhcmQoYXBwLmdldChSZWZsZWN0b3IpKSlcblxuXHRhcHAudXNlR2xvYmFsUGlwZXMobmV3IFZhbGlkYXRpb25QaXBlKHtcblx0XHR2YWxpZGF0aW9uRXJyb3I6IHsgdGFyZ2V0OiBmYWxzZSwgdmFsdWU6IHRydWUgfSxcblx0XHRza2lwTWlzc2luZ1Byb3BlcnRpZXM6IHRydWUsIC8vIGtow7RuZyB2YWxpZGF0ZSBuaOG7r25nIHByb3BlcnR5IHVuZGVmaW5lZFxuXHRcdHdoaXRlbGlzdDogdHJ1ZSwgLy8gbG/huqFpIGLhu48gY8OhYyBwcm9wZXJ0eSBraMO0bmcgY8OzIHRyb25nIERUT1xuXHRcdGZvcmJpZE5vbldoaXRlbGlzdGVkOiB0cnVlLCAvLyB4deG6pXQgaGnhu4duIHByb3BlcnR5IGtow7RuZyBjw7MgdHJvbmcgRFRPIHPhur0gYuG6r3QgbOG7l2lcblx0XHR0cmFuc2Zvcm06IHRydWUsIC8vIHPhu60gZOG7pW5nIHRyYW5zZm9ybSBjaG8gY8OhYyBEVE9cblx0XHR0cmFuc2Zvcm1PcHRpb25zOiB7XG5cdFx0XHQvLyBleGNsdWRlRXh0cmFuZW91c1ZhbHVlczogdHJ1ZSwgLy8gbG/huqFpIGLhu48gY8OhYyBwcm9wZXJ0eSBraMO0bmcgY8OzIHRyb25nIERUTyA9PiBrbyBj4bqnbiwgY+G7qSDEkeG7gyDEkeG6pXkgxJHhu4MgdmFsaWRhdGUgYuG6r3QgbOG7l2lcblx0XHRcdGV4cG9zZVVuc2V0RmllbGRzOiBmYWxzZSwgLy8gbG/huqFpIGLhu48gY8OhYyBwcm9wZXJ0eSBjw7MgdHJvbmcgRFRPLCBuaMawbmcga2jDtG5nIHRydXnhu4FuIGzDqm5cblx0XHR9LFxuXHRcdGV4Y2VwdGlvbkZhY3Rvcnk6IChlcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdID0gW10pID0+IG5ldyBWYWxpZGF0aW9uRXhjZXB0aW9uKGVycm9ycyksXG5cdH0pKVxuXG5cdGlmIChjb25maWdTZXJ2aWNlLmdldCgnTk9ERV9FTlYnKSAhPT0gJ3Byb2R1Y3Rpb24nKSB7XG5cdFx0c2V0dXBTd2FnZ2VyKGFwcClcblx0fVxuXG5cdGF3YWl0IGFwcC5saXN0ZW4oUE9SVCwgKCkgPT4ge1xuXHRcdGNvbnNvbGUubG9nKGDwn5qAIFNlcnZlciBkb2N1bWVudDogaHR0cDovLyR7SE9TVH06JHtQT1JUfS9kb2N1bWVudGApXG5cdH0pXG59XG5ib290c3RyYXAoKVxuIl0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9