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

/***/ "./apps/api/src/decorators/ip-request.decorator.ts":
/*!*********************************************************!*\
  !*** ./apps/api/src/decorators/ip-request.decorator.ts ***!
  \*********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IpRequest = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const request_ip_1 = __webpack_require__(/*! request-ip */ "request-ip");
exports.IpRequest = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return (0, request_ip_1.getClientIp)(request);
});


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

/***/ "./apps/api/src/guards/roles.guard.ts":
/*!********************************************!*\
  !*** ./apps/api/src/guards/roles.guard.ts ***!
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
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RolesGuard = exports.Roles = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const Roles = (...roles) => (0, common_1.SetMetadata)('roles_guard', roles);
exports.Roles = Roles;
let RolesGuard = class RolesGuard {
    constructor(reflector) {
        this.reflector = reflector;
    }
    canActivate(context) {
        const requiredRoles = this.reflector.getAllAndOverride('roles_guard', [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!requiredRoles)
            return true;
        const request = context.switchToHttp().getRequest();
        const { role } = request.tokenPayload;
        return requiredRoles.includes(role);
    }
};
RolesGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object])
], RolesGuard);
exports.RolesGuard = RolesGuard;


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
    (0, swagger_1.ApiProperty)({ type: PatientDto }),
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
var _a, _b, _c, _d, _e, _f, _g, _h, _j;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const ip_request_decorator_1 = __webpack_require__(/*! ../../decorators/ip-request.decorator */ "./apps/api/src/decorators/ip-request.decorator.ts");
const auth_dto_1 = __webpack_require__(/*! ./auth.dto */ "./apps/api/src/modules/auth/auth.dto.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./apps/api/src/modules/auth/auth.service.ts");
const jwt_extend_service_1 = __webpack_require__(/*! ./jwt-extend.service */ "./apps/api/src/modules/auth/jwt-extend.service.ts");
let AuthController = class AuthController {
    constructor(authService, jwtExtendService) {
        this.authService = authService;
        this.jwtExtendService = jwtExtendService;
    }
    async register(registerDto, ip) {
        const employee = await this.authService.register(registerDto);
        const { accessToken, refreshToken } = this.jwtExtendService.createTokenFromUser(employee, ip);
        return new auth_dto_1.TokensResponse({ accessToken, refreshToken });
    }
    async login(loginDto, ip) {
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
    async grantAccessToken(refreshTokenDto, ip) {
        const accessToken = await this.authService.grantAccessToken(refreshTokenDto.refreshToken, ip);
        return new auth_dto_1.TokensResponse({ accessToken });
    }
};
__decorate([
    (0, common_1.Post)('register'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, ip_request_decorator_1.IpRequest)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof auth_dto_1.RegisterDto !== "undefined" && auth_dto_1.RegisterDto) === "function" ? _c : Object, String]),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, ip_request_decorator_1.IpRequest)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_e = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _e : Object, String]),
    __metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
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
    __metadata("design:paramtypes", [String, typeof (_g = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _g : Object]),
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
    __param(1, (0, ip_request_decorator_1.IpRequest)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_h = typeof auth_dto_1.RefreshTokenDto !== "undefined" && auth_dto_1.RefreshTokenDto) === "function" ? _h : Object, String]),
    __metadata("design:returntype", typeof (_j = typeof Promise !== "undefined" && Promise) === "function" ? _j : Object)
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
                role: employee_entity_1.ERole.Owner,
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
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const employee_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/employee.entity */ "./typeorm/entities/employee.entity.ts");
const constants_1 = __webpack_require__(/*! ../../common/constants */ "./apps/api/src/common/constants.ts");
const roles_guard_1 = __webpack_require__(/*! ../../guards/roles.guard */ "./apps/api/src/guards/roles.guard.ts");
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
    (0, roles_guard_1.Roles)(employee_entity_1.ERole.Admin, employee_entity_1.ERole.Owner),
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
        snapEmployee.role = employee_entity_1.ERole.User;
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
exports.ERole = void 0;
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../base.entity */ "./typeorm/base.entity.ts");
const clinic_entity_1 = __webpack_require__(/*! ./clinic.entity */ "./typeorm/entities/clinic.entity.ts");
var ERole;
(function (ERole) {
    ERole["Owner"] = "Owner";
    ERole["Admin"] = "Admin";
    ERole["User"] = "User";
})(ERole = exports.ERole || (exports.ERole = {}));
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
    (0, typeorm_1.Column)({ type: 'enum', enum: ERole, default: ERole.User }),
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
const roles_guard_1 = __webpack_require__(/*! ./guards/roles.guard */ "./apps/api/src/guards/roles.guard.ts");
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
    app.useGlobalGuards(new roles_guard_1.RolesGuard(app.get(core_1.Reflector)));
    app.useGlobalPipes(new common_1.ValidationPipe({
        validationError: { target: false, value: true },
        skipMissingProperties: true,
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        transformOptions: {
            excludeExtraneousValues: false,
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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QUFrQixFQUFFLENBQ3hCO0lBQ0QsR0FBRyxDQUFDLGdCQUFnQixDQUNuQixJQUFJLGlEQUFzQixFQUFFLEVBQzVCLElBQUksMkNBQW1CLEVBQUUsRUFDekIsSUFBSSx1REFBeUIsRUFBRSxDQUMvQjtJQUVELEdBQUcsQ0FBQyxlQUFlLENBQUMsSUFBSSx3QkFBVSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsZ0JBQVMsQ0FBQyxDQUFDLENBQUM7SUFFdkQsR0FBRyxDQUFDLGNBQWMsQ0FBQyxJQUFJLHVCQUFjLENBQUM7UUFDckMsZUFBZSxFQUFFLEVBQUUsTUFBTSxFQUFFLEtBQUssRUFBRSxLQUFLLEVBQUUsSUFBSSxFQUFFO1FBQy9DLHFCQUFxQixFQUFFLElBQUk7UUFDM0IsU0FBUyxFQUFFLElBQUk7UUFDZixvQkFBb0IsRUFBRSxJQUFJO1FBQzFCLFNBQVMsRUFBRSxJQUFJO1FBQ2YsZ0JBQWdCLEVBQUU7WUFDakIsdUJBQXVCLEVBQUUsS0FBSztZQUM5QixpQkFBaUIsRUFBRSxLQUFLO1NBQ3hCO1FBQ0QsZ0JBQWdCLEVBQUUsQ0FBQyxTQUE0QixFQUFFLEVBQUUsRUFBRSxDQUFDLElBQUksaURBQW1CLENBQUMsTUFBTSxDQUFDO0tBQ3JGLENBQUMsQ0FBQztJQUVILElBQUksYUFBYSxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsS0FBSyxZQUFZLEVBQUU7UUFDbkQsMEJBQVksRUFBQyxHQUFHLENBQUM7S0FDakI7SUFFRCxNQUFNLEdBQUcsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLEdBQUcsRUFBRTtRQUMzQixPQUFPLENBQUMsR0FBRyxDQUFDLDhCQUE4QixJQUFJLElBQUksSUFBSSxXQUFXLENBQUM7SUFDbkUsQ0FBQyxDQUFDO0FBQ0gsQ0FBQztBQUNELFNBQVMsRUFBRSIsInNvdXJjZXMiOlsid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9hcHAubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvY29tbW9uL3N3YWdnZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2RlY29yYXRvcnMvaXAtcmVxdWVzdC5kZWNvcmF0b3IudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2Vudmlyb25tZW50cy50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2V4Y2VwdGlvbi1maWx0ZXJzL2h0dHAtZXhjZXB0aW9uLmZpbHRlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvdW5rbm93bi1leGNlcHRpb24uZmlsdGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy92YWxpZGF0aW9uLWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2d1YXJkcy9yb2xlcy5ndWFyZC50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvaW50ZXJjZXB0b3IvYWNjZXNzLWxvZy5pbnRlcmNlcHRvci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvaW50ZXJjZXB0b3IvdGltZW91dC5pbnRlcmNlcHRvci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbWlkZGxld2FyZS9sb2dnZXIubWlkZGxld2FyZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbWlkZGxld2FyZS92YWxpZGF0ZS1hY2Nlc3MtdG9rZW4ubWlkZGxld2FyZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hZG1pc3Npb24vYWRtaXNzaW9uLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYWRtaXNzaW9uL2FkbWlzc2lvbi5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYWRtaXNzaW9uL2FkbWlzc2lvbi5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYWRtaXNzaW9uL2FkbWlzc2lvbi5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGguc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2p3dC1leHRlbmQuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvY2xpbmljL2NsaW5pYy5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvY2xpbmljL2NsaW5pYy5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvY2xpbmljL2NsaW5pYy5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2hlYWx0aC9oZWFsdGguY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9oZWFsdGgvaGVhbHRoLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9kdG8vY3JlYXRlLW1lZGljaW5lLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9kdG8vdXBkYXRlLW1lZGljaW5lLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9tZWRpY2luZS5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9tZWRpY2luZS9tZWRpY2luZS5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL3BhdGllbnQvcGF0aWVudC5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL3BhdGllbnQvcGF0aWVudC5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50Lm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L3BhdGllbnQuc2VydmljZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2Jhc2UuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvYWRtaXNzaW9uLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2VudGl0aWVzL2NsaW5pYy5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9lbnRpdGllcy9tZWRpY2luZS5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2F4aW9zXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb25cIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbW1vbi9lbnVtc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbmZpZ1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29yZVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvand0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9zd2FnZ2VyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy90ZXJtaW51c1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvdHlwZW9ybVwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImJjcnlwdFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcImNsYXNzLXRyYW5zZm9ybWVyXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiY2xhc3MtdmFsaWRhdG9yXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiZXhwcmVzcy1yYXRlLWxpbWl0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiaGVsbWV0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwicmVxdWVzdC1pcFwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInJ4anNcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJyeGpzL29wZXJhdG9yc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInR5cGVvcm1cIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21haW4udHMiXSwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IsIE1pZGRsZXdhcmVDb25zdW1lciwgTW9kdWxlLCBOZXN0TW9kdWxlLCBSZXF1ZXN0TWV0aG9kIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUsIENvbmZpZ1R5cGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEFQUF9JTlRFUkNFUFRPUiB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IE1hcmlhZGJDb25maWcgfSBmcm9tICcuL2Vudmlyb25tZW50cydcbmltcG9ydCB7IExvZ2dlck1pZGRsZXdhcmUgfSBmcm9tICcuL21pZGRsZXdhcmUvbG9nZ2VyLm1pZGRsZXdhcmUnXG5pbXBvcnQgeyBWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSB9IGZyb20gJy4vbWlkZGxld2FyZS92YWxpZGF0ZS1hY2Nlc3MtdG9rZW4ubWlkZGxld2FyZSdcbmltcG9ydCB7IEFkbWlzc2lvbk1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9hZG1pc3Npb24vYWRtaXNzaW9uLm1vZHVsZSdcbmltcG9ydCB7IEF1dGhNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvYXV0aC9hdXRoLm1vZHVsZSdcbmltcG9ydCB7IENsaW5pY01vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9jbGluaWMvY2xpbmljLm1vZHVsZSdcbmltcG9ydCB7IEVtcGxveWVlTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLm1vZHVsZSdcbmltcG9ydCB7IEhlYWx0aE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9oZWFsdGgvaGVhbHRoLm1vZHVsZSdcbmltcG9ydCB7IE1lZGljaW5lTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLm1vZHVsZSdcbmltcG9ydCB7IFBhdGllbnRNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvcGF0aWVudC9wYXRpZW50Lm1vZHVsZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtcblx0XHRDb25maWdNb2R1bGUuZm9yUm9vdCh7XG5cdFx0XHRlbnZGaWxlUGF0aDogW2AuZW52LiR7cHJvY2Vzcy5lbnYuTk9ERV9FTlYgfHwgJ2xvY2FsJ31gLCAnLmVudiddLFxuXHRcdFx0aXNHbG9iYWw6IHRydWUsXG5cdFx0fSksXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JSb290QXN5bmMoe1xuXHRcdFx0aW1wb3J0czogW0NvbmZpZ01vZHVsZS5mb3JGZWF0dXJlKE1hcmlhZGJDb25maWcpXSxcblx0XHRcdGluamVjdDogW01hcmlhZGJDb25maWcuS0VZXSxcblx0XHRcdHVzZUZhY3Rvcnk6IChtYXJpYWRiQ29uZmlnOiBDb25maWdUeXBlPHR5cGVvZiBNYXJpYWRiQ29uZmlnPikgPT4gbWFyaWFkYkNvbmZpZyxcblx0XHRcdC8vIGluamVjdDogW0NvbmZpZ1NlcnZpY2VdLFxuXHRcdFx0Ly8gdXNlRmFjdG9yeTogKGNvbmZpZ1NlcnZpY2U6IENvbmZpZ1NlcnZpY2UpID0+IGNvbmZpZ1NlcnZpY2UuZ2V0KCdteXNxbCcpLFxuXHRcdH0pLFxuXHRcdEhlYWx0aE1vZHVsZSxcblx0XHRBdXRoTW9kdWxlLFxuXHRcdEFkbWlzc2lvbk1vZHVsZSxcblx0XHRFbXBsb3llZU1vZHVsZSxcblx0XHRQYXRpZW50TW9kdWxlLFxuXHRcdENsaW5pY01vZHVsZSxcblx0XHRNZWRpY2luZU1vZHVsZSxcblx0XSxcblx0cHJvdmlkZXJzOiBbXG5cdFx0e1xuXHRcdFx0cHJvdmlkZTogQVBQX0lOVEVSQ0VQVE9SLFxuXHRcdFx0dXNlQ2xhc3M6IENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yLFxuXHRcdH0sXG5cdF0sXG59KVxuZXhwb3J0IGNsYXNzIEFwcE1vZHVsZSBpbXBsZW1lbnRzIE5lc3RNb2R1bGUge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2UpIHsgfVxuXHRjb25maWd1cmUoY29uc3VtZXI6IE1pZGRsZXdhcmVDb25zdW1lcikge1xuXHRcdGNvbnN1bWVyLmFwcGx5KExvZ2dlck1pZGRsZXdhcmUpLmZvclJvdXRlcygnKicpXG5cblx0XHRjb25zdW1lci5hcHBseShWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSlcblx0XHRcdC5leGNsdWRlKFxuXHRcdFx0XHQnYXV0aC8oLiopJyxcblx0XHRcdFx0Jy8nLFxuXHRcdFx0XHR7IHBhdGg6ICdoZWFsdGgnLCBtZXRob2Q6IFJlcXVlc3RNZXRob2QuR0VUIH1cblx0XHRcdClcblx0XHRcdC5mb3JSb3V0ZXMoJyonKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBWYWxpZGF0b3JDb25zdHJhaW50LCBWYWxpZGF0b3JDb25zdHJhaW50SW50ZXJmYWNlLCBWYWxpZGF0aW9uQXJndW1lbnRzIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5AVmFsaWRhdG9yQ29uc3RyYWludCh7IG5hbWU6ICdpc1Bob25lJywgYXN5bmM6IGZhbHNlIH0pXG5leHBvcnQgY2xhc3MgSXNQaG9uZSBpbXBsZW1lbnRzIFZhbGlkYXRvckNvbnN0cmFpbnRJbnRlcmZhY2Uge1xuXHR2YWxpZGF0ZSh0ZXh0OiBzdHJpbmcsIGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRpZiAodHlwZW9mIHRleHQgIT09ICdzdHJpbmcnIHx8IHRleHQubGVuZ3RoICE9PSAxMCkgcmV0dXJuIGZhbHNlXG5cdFx0cmV0dXJuIC8oKDA5fDAzfDA3fDA4fDA1KSsoWzAtOV17OH0pXFxiKS9nLnRlc3QodGV4dClcblx0fVxuXG5cdGRlZmF1bHRNZXNzYWdlKGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRyZXR1cm4gJyRwcm9wZXJ0eSBtdXN0IGJlIHJlYWwgcGhvbmUgbnVtYmVyICEnXG5cdH1cbn1cblxuQFZhbGlkYXRvckNvbnN0cmFpbnQoeyBuYW1lOiAnaXNHbWFpbCcsIGFzeW5jOiBmYWxzZSB9KVxuZXhwb3J0IGNsYXNzIElzR21haWwgaW1wbGVtZW50cyBWYWxpZGF0b3JDb25zdHJhaW50SW50ZXJmYWNlIHtcblx0dmFsaWRhdGUodGV4dDogc3RyaW5nLCBhcmdzOiBWYWxpZGF0aW9uQXJndW1lbnRzKSB7XG5cdFx0aWYgKHR5cGVvZiB0ZXh0ICE9PSAnc3RyaW5nJykgcmV0dXJuIGZhbHNlXG5cdFx0cmV0dXJuIC9eKFthLXpBLVowLTldfFxcLnwtfF8pKyhAZ21haWwuY29tKSQvLnRlc3QodGV4dClcblx0fVxuXG5cdGRlZmF1bHRNZXNzYWdlKGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRyZXR1cm4gJyRwcm9wZXJ0eSBtdXN0IGJlIGEgZ21haWwgYWRkcmVzcyAhJ1xuXHR9XG59XG4iLCJpbXBvcnQgeyBJTmVzdEFwcGxpY2F0aW9uIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBTd2FnZ2VyTW9kdWxlLCBEb2N1bWVudEJ1aWxkZXIgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5cbmV4cG9ydCBjb25zdCBzZXR1cFN3YWdnZXIgPSAoYXBwOiBJTmVzdEFwcGxpY2F0aW9uKSA9PiB7XG5cdGNvbnN0IGNvbmZpZyA9IG5ldyBEb2N1bWVudEJ1aWxkZXIoKVxuXHRcdC5zZXRUaXRsZSgnU2ltcGxlIEFQSScpXG5cdFx0LnNldERlc2NyaXB0aW9uKCdNZWRpaG9tZSBBUEkgdXNlIFN3YWdnZXInKVxuXHRcdC5zZXRWZXJzaW9uKCcxLjAnKVxuXHRcdC5hZGRCZWFyZXJBdXRoKFxuXHRcdFx0eyB0eXBlOiAnaHR0cCcsIGRlc2NyaXB0aW9uOiAnQWNjZXNzIHRva2VuJyB9LFxuXHRcdFx0J2FjY2Vzcy10b2tlbidcblx0XHQpXG5cdFx0LmJ1aWxkKClcblx0Y29uc3QgZG9jdW1lbnQgPSBTd2FnZ2VyTW9kdWxlLmNyZWF0ZURvY3VtZW50KGFwcCwgY29uZmlnKVxuXHRTd2FnZ2VyTW9kdWxlLnNldHVwKCdkb2N1bWVudCcsIGFwcCwgZG9jdW1lbnQpXG59XG4iLCJpbXBvcnQgeyBjcmVhdGVQYXJhbURlY29yYXRvciwgRXhlY3V0aW9uQ29udGV4dCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCB9IGZyb20gJ2V4cHJlc3MnXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5cbmV4cG9ydCBjb25zdCBJcFJlcXVlc3QgPSBjcmVhdGVQYXJhbURlY29yYXRvcigoZGF0YTogdW5rbm93biwgY3R4OiBFeGVjdXRpb25Db250ZXh0KSA9PiB7XG5cdGNvbnN0IHJlcXVlc3Q6IFJlcXVlc3QgPSBjdHguc3dpdGNoVG9IdHRwKCkuZ2V0UmVxdWVzdCgpXG5cdHJldHVybiBnZXRDbGllbnRJcChyZXF1ZXN0KVxufSlcbiIsImltcG9ydCB7IHJlZ2lzdGVyQXMgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGVPcHRpb25zIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuXG5leHBvcnQgY29uc3QgSnd0Q29uZmlnID0gcmVnaXN0ZXJBcygnand0JywgKCkgPT4gKHtcblx0YWNjZXNzS2V5OiBwcm9jZXNzLmVudi5KV1RfQUNDRVNTX0tFWSxcblx0cmVmcmVzaEtleTogcHJvY2Vzcy5lbnYuSldUX1JFRlJFU0hfS0VZLFxuXHRhY2Nlc3NUaW1lOiBOdW1iZXIocHJvY2Vzcy5lbnYuSldUX0FDQ0VTU19USU1FKSxcblx0cmVmcmVzaFRpbWU6IE51bWJlcihwcm9jZXNzLmVudi5KV1RfUkVGUkVTSF9USU1FKSxcbn0pKVxuXG5leHBvcnQgY29uc3QgTWFyaWFkYkNvbmZpZyA9IHJlZ2lzdGVyQXMoJ21hcmlhZGInLCAoKTogVHlwZU9ybU1vZHVsZU9wdGlvbnMgPT4gKHtcblx0dHlwZTogJ21hcmlhZGInLFxuXHRob3N0OiBwcm9jZXNzLmVudi5NQVJJQURCX0hPU1QsXG5cdHBvcnQ6IHBhcnNlSW50KHByb2Nlc3MuZW52Lk1BUklBREJfUE9SVCwgMTApLFxuXHRkYXRhYmFzZTogcHJvY2Vzcy5lbnYuTUFSSUFEQl9EQVRBQkFTRSxcblx0dXNlcm5hbWU6IHByb2Nlc3MuZW52Lk1BUklBREJfVVNFUk5BTUUsXG5cdHBhc3N3b3JkOiBwcm9jZXNzLmVudi5NQVJJQURCX1BBU1NXT1JELFxuXHRhdXRvTG9hZEVudGl0aWVzOiB0cnVlLFxuXHQvLyBsb2dnaW5nOiBwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nLFxuXHRzeW5jaHJvbml6ZTogcHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdsb2NhbCcsXG59KSlcbiIsImV4cG9ydCBlbnVtIEVFcnJvciB7XG5cdFVua25vd24gPSAnQTAwLlVOS05PV04nXG59XG5cbmV4cG9ydCBlbnVtIEVWYWxpZGF0ZUVycm9yIHtcblx0RmFpbGVkID0gJ1YwMC5WQUxJREFURV9GQUlMRUQnXG59XG5cbmV4cG9ydCBlbnVtIEVSZWdpc3RlckVycm9yIHtcblx0RXhpc3RFbWFpbEFuZFBob25lID0gJ1IwMS5FWElTVF9FTUFJTF9BTkRfUEhPTkUnLFxuXHRFeGlzdEVtYWlsID0gJ1IwMi5FWElTVF9FTUFJTCcsXG5cdEV4aXN0UGhvbmUgPSAnUjAzLkVYSVNUX1BIT05FJyxcblx0RXhpc3RVc2VybmFtZSA9ICdSMDQuRVhJU1RfVVNFUk5BTUUnXG59XG5cbmV4cG9ydCBlbnVtIEVMb2dpbkVycm9yIHtcblx0RW1wbG95ZWVEb2VzTm90RXhpc3QgPSAnTDAxLkVNUExPWUVFX0RPRVNfTk9UX0VYSVNUJyxcblx0V3JvbmdQYXNzd29yZCA9ICdMMDIuV1JPTkdfUEFTU1dPUkQnXG59XG5cbmV4cG9ydCBlbnVtIEVUb2tlbkVycm9yIHtcblx0RXhwaXJlZCA9ICdUMDEuRVhQSVJFRCcsXG5cdEludmFsaWQgPSAnVDAyLklOVkFMSUQnXG59XG5cbmV4cG9ydCBlbnVtIEVFbXBsb3llZUVycm9yIHtcblx0VXNlcm5hbWVFeGlzdHMgPSAnVTAxLlVTRVJOQU1FX0VYSVNUUycsXG5cdE5vdEV4aXN0cyA9ICdVMDIuRU1QTE9ZRUVfRE9FU19OT1RfRVhJU1QnXG59XG5cbmV4cG9ydCBlbnVtIEVQYXRpZW50RXJyb3Ige1xuXHROb3RFeGlzdHMgPSAnUDAxLlBBVElFTlRfRE9FU19OT1RfRVhJU1QnXG59XG4iLCJpbXBvcnQgeyBFeGNlcHRpb25GaWx0ZXIsIENhdGNoLCBBcmd1bWVudHNIb3N0LCBIdHRwRXhjZXB0aW9uIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5cbkBDYXRjaChIdHRwRXhjZXB0aW9uKVxuZXhwb3J0IGNsYXNzIEh0dHBFeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjYXRjaChleGNlcHRpb246IEh0dHBFeGNlcHRpb24sIGhvc3Q6IEFyZ3VtZW50c0hvc3QpIHtcblx0XHRjb25zdCBjdHggPSBob3N0LnN3aXRjaFRvSHR0cCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVzcG9uc2U8UmVzcG9uc2U+KClcblx0XHRjb25zdCByZXF1ZXN0ID0gY3R4LmdldFJlcXVlc3Q8UmVxdWVzdD4oKVxuXHRcdGNvbnN0IGh0dHBTdGF0dXMgPSBleGNlcHRpb24uZ2V0U3RhdHVzKClcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlOiBleGNlcHRpb24uZ2V0UmVzcG9uc2UoKSxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXJndW1lbnRzSG9zdCwgQ2F0Y2gsIEV4Y2VwdGlvbkZpbHRlciwgSHR0cFN0YXR1cywgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5cbkBDYXRjaChFcnJvcilcbmV4cG9ydCBjbGFzcyBVbmtub3duRXhjZXB0aW9uRmlsdGVyIGltcGxlbWVudHMgRXhjZXB0aW9uRmlsdGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBsb2dnZXIgPSBuZXcgTG9nZ2VyKCdTRVJWRVJfRVJST1InKSkgeyB9XG5cblx0Y2F0Y2goZXhjZXB0aW9uOiBFcnJvciwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SXG5cblx0XHR0aGlzLmxvZ2dlci5lcnJvcihleGNlcHRpb24uc3RhY2spXG5cblx0XHRyZXNwb25zZS5zdGF0dXMoaHR0cFN0YXR1cykuanNvbih7XG5cdFx0XHRodHRwU3RhdHVzLFxuXHRcdFx0bWVzc2FnZTogZXhjZXB0aW9uLm1lc3NhZ2UsXG5cdFx0XHRwYXRoOiByZXF1ZXN0LnVybCxcblx0XHRcdHRpbWVzdGFtcDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IEFyZ3VtZW50c0hvc3QsIENhdGNoLCBFeGNlcHRpb25GaWx0ZXIsIEh0dHBTdGF0dXMsIFZhbGlkYXRpb25FcnJvciB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UgfSBmcm9tICdleHByZXNzJ1xuaW1wb3J0IHsgRVZhbGlkYXRlRXJyb3IgfSBmcm9tICcuL2V4Y2VwdGlvbi5lbnVtJ1xuXG5leHBvcnQgY2xhc3MgVmFsaWRhdGlvbkV4Y2VwdGlvbiBleHRlbmRzIEVycm9yIHtcblx0cHJpdmF0ZSByZWFkb25seSBlcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdXG5cdGNvbnN0cnVjdG9yKHZhbGlkYXRpb25FcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdID0gW10pIHtcblx0XHRzdXBlcihFVmFsaWRhdGVFcnJvci5GYWlsZWQpXG5cdFx0dGhpcy5lcnJvcnMgPSB2YWxpZGF0aW9uRXJyb3JzXG5cdH1cblx0Z2V0TWVzc2FnZSgpIHtcblx0XHRyZXR1cm4gdGhpcy5tZXNzYWdlXG5cdH1cblx0Z2V0RXJyb3JzKCkge1xuXHRcdHJldHVybiB0aGlzLmVycm9yc1xuXHR9XG59XG5cbkBDYXRjaChWYWxpZGF0aW9uRXhjZXB0aW9uKVxuZXhwb3J0IGNsYXNzIFZhbGlkYXRpb25FeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjYXRjaChleGNlcHRpb246IFZhbGlkYXRpb25FeGNlcHRpb24sIGhvc3Q6IEFyZ3VtZW50c0hvc3QpIHtcblx0XHRjb25zdCBjdHggPSBob3N0LnN3aXRjaFRvSHR0cCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVzcG9uc2U8UmVzcG9uc2U+KClcblx0XHRjb25zdCByZXF1ZXN0ID0gY3R4LmdldFJlcXVlc3Q8UmVxdWVzdD4oKVxuXHRcdGNvbnN0IGh0dHBTdGF0dXMgPSBIdHRwU3RhdHVzLlVOUFJPQ0VTU0FCTEVfRU5USVRZXG5cdFx0Y29uc3QgbWVzc2FnZSA9IGV4Y2VwdGlvbi5nZXRNZXNzYWdlKClcblx0XHRjb25zdCBlcnJvcnMgPSBleGNlcHRpb24uZ2V0RXJyb3JzKClcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlLFxuXHRcdFx0ZXJyb3JzLFxuXHRcdFx0cGF0aDogcmVxdWVzdC51cmwsXG5cdFx0XHR0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDYW5BY3RpdmF0ZSwgRXhlY3V0aW9uQ29udGV4dCwgSW5qZWN0YWJsZSwgU2V0TWV0YWRhdGEgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlZmxlY3RvciB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCB7IEVSb2xlIH0gZnJvbSAnLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuXG5leHBvcnQgY29uc3QgUm9sZXMgPSAoLi4ucm9sZXM6IEVSb2xlW10pID0+IFNldE1ldGFkYXRhKCdyb2xlc19ndWFyZCcsIHJvbGVzKVxuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUm9sZXNHdWFyZCBpbXBsZW1lbnRzIENhbkFjdGl2YXRlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWZsZWN0b3I6IFJlZmxlY3RvcikgeyB9XG5cblx0Y2FuQWN0aXZhdGUoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCk6IGJvb2xlYW4ge1xuXHRcdGNvbnN0IHJlcXVpcmVkUm9sZXMgPSB0aGlzLnJlZmxlY3Rvci5nZXRBbGxBbmRPdmVycmlkZTxFUm9sZVtdPigncm9sZXNfZ3VhcmQnLCBbXG5cdFx0XHRjb250ZXh0LmdldEhhbmRsZXIoKSxcblx0XHRcdGNvbnRleHQuZ2V0Q2xhc3MoKSxcblx0XHRdKVxuXHRcdGlmICghcmVxdWlyZWRSb2xlcykgcmV0dXJuIHRydWVcblxuXHRcdGNvbnN0IHJlcXVlc3Q6IFJlcXVlc3RUb2tlbiA9IGNvbnRleHQuc3dpdGNoVG9IdHRwKCkuZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgeyByb2xlIH0gPSByZXF1ZXN0LnRva2VuUGF5bG9hZFxuXG5cdFx0cmV0dXJuIHJlcXVpcmVkUm9sZXMuaW5jbHVkZXMocm9sZSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQ2FsbEhhbmRsZXIsIEV4ZWN1dGlvbkNvbnRleHQsIEluamVjdGFibGUsIE5lc3RJbnRlcmNlcHRvciwgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcydcbmltcG9ydCB7IHRhcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQWNjZXNzTG9nSW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ0FDQ0VTU19MT0cnKSkgeyB9XG5cblx0aW50ZXJjZXB0KGNvbnRleHQ6IEV4ZWN1dGlvbkNvbnRleHQsIG5leHQ6IENhbGxIYW5kbGVyKTogT2JzZXJ2YWJsZTxhbnk+IHtcblx0XHRjb25zdCBzdGFydFRpbWUgPSBuZXcgRGF0ZSgpXG5cdFx0Y29uc3QgY3R4ID0gY29udGV4dC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVxdWVzdCgpXG5cblx0XHRjb25zdCB7IHVybCwgbWV0aG9kIH0gPSByZXF1ZXN0XG5cdFx0Y29uc3QgeyBzdGF0dXNDb2RlIH0gPSByZXNwb25zZVxuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxdWVzdClcblxuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUodGFwKCgpID0+IHtcblx0XHRcdGNvbnN0IG1zZyA9IGAke3N0YXJ0VGltZS50b0lTT1N0cmluZygpfSB8ICR7aXB9IHwgJHttZXRob2R9IHwgJHtzdGF0dXNDb2RlfSB8ICR7dXJsfSB8ICR7RGF0ZS5ub3coKSAtIHN0YXJ0VGltZS5nZXRUaW1lKCl9bXNgXG5cdFx0XHRyZXR1cm4gdGhpcy5sb2dnZXIubG9nKG1zZylcblx0XHR9KSlcblx0fVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmVzdEludGVyY2VwdG9yLCBFeGVjdXRpb25Db250ZXh0LCBDYWxsSGFuZGxlciwgUmVxdWVzdFRpbWVvdXRFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IE9ic2VydmFibGUsIHRocm93RXJyb3IsIFRpbWVvdXRFcnJvciB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBjYXRjaEVycm9yLCB0aW1lb3V0IH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBUaW1lb3V0SW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRpbnRlcmNlcHQoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCwgbmV4dDogQ2FsbEhhbmRsZXIpOiBPYnNlcnZhYmxlPGFueT4ge1xuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUoXG5cdFx0XHR0aW1lb3V0KDEwMDAwKSxcblx0XHRcdGNhdGNoRXJyb3IoZXJyID0+IHtcblx0XHRcdFx0aWYgKGVyciBpbnN0YW5jZW9mIFRpbWVvdXRFcnJvcikge1xuXHRcdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IG5ldyBSZXF1ZXN0VGltZW91dEV4Y2VwdGlvbigpKVxuXHRcdFx0XHR9XG5cdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IGVycilcblx0XHRcdH0pXG5cdFx0KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZXN0TWlkZGxld2FyZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gJ2V4cHJlc3MnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBMb2dnZXJNaWRkbGV3YXJlIGltcGxlbWVudHMgTmVzdE1pZGRsZXdhcmUge1xuXHR1c2UocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pIHtcblx0XHRjb25zb2xlLmxvZygnUmVxdWVzdC4uLicpXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUsIE5lc3RNaWRkbGV3YXJlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBOZXh0RnVuY3Rpb24sIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcbmltcG9ydCB7IGdldENsaWVudElwIH0gZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IElKd3RQYXlsb2FkLCBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4uL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSBpbXBsZW1lbnRzIE5lc3RNaWRkbGV3YXJlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlKSB7IH1cblxuXHRhc3luYyB1c2UocmVxOiBSZXF1ZXN0VG9rZW4sIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikge1xuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxKVxuXHRcdGNvbnN0IGF1dGhvcml6YXRpb24gPSByZXEuaGVhZGVyKCdBdXRob3JpemF0aW9uJykgfHwgJydcblx0XHRjb25zdCBbLCBhY2Nlc3NUb2tlbl0gPSBhdXRob3JpemF0aW9uLnNwbGl0KCcgJylcblx0XHRjb25zdCBkZWNvZGU6IElKd3RQYXlsb2FkID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuLCBpcClcblx0XHRyZXEudG9rZW5QYXlsb2FkID0gZGVjb2RlXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFJlcSwgU2VyaWFsaXplT3B0aW9ucyB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IFJlcXVlc3RUb2tlbiB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnXG5pbXBvcnQgeyBDcmVhdGVBZG1pc3Npb25EdG8sIFVwZGF0ZUFkbWlzc2lvbkR0byB9IGZyb20gJy4vYWRtaXNzaW9uLmR0bydcbmltcG9ydCB7IEFkbWlzc2lvblNlcnZpY2UgfSBmcm9tICcuL2FkbWlzc2lvbi5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnQWRtaXNzaW9uJylcbkBTZXJpYWxpemVPcHRpb25zKHsgZXhjbHVkZUV4dHJhbmVvdXNWYWx1ZXM6IHRydWUsIGV4cG9zZVVuc2V0RmllbGRzOiBmYWxzZSB9KVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignYWRtaXNzaW9uJylcbmV4cG9ydCBjbGFzcyBBZG1pc3Npb25Db250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBhZG1pc3Npb25TZXJ2aWNlOiBBZG1pc3Npb25TZXJ2aWNlKSB7IH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5hZG1pc3Npb25TZXJ2aWNlLmZpbmRBbGwoKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmFkbWlzc2lvblNlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZUFkbWlzc2lvbkR0bzogQ3JlYXRlQWRtaXNzaW9uRHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5hZG1pc3Npb25TZXJ2aWNlLmNyZWF0ZShjbGluaWNJZCwgY3JlYXRlQWRtaXNzaW9uRHRvKVxuXHR9XG5cblx0QFBhdGNoKCc6aWQnKVxuXHR1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlQWRtaXNzaW9uRHRvOiBVcGRhdGVBZG1pc3Npb25EdG8pIHtcblx0XHRyZXR1cm4gdGhpcy5hZG1pc3Npb25TZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZUFkbWlzc2lvbkR0bylcblx0fVxuXG5cdEBEZWxldGUoJzppZCcpXG5cdHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmFkbWlzc2lvblNlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHksIEFwaVByb3BlcnR5T3B0aW9uYWwsIFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgRXhwb3NlLCBUeXBlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBJc0RhdGUsIElzRW51bSwgSXNOdW1iZXIsIElzU3RyaW5nLCBWYWxpZGF0ZU5lc3RlZCB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcbmltcG9ydCB7IEVHZW5kZXIgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2Jhc2UuZW50aXR5J1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eSdcblxuY2xhc3MgUGF0aWVudER0byB7XG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgbmFtZTogJ3BhdGllbnRfaWQnLCBleGFtcGxlOiAnJyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ3BhdGllbnRfaWQnIH0pXG5cdEBUeXBlKCgpID0+IE51bWJlcilcblx0QElzTnVtYmVyKClcblx0cGF0aWVudElkOiBudW1iZXJcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IG5hbWU6ICdmdWxsX25hbWUnLCBleGFtcGxlOiAnTmd1eeG7hW4gVGjhu4sgw4FuaCcgfSlcblx0QEV4cG9zZSh7IG5hbWU6ICdmdWxsX25hbWUnIH0pXG5cdEBJc1N0cmluZygpXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICcwOTg3NDQ1MjIzJyB9KVxuXHRARXhwb3NlKClcblx0QElzU3RyaW5nKClcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogJzE5MjctMDQtMjhUMDA6MDA6MDAuMDAwWicgfSlcblx0QEV4cG9zZSgpXG5cdEBUeXBlKCgpID0+IERhdGUpXG5cdEBJc0RhdGUoKVxuXHRiaXJ0aGRheTogRGF0ZVxuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZW51bTogRUdlbmRlciwgZXhhbXBsZTogRUdlbmRlci5GZW1hbGUgfSlcblx0QEV4cG9zZSgpXG5cdEBJc0VudW0oRUdlbmRlcilcblx0Z2VuZGVyOiBFR2VuZGVyXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnVOG7iW5oIEjDoCBUxKluaCAtLSBIdXnhu4duIMSQ4bupYyBUaOG7jSAtLSBYw6MgTMOibSBUcnVuZyBUaOG7p3kgLS0gVGjDtG4gUGhhbiBUaOG6r25nJyB9KVxuXHRARXhwb3NlKClcblx0QElzU3RyaW5nKClcblx0YWRkcmVzczogc3RyaW5nXG59XG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVBZG1pc3Npb25EdG8ge1xuXHRAQXBpUHJvcGVydHkoeyB0eXBlOiBQYXRpZW50RHRvIH0pXG5cdEBFeHBvc2UoKVxuXHRAVmFsaWRhdGVOZXN0ZWQoeyBlYWNoOiB0cnVlIH0pXG5cdEBUeXBlKCgpID0+IFBhdGllbnREdG8pXG5cdHBhdGllbnQ6IFBhdGllbnRFbnRpdHlcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICdT4buRdCBjYW8gbmfDoHkgdGjhu6kgMycgfSlcblx0QEV4cG9zZSgpXG5cdEBJc1N0cmluZygpXG5cdHJlYXNvbjogc3RyaW5nXG59XG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVBZG1pc3Npb25EdG8gZXh0ZW5kcyBQYXJ0aWFsVHlwZShDcmVhdGVBZG1pc3Npb25EdG8pIHsgfVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IEFkbWlzc2lvbkVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2FkbWlzc2lvbi5lbnRpdHknXG5pbXBvcnQgeyBBZG1pc3Npb25Db250cm9sbGVyIH0gZnJvbSAnLi9hZG1pc3Npb24uY29udHJvbGxlcidcbmltcG9ydCB7IEFkbWlzc2lvblNlcnZpY2UgfSBmcm9tICcuL2FkbWlzc2lvbi5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1R5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbQWRtaXNzaW9uRW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW0FkbWlzc2lvbkNvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtBZG1pc3Npb25TZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQWRtaXNzaW9uTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCB7IFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IEFkbWlzc2lvbkVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2FkbWlzc2lvbi5lbnRpdHknXG5pbXBvcnQgeyBDcmVhdGVBZG1pc3Npb25EdG8sIFVwZGF0ZUFkbWlzc2lvbkR0byB9IGZyb20gJy4vYWRtaXNzaW9uLmR0bydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEFkbWlzc2lvblNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShBZG1pc3Npb25FbnRpdHkpIHByaXZhdGUgYWRtaXNzaW9uUmVwb3NpdG9yeTogUmVwb3NpdG9yeTxBZG1pc3Npb25FbnRpdHk+KSB7IH1cblxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhbGwgYWRtaXNzaW9uYFxuXHR9XG5cblx0ZmluZE9uZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGEgIyR7aWR9IGFkbWlzc2lvbmBcblx0fVxuXHRjcmVhdGUoY2xpbmljSWQ6IG51bWJlciwgY3JlYXRlQWRtaXNzaW9uRHRvOiBDcmVhdGVBZG1pc3Npb25EdG8pIHtcblx0XHRyZXR1cm4gJ1RoaXMgYWN0aW9uIGFkZHMgYSBuZXcgYWRtaXNzaW9uJ1xuXHR9XG5cdHVwZGF0ZShpZDogbnVtYmVyLCB1cGRhdGVBZG1pc3Npb25EdG86IFVwZGF0ZUFkbWlzc2lvbkR0bykge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBhZG1pc3Npb25gXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBhZG1pc3Npb25gXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIFBhcmFtLCBQb3N0LCBTZXJpYWxpemVPcHRpb25zIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXBSZXF1ZXN0IH0gZnJvbSAnLi4vLi4vZGVjb3JhdG9ycy9pcC1yZXF1ZXN0LmRlY29yYXRvcidcbmltcG9ydCB7IExvZ2luRHRvLCBSZWZyZXNoVG9rZW5EdG8sIFJlZ2lzdGVyRHRvLCBUb2tlbnNSZXNwb25zZSB9IGZyb20gJy4vYXV0aC5kdG8nXG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJy4vYXV0aC5zZXJ2aWNlJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4vand0LWV4dGVuZC5zZXJ2aWNlJ1xuXG5AQXBpVGFncygnQXV0aCcpXG5AU2VyaWFsaXplT3B0aW9ucyh7IGV4Y2x1ZGVFeHRyYW5lb3VzVmFsdWVzOiB0cnVlLCBleHBvc2VVbnNldEZpZWxkczogZmFsc2UgfSlcbkBDb250cm9sbGVyKCdhdXRoJylcbmV4cG9ydCBjbGFzcyBBdXRoQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgYXV0aFNlcnZpY2U6IEF1dGhTZXJ2aWNlLFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgand0RXh0ZW5kU2VydmljZTogSnd0RXh0ZW5kU2VydmljZVxuXHQpIHsgfVxuXG5cdEBQb3N0KCdyZWdpc3RlcicpXG5cdGFzeW5jIHJlZ2lzdGVyKEBCb2R5KCkgcmVnaXN0ZXJEdG86IFJlZ2lzdGVyRHRvLCBASXBSZXF1ZXN0KCkgaXA6IHN0cmluZyk6IFByb21pc2U8VG9rZW5zUmVzcG9uc2U+IHtcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UucmVnaXN0ZXIocmVnaXN0ZXJEdG8pXG5cdFx0Y29uc3QgeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0gPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UuY3JlYXRlVG9rZW5Gcm9tVXNlcihlbXBsb3llZSwgaXApXG5cdFx0cmV0dXJuIG5ldyBUb2tlbnNSZXNwb25zZSh7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfSlcblx0fVxuXG5cdEBQb3N0KCdsb2dpbicpXG5cdGFzeW5jIGxvZ2luKEBCb2R5KCkgbG9naW5EdG86IExvZ2luRHRvLCBASXBSZXF1ZXN0KCkgaXA6IHN0cmluZyk6IFByb21pc2U8VG9rZW5zUmVzcG9uc2U+IHtcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UubG9naW4obG9naW5EdG8pXG5cdFx0Y29uc3QgeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0gPSB0aGlzLmp3dEV4dGVuZFNlcnZpY2UuY3JlYXRlVG9rZW5Gcm9tVXNlcihlbXBsb3llZSwgaXApXG5cdFx0cmV0dXJuIG5ldyBUb2tlbnNSZXNwb25zZSh7IGFjY2Vzc1Rva2VuLCByZWZyZXNoVG9rZW4gfSlcblx0fVxuXG5cdEBQb3N0KCdsb2dvdXQnKVxuXHRsb2dvdXQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBQb3N0KCdjaGFuZ2UtcGFzc3dvcmQnKVxuXHRjaGFuZ2VQYXNzd29yZChAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQEJvZHkoKSB1cGRhdGVBdXRoRHRvOiBMb2dpbkR0bykge1xuXHRcdC8vIHJldHVybiB0aGlzLmF1dGhTZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZUF1dGhEdG8pXG5cdH1cblxuXHRAUG9zdCgnZm9yZ290LXBhc3N3b3JkJylcblx0Zm9yZ290UGFzc3dvcmQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS5yZW1vdmUoK2lkKVxuXHR9XG5cblx0QFBvc3QoJ3JlZnJlc2gtdG9rZW4nKVxuXHRhc3luYyBncmFudEFjY2Vzc1Rva2VuKEBCb2R5KCkgcmVmcmVzaFRva2VuRHRvOiBSZWZyZXNoVG9rZW5EdG8sIEBJcFJlcXVlc3QoKSBpcDogc3RyaW5nKTogUHJvbWlzZTxUb2tlbnNSZXNwb25zZT4ge1xuXHRcdGNvbnN0IGFjY2Vzc1Rva2VuID0gYXdhaXQgdGhpcy5hdXRoU2VydmljZS5ncmFudEFjY2Vzc1Rva2VuKHJlZnJlc2hUb2tlbkR0by5yZWZyZXNoVG9rZW4sIGlwKVxuXHRcdHJldHVybiBuZXcgVG9rZW5zUmVzcG9uc2UoeyBhY2Nlc3NUb2tlbiB9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcGlQcm9wZXJ0eSB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IEV4cG9zZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgSXNOb3RFbXB0eSwgTWluTGVuZ3RoLCBWYWxpZGF0ZSB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcbmltcG9ydCB7IElzR21haWwsIElzUGhvbmUgfSBmcm9tICcuLi8uLi9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbSdcblxuZXhwb3J0IGNsYXNzIFJlZ2lzdGVyRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2V4YW1wbGUtMkBnbWFpbC5jb20nIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBWYWxpZGF0ZShJc0dtYWlsKVxuXHRlbWFpbDogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJzAzNzY4OTk4NjYnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBWYWxpZGF0ZShJc1Bob25lKVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2FkbWluJyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBNaW5MZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgTG9naW5EdG8ge1xuXHRAQXBpUHJvcGVydHkoeyBuYW1lOiAnY19waG9uZScsIGV4YW1wbGU6ICcwOTg2MDIxMTkwJyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ2NfcGhvbmUnIH0pXG5cdEBJc05vdEVtcHR5KClcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdGNQaG9uZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ2FkbWluJyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNOb3RFbXB0eSgpXG5cdEBNaW5MZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgUmVmcmVzaFRva2VuRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgbmFtZTogJ3JlZnJlc2hfdG9rZW4nIH0pXG5cdEBFeHBvc2UoeyBuYW1lOiAncmVmcmVzaF90b2tlbicgfSlcblx0QElzTm90RW1wdHkoKVxuXHRyZWZyZXNoVG9rZW46IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVG9rZW5zUmVzcG9uc2Uge1xuXHRARXhwb3NlKHsgbmFtZTogJ2FjY2Vzc190b2tlbicgfSlcblx0YWNjZXNzVG9rZW46IHN0cmluZ1xuXG5cdEBFeHBvc2UoeyBuYW1lOiAncmVmcmVzaF90b2tlbicgfSlcblx0cmVmcmVzaFRva2VuOiBzdHJpbmdcblxuXHRjb25zdHJ1Y3RvcihwYXJ0aWFsOiBQYXJ0aWFsPFRva2Vuc1Jlc3BvbnNlPikge1xuXHRcdE9iamVjdC5hc3NpZ24odGhpcywgcGFydGlhbClcblx0fVxufVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IEp3dE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvand0J1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgSnd0Q29uZmlnIH0gZnJvbSAnLi4vLi4vZW52aXJvbm1lbnRzJ1xuaW1wb3J0IHsgQXV0aENvbnRyb2xsZXIgfSBmcm9tICcuL2F1dGguY29udHJvbGxlcidcbmltcG9ydCB7IEF1dGhTZXJ2aWNlIH0gZnJvbSAnLi9hdXRoLnNlcnZpY2UnXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbXG5cdFx0VHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHksIEVtcGxveWVlRW50aXR5XSksXG5cdFx0Q29uZmlnTW9kdWxlLmZvckZlYXR1cmUoSnd0Q29uZmlnKSxcblx0XHRKd3RNb2R1bGUsXG5cdF0sXG5cdGNvbnRyb2xsZXJzOiBbQXV0aENvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtBdXRoU2VydmljZSwgSnd0RXh0ZW5kU2VydmljZV0sXG5cdGV4cG9ydHM6IFtKd3RFeHRlbmRTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQXV0aE1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb24sIEh0dHBTdGF0dXMsIEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCAqIGFzIGJjcnlwdCBmcm9tICdiY3J5cHQnXG5pbXBvcnQgeyBEYXRhU291cmNlIH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5LCB7IEVSb2xlIH0gZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBFTG9naW5FcnJvciwgRVJlZ2lzdGVyRXJyb3IgfSBmcm9tICcuLi8uLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcbmltcG9ydCB7IExvZ2luRHRvLCBSZWdpc3RlckR0byB9IGZyb20gJy4vYXV0aC5kdG8nXG5pbXBvcnQgeyBKd3RFeHRlbmRTZXJ2aWNlIH0gZnJvbSAnLi9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBdXRoU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdHByaXZhdGUgZGF0YVNvdXJjZTogRGF0YVNvdXJjZSxcblx0XHRwcml2YXRlIGp3dEV4dGVuZFNlcnZpY2U6IEp3dEV4dGVuZFNlcnZpY2Vcblx0KSB7IH1cblxuXHRhc3luYyByZWdpc3RlcihyZWdpc3RlckR0bzogUmVnaXN0ZXJEdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgeyBlbWFpbCwgcGhvbmUsIHVzZXJuYW1lLCBwYXNzd29yZCB9ID0gcmVnaXN0ZXJEdG9cblx0XHRjb25zdCBoYXNoUGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaChwYXNzd29yZCwgNSlcblxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5kYXRhU291cmNlLnRyYW5zYWN0aW9uKGFzeW5jIChtYW5hZ2VyKSA9PiB7XG5cdFx0XHRjb25zdCBmaW5kQ2xpbmljID0gYXdhaXQgbWFuYWdlci5maW5kT25lKENsaW5pY0VudGl0eSwgeyB3aGVyZTogW3sgZW1haWwgfSwgeyBwaG9uZSB9XSB9KVxuXHRcdFx0aWYgKGZpbmRDbGluaWMpIHtcblx0XHRcdFx0aWYgKGZpbmRDbGluaWMuZW1haWwgPT09IGVtYWlsICYmIGZpbmRDbGluaWMucGhvbmUgPT09IHBob25lKSB7XG5cdFx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RFbWFpbEFuZFBob25lLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2UgaWYgKGZpbmRDbGluaWMuZW1haWwgPT09IGVtYWlsKSB7XG5cdFx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RFbWFpbCwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHRcdFx0fVxuXHRcdFx0XHRlbHNlIGlmIChmaW5kQ2xpbmljLnBob25lID09PSBwaG9uZSkge1xuXHRcdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVSZWdpc3RlckVycm9yLkV4aXN0UGhvbmUsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdH1cblx0XHRcdGNvbnN0IHNuYXBDbGluaWMgPSBtYW5hZ2VyLmNyZWF0ZShDbGluaWNFbnRpdHksIHtcblx0XHRcdFx0cGhvbmUsXG5cdFx0XHRcdGVtYWlsLFxuXHRcdFx0XHRsZXZlbDogMSxcblx0XHRcdH0pXG5cdFx0XHRjb25zdCBuZXdDbGluaWMgPSBhd2FpdCBtYW5hZ2VyLnNhdmUoc25hcENsaW5pYylcblxuXHRcdFx0Y29uc3Qgc25hcEVtcGxveWVlID0gbWFuYWdlci5jcmVhdGUoRW1wbG95ZWVFbnRpdHksIHtcblx0XHRcdFx0Y2xpbmljSWQ6IG5ld0NsaW5pYy5pZCxcblx0XHRcdFx0Y2xpbmljOiBuZXdDbGluaWMsXG5cdFx0XHRcdHVzZXJuYW1lLFxuXHRcdFx0XHRwYXNzd29yZDogaGFzaFBhc3N3b3JkLFxuXHRcdFx0XHRyb2xlOiBFUm9sZS5Pd25lcixcblx0XHRcdH0pXG5cdFx0XHRjb25zdCBuZXdFbXBsb3llZSA9IGF3YWl0IG1hbmFnZXIuc2F2ZShzbmFwRW1wbG95ZWUpXG5cblx0XHRcdHJldHVybiBuZXdFbXBsb3llZVxuXHRcdH0pXG5cblx0XHRyZXR1cm4gZW1wbG95ZWVcblx0fVxuXG5cdGFzeW5jIGxvZ2luKGxvZ2luRHRvOiBMb2dpbkR0byk6IFByb21pc2U8RW1wbG95ZWVFbnRpdHk+IHtcblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuZGF0YVNvdXJjZS5tYW5hZ2VyLmZpbmRPbmUoRW1wbG95ZWVFbnRpdHksIHtcblx0XHRcdHJlbGF0aW9uczogeyBjbGluaWM6IHRydWUgfSxcblx0XHRcdHdoZXJlOiB7XG5cdFx0XHRcdHVzZXJuYW1lOiBsb2dpbkR0by51c2VybmFtZSxcblx0XHRcdFx0Y2xpbmljOiB7IHBob25lOiBsb2dpbkR0by5jUGhvbmUgfSxcblx0XHRcdH0sXG5cdFx0fSlcblx0XHRpZiAoIWVtcGxveWVlKSB0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFTG9naW5FcnJvci5FbXBsb3llZURvZXNOb3RFeGlzdCwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblxuXHRcdGNvbnN0IGNoZWNrUGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuY29tcGFyZShsb2dpbkR0by5wYXNzd29yZCwgZW1wbG95ZWUucGFzc3dvcmQpXG5cdFx0aWYgKCFjaGVja1Bhc3N3b3JkKSB0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFTG9naW5FcnJvci5Xcm9uZ1Bhc3N3b3JkLCBIdHRwU3RhdHVzLkJBRF9HQVRFV0FZKVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBncmFudEFjY2Vzc1Rva2VuKHJlZnJlc2hUb2tlbjogc3RyaW5nLCBpcDogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcblx0XHRjb25zdCB7IHVpZCB9ID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeVJlZnJlc2hUb2tlbihyZWZyZXNoVG9rZW4sIGlwKVxuXG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UuZ2V0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSkuZmluZE9uZSh7XG5cdFx0XHRyZWxhdGlvbnM6IHsgY2xpbmljOiB0cnVlIH0sXG5cdFx0XHR3aGVyZTogeyBpZDogdWlkIH0sXG5cdFx0fSlcblxuXHRcdGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLmNyZWF0ZUFjY2Vzc1Rva2VuKGVtcGxveWVlLCBpcClcblx0XHRyZXR1cm4gYWNjZXNzVG9rZW5cblx0fVxufVxuIiwiaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiwgSHR0cFN0YXR1cywgSW5qZWN0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDb25maWdUeXBlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnXG5pbXBvcnQgeyBKd3RTZXJ2aWNlIH0gZnJvbSAnQG5lc3Rqcy9qd3QnXG5pbXBvcnQgVXNlckVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IElKd3RQYXlsb2FkIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IEp3dENvbmZpZyB9IGZyb20gJy4uLy4uL2Vudmlyb25tZW50cydcbmltcG9ydCB7IEVFcnJvciwgRVRva2VuRXJyb3IgfSBmcm9tICcuLi8uLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcblxuZXhwb3J0IGNsYXNzIEp3dEV4dGVuZFNlcnZpY2Uge1xuXHRjb25zdHJ1Y3Rvcihcblx0XHRASW5qZWN0KEp3dENvbmZpZy5LRVkpIHByaXZhdGUgand0Q29uZmlnOiBDb25maWdUeXBlPHR5cGVvZiBKd3RDb25maWc+LFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgand0U2VydmljZTogSnd0U2VydmljZVxuXHQpIHsgfVxuXG5cdGNyZWF0ZUFjY2Vzc1Rva2VuKHVzZXI6IFVzZXJFbnRpdHksIGlwOiBzdHJpbmcpOiBzdHJpbmcge1xuXHRcdGNvbnN0IHVzZXJQYXlsb2FkOiBJSnd0UGF5bG9hZCA9IHtcblx0XHRcdGlwLFxuXHRcdFx0Y1Bob25lOiB1c2VyLmNsaW5pYy5waG9uZSxcblx0XHRcdGNpZDogdXNlci5jbGluaWMuaWQsXG5cdFx0XHR1aWQ6IHVzZXIuaWQsXG5cdFx0XHR1c2VybmFtZTogdXNlci51c2VybmFtZSxcblx0XHRcdHJvbGU6IHVzZXIucm9sZSxcblx0XHR9XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHVzZXJQYXlsb2FkLCB7XG5cdFx0XHRzZWNyZXQ6IHRoaXMuand0Q29uZmlnLmFjY2Vzc0tleSxcblx0XHRcdGV4cGlyZXNJbjogdGhpcy5qd3RDb25maWcuYWNjZXNzVGltZSxcblx0XHR9KVxuXHR9XG5cblx0Y3JlYXRlUmVmcmVzaFRva2VuKHVpZDogbnVtYmVyLCBpcDogc3RyaW5nKTogc3RyaW5nIHtcblx0XHRyZXR1cm4gdGhpcy5qd3RTZXJ2aWNlLnNpZ24oeyB1aWQsIGlwIH0sIHtcblx0XHRcdHNlY3JldDogdGhpcy5qd3RDb25maWcucmVmcmVzaEtleSxcblx0XHRcdGV4cGlyZXNJbjogdGhpcy5qd3RDb25maWcucmVmcmVzaFRpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVRva2VuRnJvbVVzZXIodXNlcjogVXNlckVudGl0eSwgaXA6IHN0cmluZykge1xuXHRcdGNvbnN0IGFjY2Vzc1Rva2VuID0gdGhpcy5jcmVhdGVBY2Nlc3NUb2tlbih1c2VyLCBpcClcblx0XHRjb25zdCByZWZyZXNoVG9rZW4gPSB0aGlzLmNyZWF0ZVJlZnJlc2hUb2tlbih1c2VyLmlkLCBpcClcblx0XHRyZXR1cm4geyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH1cblx0fVxuXG5cdHZlcmlmeUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuOiBzdHJpbmcsIGlwOiBzdHJpbmcpOiBJSnd0UGF5bG9hZCB7XG5cdFx0dHJ5IHtcblx0XHRcdGNvbnN0IGp3dFBheWxvYWQ6IElKd3RQYXlsb2FkID0gdGhpcy5qd3RTZXJ2aWNlLnZlcmlmeShhY2Nlc3NUb2tlbiwgeyBzZWNyZXQ6IHRoaXMuand0Q29uZmlnLmFjY2Vzc0tleSB9KVxuXHRcdFx0aWYgKGp3dFBheWxvYWQuaXAgIT09IGlwKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fVxuXHRcdFx0cmV0dXJuIGp3dFBheWxvYWRcblx0XHR9IGNhdGNoIChlcnJvcikge1xuXHRcdFx0aWYgKGVycm9yLm5hbWUgPT09ICdUb2tlbkV4cGlyZWRFcnJvcicpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVRva2VuRXJyb3IuRXhwaXJlZCwgSHR0cFN0YXR1cy5VTkFVVEhPUklaRUQpXG5cdFx0XHR9IGVsc2UgaWYgKGVycm9yLm5hbWUgPT09ICdKc29uV2ViVG9rZW5FcnJvcicpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVRva2VuRXJyb3IuSW52YWxpZCwgSHR0cFN0YXR1cy5VTkFVVEhPUklaRUQpXG5cdFx0XHR9XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFRXJyb3IuVW5rbm93biwgSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1IpXG5cdFx0fVxuXHR9XG5cblx0dmVyaWZ5UmVmcmVzaFRva2VuKHJlZnJlc2hUb2tlbjogc3RyaW5nLCBpcDogc3RyaW5nKTogeyB1aWQ6IG51bWJlciB9IHtcblx0XHR0cnkge1xuXHRcdFx0Y29uc3Qgand0UGF5bG9hZCA9IHRoaXMuand0U2VydmljZS52ZXJpZnkocmVmcmVzaFRva2VuLCB7IHNlY3JldDogdGhpcy5qd3RDb25maWcucmVmcmVzaEtleSB9KVxuXHRcdFx0aWYgKGp3dFBheWxvYWQuaXAgIT09IGlwKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fVxuXHRcdFx0cmV0dXJuIGp3dFBheWxvYWRcblx0XHR9IGNhdGNoIChlcnJvcikge1xuXHRcdFx0aWYgKGVycm9yLm5hbWUgPT09ICdUb2tlbkV4cGlyZWRFcnJvcicpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVRva2VuRXJyb3IuRXhwaXJlZCwgSHR0cFN0YXR1cy5GT1JCSURERU4pXG5cdFx0XHR9IGVsc2UgaWYgKGVycm9yLm5hbWUgPT09ICdKc29uV2ViVG9rZW5FcnJvcicpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVRva2VuRXJyb3IuSW52YWxpZCwgSHR0cFN0YXR1cy5GT1JCSURERU4pXG5cdFx0XHR9XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFRXJyb3IuVW5rbm93biwgSHR0cFN0YXR1cy5JTlRFUk5BTF9TRVJWRVJfRVJST1IpXG5cdFx0fVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDb250cm9sbGVyLCBHZXQsIFBvc3QsIEJvZHksIFBhdGNoLCBQYXJhbSwgRGVsZXRlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBDbGluaWNTZXJ2aWNlIH0gZnJvbSAnLi9jbGluaWMuc2VydmljZSdcbmltcG9ydCB7IENyZWF0ZUNsaW5pY0R0bywgVXBkYXRlQ2xpbmljRHRvIH0gZnJvbSAnLi9jbGluaWMuZHRvJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcblxuQEFwaVRhZ3MoJ0NsaW5pYycpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBDb250cm9sbGVyKCdjbGluaWMnKVxuZXhwb3J0IGNsYXNzIENsaW5pY0NvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGNsaW5pY1NlcnZpY2U6IENsaW5pY1NlcnZpY2UpIHsgfVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlQ2xpbmljRHRvOiBDcmVhdGVDbGluaWNEdG8pIHtcblx0XHRyZXR1cm4gJydcblx0fVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMuY2xpbmljU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBEZWxldGUoJzppZCcpXG5cdHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxufVxuIiwiaW1wb3J0IHsgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0VtYWlsLCBMZW5ndGggfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVDbGluaWNEdG8ge1xuXHRASXNFbWFpbCgpXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRATGVuZ3RoKDEwLCAxMClcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBMZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlQ2xpbmljRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlQ2xpbmljRHRvKSB7IH1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IHsgQ2xpbmljQ29udHJvbGxlciB9IGZyb20gJy4vY2xpbmljLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBDbGluaWNTZXJ2aWNlIH0gZnJvbSAnLi9jbGluaWMuc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW0NsaW5pY0VudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtDbGluaWNDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbQ2xpbmljU2VydmljZV0sXG5cdGV4cG9ydHM6IFtDbGluaWNTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgQ2xpbmljTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCB7IERhdGFTb3VyY2UsIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2NsaW5pYy5lbnRpdHknXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBDbGluaWNTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0QEluamVjdFJlcG9zaXRvcnkoQ2xpbmljRW50aXR5KSBwcml2YXRlIGNsaW5pY1JlcG9zaXRvcnk6IFJlcG9zaXRvcnk8Q2xpbmljRW50aXR5Pixcblx0XHRwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2Vcblx0KSB7IH1cblxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhbGwgY2xpbmljYFxuXHR9XG5cblx0ZmluZE9uZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxuXG5cdHVwZGF0ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiB1cGRhdGVzIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxuXG5cdHJlbW92ZShpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZW1vdmVzIGEgIyR7aWR9IGNsaW5pY2Bcblx0fVxufVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgRGVsZXRlLCBHZXQsIFBhcmFtLCBQYXRjaCwgUG9zdCwgUmVxIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBBcGlCZWFyZXJBdXRoLCBBcGlQYXJhbSwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IEVSb2xlIH0gZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgUm9sZXMgfSBmcm9tICcuLi8uLi9ndWFyZHMvcm9sZXMuZ3VhcmQnXG5pbXBvcnQgeyBDcmVhdGVFbXBsb3llZUR0bywgVXBkYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2VtcGxveWVlLmR0bydcbmltcG9ydCB7IEVtcGxveWVlU2VydmljZSB9IGZyb20gJy4vZW1wbG95ZWUuc2VydmljZSdcblxuQEFwaVRhZ3MoJ0VtcGxveWVlJylcbkBBcGlCZWFyZXJBdXRoKCdhY2Nlc3MtdG9rZW4nKVxuQFJvbGVzKEVSb2xlLkFkbWluLCBFUm9sZS5Pd25lcilcbkBDb250cm9sbGVyKCdlbXBsb3llZScpXG5leHBvcnQgY2xhc3MgRW1wbG95ZWVDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBlbXBsb3llZVNlcnZpY2U6IEVtcGxveWVlU2VydmljZSkgeyB9XG5cblx0QEdldCgpXG5cdGZpbmRBbGwoQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLmZpbmRBbGwoY2xpbmljSWQpXG5cdH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZUVtcGxveWVlRHRvOiBDcmVhdGVFbXBsb3llZUR0bywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMuZW1wbG95ZWVTZXJ2aWNlLmNyZWF0ZShjbGluaWNJZCwgY3JlYXRlRW1wbG95ZWVEdG8pXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5maW5kT25lKGNsaW5pY0lkLCAraWQpXG5cdH1cblxuXHRAUGF0Y2goJ3VwZGF0ZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHVwZGF0ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbiwgQEJvZHkoKSB1cGRhdGVFbXBsb3llZUR0bzogVXBkYXRlRW1wbG95ZWVEdG8pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnVwZGF0ZShjbGluaWNJZCwgK2lkLCB1cGRhdGVFbXBsb3llZUR0bylcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG5cblx0QERlbGV0ZSgncmVtb3ZlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgcmVtb3ZlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLmVtcGxveWVlU2VydmljZS5yZW1vdmUoY2xpbmljSWQsICtpZClcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG5cblx0QFBhdGNoKCdyZXN0b3JlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgcmVzdG9yZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5lbXBsb3llZVNlcnZpY2UucmVzdG9yZShjbGluaWNJZCwgK2lkKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cbn1cbiIsImltcG9ydCB7IEFwaVByb3BlcnR5LCBQYXJ0aWFsVHlwZSB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IElzRGVmaW5lZCwgTWluTGVuZ3RoIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5leHBvcnQgY2xhc3MgQ3JlYXRlRW1wbG95ZWVEdG8ge1xuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnbmhhdGR1b25nMjAxOScgfSlcblx0QElzRGVmaW5lZCgpXG5cdHVzZXJuYW1lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnQWJjQDEyMzQ1NicgfSlcblx0QElzRGVmaW5lZCgpXG5cdEBNaW5MZW5ndGgoNilcblx0cGFzc3dvcmQ6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdOZ8O0IE5o4bqtdCBExrDGoW5nJyB9KVxuXHRmdWxsTmFtZTogc3RyaW5nXG59XG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVFbXBsb3llZUR0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZUVtcGxveWVlRHRvKSB7IH1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuaW1wb3J0IEVtcGxveWVlRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgRW1wbG95ZWVDb250cm9sbGVyIH0gZnJvbSAnLi9lbXBsb3llZS5jb250cm9sbGVyJ1xuaW1wb3J0IHsgRW1wbG95ZWVTZXJ2aWNlIH0gZnJvbSAnLi9lbXBsb3llZS5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1R5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbRW1wbG95ZWVFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbRW1wbG95ZWVDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbRW1wbG95ZWVTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgRW1wbG95ZWVNb2R1bGUgeyB9XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBIdHRwU3RhdHVzIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vZW51bXMnXG5pbXBvcnQgeyBIdHRwRXhjZXB0aW9uIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24vZXhjZXB0aW9ucydcbmltcG9ydCB7IEluamVjdFJlcG9zaXRvcnkgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgKiBhcyBiY3J5cHQgZnJvbSAnYmNyeXB0J1xuaW1wb3J0IHsgcGxhaW5Ub0NsYXNzIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBFbXBsb3llZUVudGl0eSwgeyBFUm9sZSB9IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgRUVtcGxveWVlRXJyb3IsIEVSZWdpc3RlckVycm9yIH0gZnJvbSAnLi4vLi4vZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0nXG5pbXBvcnQgeyBDcmVhdGVFbXBsb3llZUR0bywgVXBkYXRlRW1wbG95ZWVEdG8gfSBmcm9tICcuL2VtcGxveWVlLmR0bydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKEBJbmplY3RSZXBvc2l0b3J5KEVtcGxveWVlRW50aXR5KSBwcml2YXRlIGVtcGxveWVlUmVwb3NpdG9yeTogUmVwb3NpdG9yeTxFbXBsb3llZUVudGl0eT4pIHsgfVxuXG5cdGFzeW5jIGZpbmRBbGwoY2xpbmljSWQ6IG51bWJlcik6IFByb21pc2U8RW1wbG95ZWVFbnRpdHlbXT4ge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5maW5kKHsgd2hlcmU6IHsgY2xpbmljSWQgfSB9KVxuXHR9XG5cblx0YXN5bmMgY3JlYXRlKGNsaW5pY0lkOiBudW1iZXIsIGNyZWF0ZUVtcGxveWVlRHRvOiBDcmVhdGVFbXBsb3llZUR0byk6IFByb21pc2U8RW1wbG95ZWVFbnRpdHk+IHtcblx0XHRjb25zdCBmaW5kRW1wbG95ZWUgPSBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5maW5kT25lQnkoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHR1c2VybmFtZTogY3JlYXRlRW1wbG95ZWVEdG8udXNlcm5hbWUsXG5cdFx0fSlcblx0XHRpZiAoZmluZEVtcGxveWVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdFVzZXJuYW1lLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdH1cblx0XHRjb25zdCBzbmFwRW1wbG95ZWUgPSBwbGFpblRvQ2xhc3MoRW1wbG95ZWVFbnRpdHksIGNyZWF0ZUVtcGxveWVlRHRvKVxuXHRcdHNuYXBFbXBsb3llZS5wYXNzd29yZCA9IGF3YWl0IGJjcnlwdC5oYXNoKGNyZWF0ZUVtcGxveWVlRHRvLnBhc3N3b3JkLCA1KVxuXHRcdHNuYXBFbXBsb3llZS5yb2xlID0gRVJvbGUuVXNlclxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5zYXZlKGNyZWF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0YXN5bmMgZmluZE9uZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHR9XG5cblx0YXN5bmMgdXBkYXRlKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIsIHVwZGF0ZUVtcGxveWVlRHRvOiBVcGRhdGVFbXBsb3llZUR0bykge1xuXHRcdGNvbnN0IGZpbmRFbXBsb3llZSA9IGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHRcdGlmICghZmluZEVtcGxveWVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFRW1wbG95ZWVFcnJvci5Ob3RFeGlzdHMsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0fVxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS51cGRhdGUoeyBjbGluaWNJZCwgaWQgfSwgdXBkYXRlRW1wbG95ZWVEdG8pXG5cdH1cblxuXHRhc3luYyByZW1vdmUoY2xpbmljSWQ6IG51bWJlciwgZW1wbG95ZWVJZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LnNvZnREZWxldGUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG5cblx0YXN5bmMgcmVzdG9yZShjbGluaWNJZDogbnVtYmVyLCBlbXBsb3llZUlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkucmVzdG9yZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkOiBlbXBsb3llZUlkLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IENvbnRyb2xsZXIsIEdldCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7XG5cdERpc2tIZWFsdGhJbmRpY2F0b3IsIEhlYWx0aENoZWNrLCBIZWFsdGhDaGVja1NlcnZpY2UsIEh0dHBIZWFsdGhJbmRpY2F0b3IsXG5cdE1lbW9yeUhlYWx0aEluZGljYXRvciwgVHlwZU9ybUhlYWx0aEluZGljYXRvcixcbn0gZnJvbSAnQG5lc3Rqcy90ZXJtaW51cydcblxuQEFwaVRhZ3MoJ0hlYWx0aCcpXG5AQ29udHJvbGxlcignaGVhbHRoJylcbmV4cG9ydCBjbGFzcyBIZWFsdGhDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0cHJpdmF0ZSByZWFkb25seSBoZWFsdGg6IEhlYWx0aENoZWNrU2VydmljZSxcblx0XHRwcml2YXRlIHJlYWRvbmx5IGh0dHA6IEh0dHBIZWFsdGhJbmRpY2F0b3IsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBkYjogVHlwZU9ybUhlYWx0aEluZGljYXRvcixcblx0XHRwcml2YXRlIHJlYWRvbmx5IGRpc2s6IERpc2tIZWFsdGhJbmRpY2F0b3IsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBtZW1vcnk6IE1lbW9yeUhlYWx0aEluZGljYXRvclxuXHQpIHsgfVxuXG5cdEBHZXQoKVxuXHRASGVhbHRoQ2hlY2soKVxuXHRjaGVjaygpIHtcblx0XHRjb25zdCBwYXRoU3RvcmFnZSA9IHByb2Nlc3MucGxhdGZvcm0gPT09ICd3aW4zMicgPyAnQzpcXFxcJyA6ICcvJ1xuXHRcdGNvbnN0IHRocmVzaG9sZFBlcmNlbnQgPSBwcm9jZXNzLnBsYXRmb3JtID09PSAnd2luMzInID8gMC45IDogMC41XG5cblx0XHRyZXR1cm4gdGhpcy5oZWFsdGguY2hlY2soW1xuXHRcdFx0KCkgPT4gdGhpcy5odHRwLnBpbmdDaGVjaygnbmVzdGpzLWRvY3MnLCAnaHR0cHM6Ly9tZWRpaG9tZS52bi9kb2N1bWVudCcpLFxuXHRcdFx0KCkgPT4gdGhpcy5kYi5waW5nQ2hlY2soJ2RhdGFiYXNlJyksXG5cdFx0XHQoKSA9PiB0aGlzLmRpc2suY2hlY2tTdG9yYWdlKCdzdG9yYWdlJywgeyBwYXRoOiBwYXRoU3RvcmFnZSwgdGhyZXNob2xkUGVyY2VudCB9KSxcblx0XHRcdCgpID0+IHRoaXMubWVtb3J5LmNoZWNrSGVhcCgnbWVtb3J5X2hlYXAnLCAxNTAgKiAxMDI0ICogMTAyNCksXG5cdFx0XHQoKSA9PiB0aGlzLm1lbW9yeS5jaGVja1JTUygnbWVtb3J5X3JzcycsIDE1MCAqIDEwMjQgKiAxMDI0KSxcblx0XHRdKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBIdHRwTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9heGlvcydcbmltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVGVybWludXNNb2R1bGUgfSBmcm9tICdAbmVzdGpzL3Rlcm1pbnVzJ1xuaW1wb3J0IHsgSGVhbHRoQ29udHJvbGxlciB9IGZyb20gJy4vaGVhbHRoLmNvbnRyb2xsZXInXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVGVybWludXNNb2R1bGUsIEh0dHBNb2R1bGVdLFxuXHRjb250cm9sbGVyczogW0hlYWx0aENvbnRyb2xsZXJdLFxufSlcbmV4cG9ydCBjbGFzcyBIZWFsdGhNb2R1bGUgeyB9XG4iLCJleHBvcnQgY2xhc3MgQ3JlYXRlTWVkaWNpbmVEdG8ge31cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2NyZWF0ZS1tZWRpY2luZS5kdG8nXG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVNZWRpY2luZUR0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZU1lZGljaW5lRHRvKSB7fVxuIiwiaW1wb3J0IHsgQm9keSwgQ29udHJvbGxlciwgRGVsZXRlLCBHZXQsIFBhcmFtLCBQYXRjaCwgUG9zdCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IENyZWF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vY3JlYXRlLW1lZGljaW5lLmR0bydcbmltcG9ydCB7IFVwZGF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlLW1lZGljaW5lLmR0bydcbmltcG9ydCB7IE1lZGljaW5lU2VydmljZSB9IGZyb20gJy4vbWVkaWNpbmUuc2VydmljZSdcblxuQEFwaVRhZ3MoJ01lZGljaW5lJylcbkBBcGlCZWFyZXJBdXRoKCdhY2Nlc3MtdG9rZW4nKVxuQENvbnRyb2xsZXIoJ21lZGljaW5lJylcbmV4cG9ydCBjbGFzcyBNZWRpY2luZUNvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IG1lZGljaW5lU2VydmljZTogTWVkaWNpbmVTZXJ2aWNlKSB7IH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZU1lZGljaW5lRHRvOiBDcmVhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5jcmVhdGUoY3JlYXRlTWVkaWNpbmVEdG8pXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLmZpbmRPbmUoK2lkKVxuXHR9XG5cblx0QFBhdGNoKCc6aWQnKVxuXHR1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlTWVkaWNpbmVEdG86IFVwZGF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLnVwZGF0ZSgraWQsIHVwZGF0ZU1lZGljaW5lRHRvKVxuXHR9XG5cblx0QERlbGV0ZSgnOmlkJylcblx0cmVtb3ZlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBNZWRpY2luZUVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL21lZGljaW5lLmVudGl0eSdcbmltcG9ydCB7IE1lZGljaW5lQ29udHJvbGxlciB9IGZyb20gJy4vbWVkaWNpbmUuY29udHJvbGxlcidcbmltcG9ydCB7IE1lZGljaW5lU2VydmljZSB9IGZyb20gJy4vbWVkaWNpbmUuc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW01lZGljaW5lRW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW01lZGljaW5lQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW01lZGljaW5lU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIE1lZGljaW5lTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ3JlYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvJ1xuaW1wb3J0IHsgVXBkYXRlTWVkaWNpbmVEdG8gfSBmcm9tICcuL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgTWVkaWNpbmVTZXJ2aWNlIHtcblx0Y3JlYXRlKGNyZWF0ZU1lZGljaW5lRHRvOiBDcmVhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiAnVGhpcyBhY3Rpb24gYWRkcyBhIG5ldyBtZWRpY2luZSdcblx0fVxuXG5cdGZpbmRBbGwoKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiByZXR1cm5zIGFsbCBtZWRpY2luZWBcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxuXG5cdHVwZGF0ZShpZDogbnVtYmVyLCB1cGRhdGVNZWRpY2luZUR0bzogVXBkYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHVwZGF0ZXMgYSAjJHtpZH0gbWVkaWNpbmVgXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBtZWRpY2luZWBcblx0fVxufVxuIiwiaW1wb3J0IHsgQm9keSwgQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IsIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFF1ZXJ5LCBSZXEsIFVzZUludGVyY2VwdG9ycyB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpUGFyYW0sIEFwaVF1ZXJ5LCBBcGlUYWdzIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IENyZWF0ZVBhdGllbnREdG8sIFVwZGF0ZVBhdGllbnREdG8gfSBmcm9tICcuL3BhdGllbnQuZHRvJ1xuaW1wb3J0IHsgUGF0aWVudFNlcnZpY2UgfSBmcm9tICcuL3BhdGllbnQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ1BhdGllbnQnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AVXNlSW50ZXJjZXB0b3JzKENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yKVxuQENvbnRyb2xsZXIoJ3BhdGllbnQnKVxuZXhwb3J0IGNsYXNzIFBhdGllbnRDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBwYXRpZW50U2VydmljZTogUGF0aWVudFNlcnZpY2UpIHsgfVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRBbGwoY2xpbmljSWQpXG5cdH1cblxuXHRAR2V0KCdzZWFyY2gnKVxuXHRAQXBpUXVlcnkoeyBuYW1lOiAnc2VhcmNoVGV4dCcsIGV4YW1wbGU6ICcwOTg2MTIzNDU2JyB9KVxuXHRzZWFyY2goQFF1ZXJ5KCdzZWFyY2hUZXh0Jykgc2VhcmNoVGV4dDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRpZiAoL15cXGQrJC8udGVzdChzZWFyY2hUZXh0KSkge1xuXHRcdFx0cmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuZmluZEJ5UGhvbmUoY2xpbmljSWQsIHNlYXJjaFRleHQpXG5cdFx0fVxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRCeUZ1bGxOYW1lKGNsaW5pY0lkLCBzZWFyY2hUZXh0KVxuXHR9XG5cblx0QFBvc3QoKVxuXHRjcmVhdGUoQEJvZHkoKSBjcmVhdGVQYXRpZW50RHRvOiBDcmVhdGVQYXRpZW50RHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS5jcmVhdGUoY2xpbmljSWQsIGNyZWF0ZVBhdGllbnREdG8pXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGZpbmRPbmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRPbmUoY2xpbmljSWQsICtpZClcblx0fVxuXG5cdEBQYXRjaCgndXBkYXRlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgdXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAQm9keSgpIHVwZGF0ZVBhdGllbnREdG86IFVwZGF0ZVBhdGllbnREdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMucGF0aWVudFNlcnZpY2UudXBkYXRlKGNsaW5pY0lkLCAraWQsIHVwZGF0ZVBhdGllbnREdG8pXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBEZWxldGUoJ3JlbW92ZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5wYXRpZW50U2VydmljZS5yZW1vdmUoY2xpbmljSWQsICtpZClcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG5cblx0QFBhdGNoKCdyZXN0b3JlLzppZCcpXG5cdEBBcGlQYXJhbSh7IG5hbWU6ICdpZCcsIGV4YW1wbGU6IDEgfSlcblx0YXN5bmMgcmVzdG9yZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5wYXRpZW50U2VydmljZS5yZXN0b3JlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHlPcHRpb25hbCwgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBUeXBlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBJc0RhdGUsIElzRGVmaW5lZCwgSXNFbnVtLCBJc1N0cmluZywgVmFsaWRhdGUgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5pbXBvcnQgeyBFR2VuZGVyIH0gZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9iYXNlLmVudGl0eSdcbmltcG9ydCB7IElzUGhvbmUgfSBmcm9tICcuLi8uLi9jb21tb24vY2xhc3MtdmFsaWRhdG9yLmN1c3RvbSdcblxuZXhwb3J0IGNsYXNzIENyZWF0ZVBhdGllbnREdG8ge1xuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICdQaOG6oW0gSG/DoG5nIE1haScgfSlcblx0QElzRGVmaW5lZCgpXG5cdGZ1bGxOYW1lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICcwOTg2MTIzNDU2JyB9KVxuXHRAVmFsaWRhdGUoSXNQaG9uZSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogRUdlbmRlci5GZW1hbGUgfSlcblx0QElzRW51bShFR2VuZGVyKVxuXHRnZW5kZXI6IEVHZW5kZXJcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICdUaMOgbmggcGjhu5EgSMOgIE7hu5lpIC0tIFF14bqtbiBMb25nIEJpw6puIC0tIFBoxrDhu51uZyBUaOG6oWNoIELDoG4gLS0gc+G7kSA4IC0gdMOyYSBuaMOgIMSQ4bqjbyBD4bqndSBW4buTbmcnIH0pXG5cdEBJc1N0cmluZygpXG5cdGFkZHJlc3M6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogJzE5OTgtMTEtMjhUMDA6MDA6MDAuMDAwWicgfSlcblx0QFR5cGUoKCkgPT4gRGF0ZSlcblx0QElzRGF0ZSgpXG5cdGJpcnRoZGF5OiBEYXRlXG59XG5cbmV4cG9ydCBjbGFzcyBVcGRhdGVQYXRpZW50RHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlUGF0aWVudER0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgUGF0aWVudEVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL3BhdGllbnQuZW50aXR5J1xuaW1wb3J0IHsgUGF0aWVudENvbnRyb2xsZXIgfSBmcm9tICcuL3BhdGllbnQuY29udHJvbGxlcidcbmltcG9ydCB7IFBhdGllbnRTZXJ2aWNlIH0gZnJvbSAnLi9wYXRpZW50LnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtQYXRpZW50RW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW1BhdGllbnRDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbUGF0aWVudFNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBQYXRpZW50TW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSHR0cFN0YXR1cywgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnMnXG5pbXBvcnQgeyBJbmplY3RSZXBvc2l0b3J5IH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IHsgRXF1YWwsIExpa2UsIFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eSdcbmltcG9ydCB7IEVQYXRpZW50RXJyb3IgfSBmcm9tICcuLi8uLi9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bSdcbmltcG9ydCB7IENyZWF0ZVBhdGllbnREdG8sIFVwZGF0ZVBhdGllbnREdG8gfSBmcm9tICcuL3BhdGllbnQuZHRvJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUGF0aWVudFNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShQYXRpZW50RW50aXR5KSBwcml2YXRlIHBhdGllbnRSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PFBhdGllbnRFbnRpdHk+KSB7IH1cblxuXHRhc3luYyBmaW5kQWxsKGNsaW5pY0lkOiBudW1iZXIpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHsgd2hlcmU6IHsgY2xpbmljSWQgfSB9KVxuXHRcdHJldHVybiBwYXRpZW50TGlzdFxuXHR9XG5cblx0YXN5bmMgY3JlYXRlKGNsaW5pY0lkOiBudW1iZXIsIGNyZWF0ZVBhdGllbnREdG86IENyZWF0ZVBhdGllbnREdG8pOiBQcm9taXNlPFBhdGllbnRFbnRpdHk+IHtcblx0XHRjb25zdCBwYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5zYXZlKHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0Li4uY3JlYXRlUGF0aWVudER0byxcblx0XHR9KVxuXHRcdHJldHVybiBwYXRpZW50XG5cdH1cblxuXHRhc3luYyBmaW5kT25lKGNsaW5pY0lkOiBudW1iZXIsIGlkOiBudW1iZXIpIHtcblx0XHRjb25zdCBwYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kT25lQnkoeyBjbGluaWNJZCwgaWQgfSlcblx0XHRyZXR1cm4gcGF0aWVudFxuXHR9XG5cblx0YXN5bmMgZmluZEJ5UGhvbmUoY2xpbmljSWQ6IG51bWJlciwgcGhvbmU6IHN0cmluZyk6IFByb21pc2U8UGF0aWVudEVudGl0eVtdPiB7XG5cdFx0Y29uc3QgcGF0aWVudExpc3QgPSBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LmZpbmQoe1xuXHRcdFx0d2hlcmU6IHtcblx0XHRcdFx0Y2xpbmljSWQ6IEVxdWFsKGNsaW5pY0lkKSxcblx0XHRcdFx0cGhvbmU6IExpa2UoYCR7cGhvbmV9JWApLFxuXHRcdFx0fSxcblx0XHRcdHNraXA6IDAsXG5cdFx0XHR0YWtlOiAxMCxcblx0XHR9KVxuXHRcdHJldHVybiBwYXRpZW50TGlzdFxuXHR9XG5cdGFzeW5jIGZpbmRCeUZ1bGxOYW1lKGNsaW5pY0lkOiBudW1iZXIsIGZ1bGxOYW1lOiBzdHJpbmcpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHtcblx0XHRcdHdoZXJlOiB7XG5cdFx0XHRcdGNsaW5pY0lkOiBFcXVhbChjbGluaWNJZCksXG5cdFx0XHRcdGZ1bGxOYW1lOiBMaWtlKGAke2Z1bGxOYW1lfSVgKSxcblx0XHRcdH0sXG5cdFx0XHRza2lwOiAwLFxuXHRcdFx0dGFrZTogMTAsXG5cdFx0fSlcblx0XHRyZXR1cm4gcGF0aWVudExpc3Rcblx0fVxuXG5cdGFzeW5jIHVwZGF0ZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyLCB1cGRhdGVQYXRpZW50RHRvOiBVcGRhdGVQYXRpZW50RHRvKSB7XG5cdFx0Y29uc3QgZmluZFBhdGllbnQgPSBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGNsaW5pY0lkLCBpZCB9KVxuXHRcdGlmICghZmluZFBhdGllbnQpIHtcblx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVQYXRpZW50RXJyb3IuTm90RXhpc3RzLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdH1cblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS51cGRhdGUoeyBjbGluaWNJZCwgaWQgfSwgdXBkYXRlUGF0aWVudER0bylcblx0fVxuXG5cdGFzeW5jIHJlbW92ZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuc29mdERlbGV0ZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdGlkLFxuXHRcdH0pXG5cdH1cblxuXHRhc3luYyByZXN0b3JlKGNsaW5pY0lkOiBudW1iZXIsIGVtcGxveWVlSWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LnJlc3RvcmUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDcmVhdGVEYXRlQ29sdW1uLCBEZWxldGVEYXRlQ29sdW1uLCBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLCBVcGRhdGVEYXRlQ29sdW1uIH0gZnJvbSAndHlwZW9ybSdcblxuZXhwb3J0IGVudW0gRUdlbmRlciB7XG5cdE1hbGUgPSAnTWFsZScsXG5cdEZlbWFsZSA9ICdGZW1hbGUnLFxufVxuXG5leHBvcnQgdHlwZSBUR2VuZGVyID0ga2V5b2YgdHlwZW9mIEVHZW5kZXJcblxuZXhwb3J0IGNsYXNzIEJhc2VFbnRpdHkge1xuXHRAUHJpbWFyeUdlbmVyYXRlZENvbHVtbih7IG5hbWU6ICdpZCcgfSlcblx0aWQ6IG51bWJlclxuXG5cdEBDcmVhdGVEYXRlQ29sdW1uKHsgbmFtZTogJ2NyZWF0ZWRfYXQnIH0pXG5cdGNyZWF0ZWRBdDogRGF0ZVxuXG5cdEBVcGRhdGVEYXRlQ29sdW1uKHsgbmFtZTogJ3VwZGF0ZWRfYXQnIH0pXG5cdHVwZGF0ZWRBdDogRGF0ZVxuXG5cdEBEZWxldGVEYXRlQ29sdW1uKHsgbmFtZTogJ2RlbGV0ZWRfYXQnIH0pXG5cdEBFeGNsdWRlKClcblx0ZGVsZXRlZEF0OiBEYXRlXG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDb2x1bW4sIEVudGl0eSB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5IH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ2FkbWlzc2lvbicpXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBBZG1pc3Npb25FbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IG5hbWU6ICdjbGluaWNfaWQnIH0pXG5cdEBFeGNsdWRlKClcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAncGF0aWVudF9pZCcgfSlcblx0cGF0aWVudElkOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbmFtZTogJ3JlYXNvbicsIG51bGxhYmxlOiB0cnVlIH0pXG5cdHJlYXNvbjogc3RyaW5nIC8vIEzDvSBkbyB2w6BvIHZp4buHblxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnbWVkaWNhbF9yZWNvcmQnLCB0eXBlOiAndGV4dCcgfSlcblx0bWVkaWNhbFJlY29yZDogc3RyaW5nIC8vIFTDs20gdMSDdCBi4buHbmggw6FuXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGRpYWdub3Npczogc3RyaW5nIC8vIENo4bqpbiDEkW/DoW5cblxuXHRAQ29sdW1uKHsgdHlwZTogJ3RpbnlpbnQnLCB1bnNpZ25lZDogdHJ1ZSwgbnVsbGFibGU6IHRydWUgfSkgICAgICAgICAgICAgICAvLyAtLS0tLSB0aW55aW50X3Vuc2lnbmVkOiAwIC0+IDI1NlxuXHRwdWxzZTogbnVtYmVyXG5cblx0QENvbHVtbih7IHR5cGU6ICdmbG9hdCcsIHByZWNpc2lvbjogMywgc2NhbGU6IDEsIG51bGxhYmxlOiB0cnVlIH0pXG5cdHRlbXBlcmF0dXJlOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2Jsb29kX3ByZXNzdXJlJywgbGVuZ3RoOiAxMCwgbnVsbGFibGU6IHRydWUgfSlcblx0Ymxvb2RQcmVzc3VyZTogc3RyaW5nXG5cblx0QENvbHVtbih7IG5hbWU6ICdyZXNwaXJhdG9yeV9yYXRlJywgdHlwZTogJ3RpbnlpbnQnLCBudWxsYWJsZTogdHJ1ZSB9KSAgICAgLy8gLS0tLS0gdGlueWludDogLTEyOCAtPiAxMjdcblx0cmVzcGlyYXRvcnlSYXRlOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgdHlwZTogJ3RpbnlpbnQnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRzcE8yOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0bm90ZTogc3RyaW5nIC8vIEdoaSBjaMO6XG59XG4iLCJpbXBvcnQgeyBDb2x1bW4sIEVudGl0eSwgSW5kZXggfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuXG5ARW50aXR5KCdjbGluaWMnKVxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgQ2xpbmljRW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyB1bmlxdWU6IHRydWUsIGxlbmd0aDogMTAsIG51bGxhYmxlOiBmYWxzZSB9KVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgbnVsbGFibGU6IGZhbHNlIH0pXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ3RpbnlpbnQnLCBkZWZhdWx0OiAxIH0pXG5cdGxldmVsOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0bmFtZTogc3RyaW5nXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGFkZHJlc3M6IHN0cmluZ1xufVxuIiwiaW1wb3J0IHsgRXhjbHVkZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgQ29sdW1uLCBFbnRpdHksIEluZGV4LCBKb2luQ29sdW1uLCBNYW55VG9PbmUgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSwgRUdlbmRlciB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuL2NsaW5pYy5lbnRpdHknXG5cbmV4cG9ydCBlbnVtIEVSb2xlIHtcblx0T3duZXIgPSAnT3duZXInLFxuXHRBZG1pbiA9ICdBZG1pbicsXG5cdFVzZXIgPSAnVXNlcicsXG59XG5cbmV4cG9ydCB0eXBlIFRSb2xlID0ga2V5b2YgdHlwZW9mIEVSb2xlXG5cbkBFbnRpdHkoJ2VtcGxveWVlJylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ3VzZXJuYW1lJ10sIHsgdW5pcXVlOiB0cnVlIH0pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBFbXBsb3llZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QE1hbnlUb09uZSh0eXBlID0+IENsaW5pY0VudGl0eSlcblx0QEpvaW5Db2x1bW4oeyBuYW1lOiAnY2xpbmljX2lkJywgcmVmZXJlbmNlZENvbHVtbk5hbWU6ICdpZCcgfSlcblx0Y2xpbmljOiBDbGluaWNFbnRpdHlcblxuXHRAQ29sdW1uKHsgbGVuZ3RoOiAxMCwgbnVsbGFibGU6IHRydWUgfSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QENvbHVtbigpXG5cdEBFeGNsdWRlKClcblx0cGFzc3dvcmQ6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IEVSb2xlLCBkZWZhdWx0OiBFUm9sZS5Vc2VyIH0pXG5cdHJvbGU6IEVSb2xlXG5cblx0QENvbHVtbih7IG5hbWU6ICdmdWxsX25hbWUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRmdWxsTmFtZTogc3RyaW5nXG5cblx0QENvbHVtbih7IHR5cGU6ICdkYXRlJywgbnVsbGFibGU6IHRydWUgfSlcblx0YmlydGhkYXk6IERhdGVcblxuXHRAQ29sdW1uKHsgdHlwZTogJ2VudW0nLCBlbnVtOiBFR2VuZGVyLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRnZW5kZXI6IEVHZW5kZXJcbn1cbiIsImltcG9ydCB7IEVudGl0eSwgQ29sdW1uLCBJbmRleCB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgeyBCYXNlRW50aXR5IH0gZnJvbSAnLi4vYmFzZS5lbnRpdHknXG5cbkBFbnRpdHkoJ21lZGljaW5lJylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ2lkJ10sIHsgdW5pcXVlOiB0cnVlIH0pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNZWRpY2luZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnYnJhbmRfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGJyYW5kTmFtZTogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdMOqbiBiaeG7h3QgZMaw4bujY1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnY2hlbWljYWxfbmFtZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGNoZW1pY2FsTmFtZTogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gdMOqbiBn4buRY1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnY2FsY3VsYXRpb25fdW5pdCcsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGNhbGN1bGF0aW9uVW5pdDogc3RyaW5nICAgICAgICAgICAgICAgICAgICAgICAgLy8gxJHGoW4gduG7iyB0w61uaDogbOG7jSwg4buRbmcsIHbhu4lcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2ltYWdlJywgbnVsbGFibGU6IHRydWUgfSlcblx0aW1hZ2U6IHN0cmluZ1xufVxuIiwiaW1wb3J0IHsgRXhjbHVkZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgQ29sdW1uLCBFbnRpdHksIEluZGV4IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHksIEVHZW5kZXIgfSBmcm9tICcuLi9iYXNlLmVudGl0eSdcblxuQEVudGl0eSgncGF0aWVudCcpXG5ASW5kZXgoWydjbGluaWNJZCcsICdmdWxsTmFtZSddKVxuQEluZGV4KFsnY2xpbmljSWQnLCAncGhvbmUnXSlcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIFBhdGllbnRFbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IG5hbWU6ICdjbGluaWNfaWQnIH0pXG5cdEBFeGNsdWRlKClcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnZnVsbF9uYW1lJyB9KVxuXHRmdWxsTmFtZTogc3RyaW5nXG5cblx0QENvbHVtbih7IGxlbmd0aDogMTAsIG51bGxhYmxlOiB0cnVlIH0pXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ2RhdGUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRiaXJ0aGRheTogRGF0ZVxuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IEVHZW5kZXIsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGdlbmRlcjogRUdlbmRlclxuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRhZGRyZXNzOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2hlYWx0aF9oaXN0b3J5JywgdHlwZTogJ3RleHQnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRoZWFsdGhIaXN0b3J5OiBzdHJpbmcgLy8gVGnhu4FuIHPhu60gYuG7h25oXG59XG4iLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2F4aW9zXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uL2VudW1zXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb25maWdcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb3JlXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvand0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvc3dhZ2dlclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL3Rlcm1pbnVzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdHlwZW9ybVwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJiY3J5cHRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdHJhbnNmb3JtZXJcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiY2xhc3MtdmFsaWRhdG9yXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImV4cHJlc3MtcmF0ZS1saW1pdFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJoZWxtZXRcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwicmVxdWVzdC1pcFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJyeGpzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInJ4anMvb3BlcmF0b3JzXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInR5cGVvcm1cIik7IiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXS5jYWxsKG1vZHVsZS5leHBvcnRzLCBtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsImltcG9ydCB7IFZhbGlkYXRpb25FcnJvciwgVmFsaWRhdGlvblBpcGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IENvbmZpZ1NlcnZpY2UgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IE5lc3RGYWN0b3J5LCBSZWZsZWN0b3IgfSBmcm9tICdAbmVzdGpzL2NvcmUnXG5pbXBvcnQgcmF0ZUxpbWl0IGZyb20gJ2V4cHJlc3MtcmF0ZS1saW1pdCdcbmltcG9ydCBoZWxtZXQgZnJvbSAnaGVsbWV0J1xuaW1wb3J0ICogYXMgcmVxdWVzdElwIGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBBcHBNb2R1bGUgfSBmcm9tICcuL2FwcC5tb2R1bGUnXG5pbXBvcnQgeyBzZXR1cFN3YWdnZXIgfSBmcm9tICcuL2NvbW1vbi9zd2FnZ2VyJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbkZpbHRlciB9IGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvaHR0cC1leGNlcHRpb24uZmlsdGVyJ1xuaW1wb3J0IHsgVW5rbm93bkV4Y2VwdGlvbkZpbHRlciB9IGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvdW5rbm93bi1leGNlcHRpb24uZmlsdGVyJ1xuaW1wb3J0IHsgVmFsaWRhdGlvbkV4Y2VwdGlvbiwgVmFsaWRhdGlvbkV4Y2VwdGlvbkZpbHRlciB9IGZyb20gJy4vZXhjZXB0aW9uLWZpbHRlcnMvdmFsaWRhdGlvbi1leGNlcHRpb24uZmlsdGVyJ1xuaW1wb3J0IHsgUm9sZXNHdWFyZCB9IGZyb20gJy4vZ3VhcmRzL3JvbGVzLmd1YXJkJ1xuaW1wb3J0IHsgQWNjZXNzTG9nSW50ZXJjZXB0b3IgfSBmcm9tICcuL2ludGVyY2VwdG9yL2FjY2Vzcy1sb2cuaW50ZXJjZXB0b3InXG5pbXBvcnQgeyBUaW1lb3V0SW50ZXJjZXB0b3IgfSBmcm9tICcuL2ludGVyY2VwdG9yL3RpbWVvdXQuaW50ZXJjZXB0b3InXG5cbmFzeW5jIGZ1bmN0aW9uIGJvb3RzdHJhcCgpIHtcblx0Y29uc3QgYXBwID0gYXdhaXQgTmVzdEZhY3RvcnkuY3JlYXRlKEFwcE1vZHVsZSlcblxuXHRjb25zdCBjb25maWdTZXJ2aWNlID0gYXBwLmdldChDb25maWdTZXJ2aWNlKVxuXHRjb25zdCBQT1JUID0gY29uZmlnU2VydmljZS5nZXQoJ05FU1RKU19QT1JUJylcblx0Y29uc3QgSE9TVCA9IGNvbmZpZ1NlcnZpY2UuZ2V0KCdORVNUSlNfSE9TVCcpIHx8ICdsb2NhbGhvc3QnXG5cblx0YXBwLnVzZShoZWxtZXQoKSlcblx0YXBwLnVzZShyYXRlTGltaXQoe1xuXHRcdHdpbmRvd01zOiA2MCAqIDEwMDAsIC8vIDEgbWludXRlc1xuXHRcdG1heDogMTAwLCAvLyBsaW1pdCBlYWNoIElQIHRvIDEwMCByZXF1ZXN0cyBwZXIgd2luZG93TXNcblx0fSkpXG5cdGFwcC5lbmFibGVDb3JzKClcblxuXHRhcHAudXNlKHJlcXVlc3RJcC5tdygpKVxuXG5cdGFwcC51c2VHbG9iYWxJbnRlcmNlcHRvcnMoXG5cdFx0bmV3IEFjY2Vzc0xvZ0ludGVyY2VwdG9yKCksXG5cdFx0bmV3IFRpbWVvdXRJbnRlcmNlcHRvcigpXG5cdClcblx0YXBwLnVzZUdsb2JhbEZpbHRlcnMoXG5cdFx0bmV3IFVua25vd25FeGNlcHRpb25GaWx0ZXIoKSxcblx0XHRuZXcgSHR0cEV4Y2VwdGlvbkZpbHRlcigpLFxuXHRcdG5ldyBWYWxpZGF0aW9uRXhjZXB0aW9uRmlsdGVyKClcblx0KVxuXHRcblx0YXBwLnVzZUdsb2JhbEd1YXJkcyhuZXcgUm9sZXNHdWFyZChhcHAuZ2V0KFJlZmxlY3RvcikpKVxuXG5cdGFwcC51c2VHbG9iYWxQaXBlcyhuZXcgVmFsaWRhdGlvblBpcGUoe1xuXHRcdHZhbGlkYXRpb25FcnJvcjogeyB0YXJnZXQ6IGZhbHNlLCB2YWx1ZTogdHJ1ZSB9LFxuXHRcdHNraXBNaXNzaW5nUHJvcGVydGllczogdHJ1ZSwgLy8ga2jDtG5nIHZhbGlkYXRlIG5o4buvbmcgcHJvcGVydHkgdW5kZWZpbmVkXG5cdFx0d2hpdGVsaXN0OiB0cnVlLCAvLyBsb+G6oWkgYuG7jyBjw6FjIHByb3BlcnR5IGtow7RuZyBjw7MgdHJvbmcgRFRPXG5cdFx0Zm9yYmlkTm9uV2hpdGVsaXN0ZWQ6IHRydWUsIC8vIHh14bqldCBoaeG7h24gcHJvcGVydHkga2jDtG5nIGPDsyB0cm9uZyBEVE8gc+G6vSBi4bqvdCBs4buXaVxuXHRcdHRyYW5zZm9ybTogdHJ1ZSwgLy8gdXNlIGZvciBEVE9cblx0XHR0cmFuc2Zvcm1PcHRpb25zOiB7XG5cdFx0XHRleGNsdWRlRXh0cmFuZW91c1ZhbHVlczogZmFsc2UsIC8vIGV4Y2x1ZGUgZmllbGQgbm90IGluIGNsYXNzIERUTyA9PiBub1xuXHRcdFx0ZXhwb3NlVW5zZXRGaWVsZHM6IGZhbHNlLCAvLyBleHBvc2UgZmllbGQgdW5kZWZpbmVkIGluIERUTyA9PiBub1xuXHRcdH0sXG5cdFx0ZXhjZXB0aW9uRmFjdG9yeTogKGVycm9yczogVmFsaWRhdGlvbkVycm9yW10gPSBbXSkgPT4gbmV3IFZhbGlkYXRpb25FeGNlcHRpb24oZXJyb3JzKSxcblx0fSkpXG5cblx0aWYgKGNvbmZpZ1NlcnZpY2UuZ2V0KCdOT0RFX0VOVicpICE9PSAncHJvZHVjdGlvbicpIHtcblx0XHRzZXR1cFN3YWdnZXIoYXBwKVxuXHR9XG5cblx0YXdhaXQgYXBwLmxpc3RlbihQT1JULCAoKSA9PiB7XG5cdFx0Y29uc29sZS5sb2coYPCfmoAgU2VydmVyIGRvY3VtZW50OiBodHRwOi8vJHtIT1NUfToke1BPUlR9L2RvY3VtZW50YClcblx0fSlcbn1cbmJvb3RzdHJhcCgpXG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=