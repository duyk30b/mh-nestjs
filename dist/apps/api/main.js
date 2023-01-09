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

/***/ "./apps/api/src/decorators/request.decorator.ts":
/*!******************************************************!*\
  !*** ./apps/api/src/decorators/request.decorator.ts ***!
  \******************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CidRequest = exports.IpRequest = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const request_ip_1 = __webpack_require__(/*! request-ip */ "request-ip");
exports.IpRequest = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return (0, request_ip_1.getClientIp)(request);
});
exports.CidRequest = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.tokenPayload.cid;
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
    logging: process.env.NODE_ENV !== 'production',
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
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AdmissionController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const request_decorator_1 = __webpack_require__(/*! ../../decorators/request.decorator */ "./apps/api/src/decorators/request.decorator.ts");
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
    async create(createAdmissionDto, cid) {
        return await this.admissionService.create(cid, createAdmissionDto);
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
    __param(1, (0, request_decorator_1.CidRequest)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof admission_dto_1.CreateAdmissionDto !== "undefined" && admission_dto_1.CreateAdmissionDto) === "function" ? _b : Object, Number]),
    __metadata("design:returntype", Promise)
], AdmissionController.prototype, "create", null);
__decorate([
    (0, common_1.Patch)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_c = typeof admission_dto_1.UpdateAdmissionDto !== "undefined" && admission_dto_1.UpdateAdmissionDto) === "function" ? _c : Object]),
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
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateAdmissionDto = exports.CreateAdmissionDto = exports.PatientDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const base_entity_1 = __webpack_require__(/*! ../../../../../typeorm/base.entity */ "./typeorm/base.entity.ts");
class PatientDto {
}
__decorate([
    (0, swagger_1.ApiPropertyOptional)({ example: '' }),
    (0, class_transformer_1.Expose)(),
    (0, class_transformer_1.Type)(() => Number),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], PatientDto.prototype, "id", void 0);
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
exports.PatientDto = PatientDto;
class CreateAdmissionDto {
}
__decorate([
    (0, swagger_1.ApiProperty)({ type: PatientDto }),
    (0, class_transformer_1.Expose)(),
    (0, class_validator_1.ValidateNested)({ each: true }),
    (0, class_transformer_1.Type)(() => PatientDto),
    __metadata("design:type", PatientDto)
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
const patient_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/patient.entity */ "./typeorm/entities/patient.entity.ts");
const admission_controller_1 = __webpack_require__(/*! ./admission.controller */ "./apps/api/src/modules/admission/admission.controller.ts");
const admission_service_1 = __webpack_require__(/*! ./admission.service */ "./apps/api/src/modules/admission/admission.service.ts");
let AdmissionModule = class AdmissionModule {
};
AdmissionModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([admission_entity_1.default, patient_entity_1.default])],
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
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AdmissionService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const admission_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/admission.entity */ "./typeorm/entities/admission.entity.ts");
const patient_entity_1 = __webpack_require__(/*! ../../../../../typeorm/entities/patient.entity */ "./typeorm/entities/patient.entity.ts");
let AdmissionService = class AdmissionService {
    constructor(admissionRepository, patientRepository) {
        this.admissionRepository = admissionRepository;
        this.patientRepository = patientRepository;
    }
    findAll() {
        return `This action returns all admission`;
    }
    findOne(id) {
        return `This action returns a #${id} admission`;
    }
    async create(clinicId, createAdmissionDto) {
        const admission = (0, class_transformer_1.plainToInstance)(admission_entity_1.default, createAdmissionDto, { exposeUnsetFields: false });
        admission.clinicId = clinicId;
        admission.patient.clinicId = clinicId;
        if (!admission.patient.id) {
            admission.patient = await this.patientRepository.save(admission.patient);
        }
        else {
            admission.patient = await this.patientRepository.findOneBy({ id: admission.patient.id });
        }
        admission.patientId = admission.patient.id;
        return await this.admissionRepository.save(admission);
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
    __param(1, (0, typeorm_1.InjectRepository)(patient_entity_1.default)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object])
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
const request_decorator_1 = __webpack_require__(/*! ../../decorators/request.decorator */ "./apps/api/src/decorators/request.decorator.ts");
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
    __param(1, (0, request_decorator_1.IpRequest)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof auth_dto_1.RegisterDto !== "undefined" && auth_dto_1.RegisterDto) === "function" ? _c : Object, String]),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, request_decorator_1.IpRequest)()),
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
    __param(1, (0, request_decorator_1.IpRequest)()),
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
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", Number)
], BaseEntity.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({ name: 'created_at' }),
    (0, class_transformer_1.Expose)({ name: 'created_at' }),
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
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../base.entity */ "./typeorm/base.entity.ts");
const patient_entity_1 = __webpack_require__(/*! ./patient.entity */ "./typeorm/entities/patient.entity.ts");
let AdmissionEntity = class AdmissionEntity extends base_entity_1.BaseEntity {
};
__decorate([
    (0, typeorm_1.Column)({ name: 'clinic_id' }),
    (0, class_transformer_1.Exclude)(),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "clinicId", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'patient_id' }),
    (0, class_transformer_1.Expose)({ name: 'patient_id' }),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "patientId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(type => patient_entity_1.default, { createForeignKeyConstraints: false }),
    (0, typeorm_1.JoinColumn)({ name: 'patient_id', referencedColumnName: 'id' }),
    (0, class_transformer_1.Type)(() => patient_entity_1.default),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", typeof (_a = typeof patient_entity_1.default !== "undefined" && patient_entity_1.default) === "function" ? _a : Object)
], AdmissionEntity.prototype, "patient", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'reason', nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "reason", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'medical_record', type: 'text', nullable: true }),
    (0, class_transformer_1.Expose)({ name: 'medical_record' }),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "medicalRecord", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "diagnosis", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'tinyint', unsigned: true, nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "pulse", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'float', precision: 3, scale: 1, nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "temperature", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'blood_pressure', length: 10, nullable: true }),
    (0, class_transformer_1.Expose)({ name: 'blood_pressure' }),
    __metadata("design:type", String)
], AdmissionEntity.prototype, "bloodPressure", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'respiratory_rate', type: 'tinyint', nullable: true }),
    (0, class_transformer_1.Expose)({ name: 'respiratory_rate' }),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "respiratoryRate", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'tinyint', nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", Number)
], AdmissionEntity.prototype, "spO2", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    (0, class_transformer_1.Expose)(),
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
    (0, typeorm_1.ManyToOne)(type => clinic_entity_1.default, { createForeignKeyConstraints: false }),
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
    (0, class_transformer_1.Expose)({ name: 'full_name' }),
    __metadata("design:type", String)
], PatientEntity.prototype, "fullName", void 0);
__decorate([
    (0, typeorm_1.Column)({ length: 10, nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", String)
], PatientEntity.prototype, "phone", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'date', nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], PatientEntity.prototype, "birthday", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'enum', enum: base_entity_1.EGender, nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", typeof (_b = typeof base_entity_1.EGender !== "undefined" && base_entity_1.EGender) === "function" ? _b : Object)
], PatientEntity.prototype, "gender", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    (0, class_transformer_1.Expose)(),
    __metadata("design:type", String)
], PatientEntity.prototype, "address", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'health_history', type: 'text', nullable: true }),
    (0, class_transformer_1.Expose)({ name: 'health_history' }),
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXBwc1xcYXBpXFxtYWluLmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsNkVBQWtIO0FBQ2xILDZFQUF5RDtBQUN6RCx1RUFBOEM7QUFDOUMsZ0ZBQStDO0FBQy9DLGdFQUFvQztBQUNwQyxtR0FBOEM7QUFDOUMsd0lBQWlFO0FBQ2pFLHFMQUE2RjtBQUM3RixtSkFBc0U7QUFDdEUsMEhBQXVEO0FBQ3ZELG9JQUE2RDtBQUM3RCw4SUFBbUU7QUFDbkUsb0lBQTZEO0FBQzdELDhJQUFtRTtBQUNuRSx5SUFBZ0U7QUE4QnpELElBQU0sU0FBUyxHQUFmLE1BQU0sU0FBUztJQUNyQixZQUFvQixVQUFzQjtRQUF0QixlQUFVLEdBQVYsVUFBVSxDQUFZO0lBQUksQ0FBQztJQUMvQyxTQUFTLENBQUMsUUFBNEI7UUFDckMsUUFBUSxDQUFDLEtBQUssQ0FBQyxvQ0FBZ0IsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUM7UUFFL0MsUUFBUSxDQUFDLEtBQUssQ0FBQyxnRUFBNkIsQ0FBQzthQUMzQyxPQUFPLENBQ1AsV0FBVyxFQUNYLEdBQUcsRUFDSCxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFLHNCQUFhLENBQUMsR0FBRyxFQUFFLENBQzdDO2FBQ0EsU0FBUyxDQUFDLEdBQUcsQ0FBQztJQUNqQixDQUFDO0NBQ0Q7QUFiWSxTQUFTO0lBNUJyQixtQkFBTSxFQUFDO1FBQ1AsT0FBTyxFQUFFO1lBQ1IscUJBQVksQ0FBQyxPQUFPLENBQUM7Z0JBQ3BCLFdBQVcsRUFBRSxDQUFDLFFBQVEsT0FBTyxDQUFDLEdBQUcsQ0FBQyxRQUFRLElBQUksT0FBTyxFQUFFLEVBQUUsTUFBTSxDQUFDO2dCQUNoRSxRQUFRLEVBQUUsSUFBSTthQUNkLENBQUM7WUFDRix1QkFBYSxDQUFDLFlBQVksQ0FBQztnQkFDMUIsT0FBTyxFQUFFLENBQUMscUJBQVksQ0FBQyxVQUFVLENBQUMsNEJBQWEsQ0FBQyxDQUFDO2dCQUNqRCxNQUFNLEVBQUUsQ0FBQyw0QkFBYSxDQUFDLEdBQUcsQ0FBQztnQkFDM0IsVUFBVSxFQUFFLENBQUMsYUFBK0MsRUFBRSxFQUFFLENBQUMsYUFBYTthQUc5RSxDQUFDO1lBQ0YsNEJBQVk7WUFDWix3QkFBVTtZQUNWLGtDQUFlO1lBQ2YsZ0NBQWM7WUFDZCw4QkFBYTtZQUNiLDRCQUFZO1lBQ1osZ0NBQWM7U0FDZDtRQUNELFNBQVMsRUFBRTtZQUNWO2dCQUNDLE9BQU8sRUFBRSxzQkFBZTtnQkFDeEIsUUFBUSxFQUFFLG1DQUEwQjthQUNwQztTQUNEO0tBQ0QsQ0FBQzt5REFFK0Isb0JBQVUsb0JBQVYsb0JBQVU7R0FEOUIsU0FBUyxDQWFyQjtBQWJZLDhCQUFTOzs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQzVDdEIsd0ZBQXdHO0FBR2pHLElBQU0sT0FBTyxHQUFiLE1BQU0sT0FBTztJQUNuQixRQUFRLENBQUMsSUFBWSxFQUFFLElBQXlCO1FBQy9DLElBQUksT0FBTyxJQUFJLEtBQUssUUFBUSxJQUFJLElBQUksQ0FBQyxNQUFNLEtBQUssRUFBRTtZQUFFLE9BQU8sS0FBSztRQUNoRSxPQUFPLGtDQUFrQyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUM7SUFDckQsQ0FBQztJQUVELGNBQWMsQ0FBQyxJQUF5QjtRQUN2QyxPQUFPLHVDQUF1QztJQUMvQyxDQUFDO0NBQ0Q7QUFUWSxPQUFPO0lBRG5CLHlDQUFtQixFQUFDLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxLQUFLLEVBQUUsS0FBSyxFQUFFLENBQUM7R0FDMUMsT0FBTyxDQVNuQjtBQVRZLDBCQUFPO0FBWWIsSUFBTSxPQUFPLEdBQWIsTUFBTSxPQUFPO0lBQ25CLFFBQVEsQ0FBQyxJQUFZLEVBQUUsSUFBeUI7UUFDL0MsSUFBSSxPQUFPLElBQUksS0FBSyxRQUFRO1lBQUUsT0FBTyxLQUFLO1FBQzFDLE9BQU8scUNBQXFDLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQztJQUN4RCxDQUFDO0lBRUQsY0FBYyxDQUFDLElBQXlCO1FBQ3ZDLE9BQU8scUNBQXFDO0lBQzdDLENBQUM7Q0FDRDtBQVRZLE9BQU87SUFEbkIseUNBQW1CLEVBQUMsRUFBRSxJQUFJLEVBQUUsU0FBUyxFQUFFLEtBQUssRUFBRSxLQUFLLEVBQUUsQ0FBQztHQUMxQyxPQUFPLENBU25CO0FBVFksMEJBQU87Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDZHBCLGdGQUFnRTtBQUV6RCxNQUFNLFlBQVksR0FBRyxDQUFDLEdBQXFCLEVBQUUsRUFBRTtJQUNyRCxNQUFNLE1BQU0sR0FBRyxJQUFJLHlCQUFlLEVBQUU7U0FDbEMsUUFBUSxDQUFDLFlBQVksQ0FBQztTQUN0QixjQUFjLENBQUMsMEJBQTBCLENBQUM7U0FDMUMsVUFBVSxDQUFDLEtBQUssQ0FBQztTQUNqQixhQUFhLENBQ2IsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLFdBQVcsRUFBRSxjQUFjLEVBQUUsRUFDN0MsY0FBYyxDQUNkO1NBQ0EsS0FBSyxFQUFFO0lBQ1QsTUFBTSxRQUFRLEdBQUcsdUJBQWEsQ0FBQyxjQUFjLENBQUMsR0FBRyxFQUFFLE1BQU0sQ0FBQztJQUMxRCx1QkFBYSxDQUFDLEtBQUssQ0FBQyxVQUFVLEVBQUUsR0FBRyxFQUFFLFFBQVEsQ0FBQztBQUMvQyxDQUFDO0FBWlksb0JBQVksZ0JBWXhCOzs7Ozs7Ozs7Ozs7OztBQ2ZELDZFQUF1RTtBQUV2RSx5RUFBd0M7QUFHM0IsaUJBQVMsR0FBRyxpQ0FBb0IsRUFBQyxDQUFDLElBQWEsRUFBRSxHQUFxQixFQUFFLEVBQUU7SUFDdEYsTUFBTSxPQUFPLEdBQVksR0FBRyxDQUFDLFlBQVksRUFBRSxDQUFDLFVBQVUsRUFBRTtJQUN4RCxPQUFPLDRCQUFXLEVBQUMsT0FBTyxDQUFDO0FBQzVCLENBQUMsQ0FBQztBQUVXLGtCQUFVLEdBQUcsaUNBQW9CLEVBQUMsQ0FBQyxJQUFhLEVBQUUsR0FBcUIsRUFBRSxFQUFFO0lBQ3ZGLE1BQU0sT0FBTyxHQUFpQixHQUFHLENBQUMsWUFBWSxFQUFFLENBQUMsVUFBVSxFQUFFO0lBQzdELE9BQU8sT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO0FBQ2hDLENBQUMsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7QUNiRiw2RUFBMkM7QUFHOUIsaUJBQVMsR0FBRyx1QkFBVSxFQUFDLEtBQUssRUFBRSxHQUFHLEVBQUUsQ0FBQyxDQUFDO0lBQ2pELFNBQVMsRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLGNBQWM7SUFDckMsVUFBVSxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsZUFBZTtJQUN2QyxVQUFVLEVBQUUsTUFBTSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsZUFBZSxDQUFDO0lBQy9DLFdBQVcsRUFBRSxNQUFNLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxnQkFBZ0IsQ0FBQztDQUNqRCxDQUFDLENBQUM7QUFFVSxxQkFBYSxHQUFHLHVCQUFVLEVBQUMsU0FBUyxFQUFFLEdBQXlCLEVBQUUsQ0FBQyxDQUFDO0lBQy9FLElBQUksRUFBRSxTQUFTO0lBQ2YsSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsWUFBWTtJQUM5QixJQUFJLEVBQUUsUUFBUSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsWUFBWSxFQUFFLEVBQUUsQ0FBQztJQUM1QyxRQUFRLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxnQkFBZ0I7SUFDdEMsUUFBUSxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCO0lBQ3RDLFFBQVEsRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLGdCQUFnQjtJQUN0QyxnQkFBZ0IsRUFBRSxJQUFJO0lBQ3RCLE9BQU8sRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLFFBQVEsS0FBSyxZQUFZO0NBRTlDLENBQUMsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7QUNwQkgsSUFBWSxNQUVYO0FBRkQsV0FBWSxNQUFNO0lBQ2pCLGlDQUF1QjtBQUN4QixDQUFDLEVBRlcsTUFBTSxHQUFOLGNBQU0sS0FBTixjQUFNLFFBRWpCO0FBRUQsSUFBWSxjQUVYO0FBRkQsV0FBWSxjQUFjO0lBQ3pCLGdEQUE4QjtBQUMvQixDQUFDLEVBRlcsY0FBYyxHQUFkLHNCQUFjLEtBQWQsc0JBQWMsUUFFekI7QUFFRCxJQUFZLGNBS1g7QUFMRCxXQUFZLGNBQWM7SUFDekIsa0VBQWdEO0lBQ2hELGdEQUE4QjtJQUM5QixnREFBOEI7SUFDOUIsc0RBQW9DO0FBQ3JDLENBQUMsRUFMVyxjQUFjLEdBQWQsc0JBQWMsS0FBZCxzQkFBYyxRQUt6QjtBQUVELElBQVksV0FHWDtBQUhELFdBQVksV0FBVztJQUN0QixtRUFBb0Q7SUFDcEQsbURBQW9DO0FBQ3JDLENBQUMsRUFIVyxXQUFXLEdBQVgsbUJBQVcsS0FBWCxtQkFBVyxRQUd0QjtBQUVELElBQVksV0FHWDtBQUhELFdBQVksV0FBVztJQUN0QixzQ0FBdUI7SUFDdkIsc0NBQXVCO0FBQ3hCLENBQUMsRUFIVyxXQUFXLEdBQVgsbUJBQVcsS0FBWCxtQkFBVyxRQUd0QjtBQUVELElBQVksY0FHWDtBQUhELFdBQVksY0FBYztJQUN6Qix3REFBc0M7SUFDdEMsMkRBQXlDO0FBQzFDLENBQUMsRUFIVyxjQUFjLEdBQWQsc0JBQWMsS0FBZCxzQkFBYyxRQUd6QjtBQUVELElBQVksYUFFWDtBQUZELFdBQVksYUFBYTtJQUN4Qix5REFBd0M7QUFDekMsQ0FBQyxFQUZXLGFBQWEsR0FBYixxQkFBYSxLQUFiLHFCQUFhLFFBRXhCOzs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ2hDRCw2RUFBcUY7QUFJOUUsSUFBTSxtQkFBbUIsR0FBekIsTUFBTSxtQkFBbUI7SUFDL0IsS0FBSyxDQUFDLFNBQXdCLEVBQUUsSUFBbUI7UUFDbEQsTUFBTSxHQUFHLEdBQUcsSUFBSSxDQUFDLFlBQVksRUFBRTtRQUMvQixNQUFNLFFBQVEsR0FBRyxHQUFHLENBQUMsV0FBVyxFQUFZO1FBQzVDLE1BQU0sT0FBTyxHQUFHLEdBQUcsQ0FBQyxVQUFVLEVBQVc7UUFDekMsTUFBTSxVQUFVLEdBQUcsU0FBUyxDQUFDLFNBQVMsRUFBRTtRQUV4QyxRQUFRLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLElBQUksQ0FBQztZQUNoQyxVQUFVO1lBQ1YsT0FBTyxFQUFFLFNBQVMsQ0FBQyxXQUFXLEVBQUU7WUFDaEMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHO1lBQ2pCLFNBQVMsRUFBRSxJQUFJLElBQUksRUFBRSxDQUFDLFdBQVcsRUFBRTtTQUNuQyxDQUFDO0lBQ0gsQ0FBQztDQUNEO0FBZFksbUJBQW1CO0lBRC9CLGtCQUFLLEVBQUMsc0JBQWEsQ0FBQztHQUNSLG1CQUFtQixDQWMvQjtBQWRZLGtEQUFtQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNKaEMsNkVBQTBGO0FBSW5GLElBQU0sc0JBQXNCLEdBQTVCLE1BQU0sc0JBQXNCO0lBQ2xDLFlBQTZCLFNBQVMsSUFBSSxlQUFNLENBQUMsY0FBYyxDQUFDO1FBQW5DLFdBQU0sR0FBTixNQUFNLENBQTZCO0lBQUksQ0FBQztJQUVyRSxLQUFLLENBQUMsU0FBZ0IsRUFBRSxJQUFtQjtRQUMxQyxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsWUFBWSxFQUFFO1FBQy9CLE1BQU0sUUFBUSxHQUFHLEdBQUcsQ0FBQyxXQUFXLEVBQVk7UUFDNUMsTUFBTSxPQUFPLEdBQUcsR0FBRyxDQUFDLFVBQVUsRUFBVztRQUN6QyxNQUFNLFVBQVUsR0FBRyxtQkFBVSxDQUFDLHFCQUFxQjtRQUVuRCxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDO1FBRWxDLFFBQVEsQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFDLENBQUMsSUFBSSxDQUFDO1lBQ2hDLFVBQVU7WUFDVixPQUFPLEVBQUUsU0FBUyxDQUFDLE9BQU87WUFDMUIsSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHO1lBQ2pCLFNBQVMsRUFBRSxJQUFJLElBQUksRUFBRSxDQUFDLFdBQVcsRUFBRTtTQUNuQyxDQUFDO0lBQ0gsQ0FBQztDQUNEO0FBbEJZLHNCQUFzQjtJQURsQyxrQkFBSyxFQUFDLEtBQUssQ0FBQzs7R0FDQSxzQkFBc0IsQ0FrQmxDO0FBbEJZLHdEQUFzQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNKbkMsNkVBQW1HO0FBRW5HLDJIQUFpRDtBQUVqRCxNQUFhLG1CQUFvQixTQUFRLEtBQUs7SUFFN0MsWUFBWSxtQkFBc0MsRUFBRTtRQUNuRCxLQUFLLENBQUMsK0JBQWMsQ0FBQyxNQUFNLENBQUM7UUFDNUIsSUFBSSxDQUFDLE1BQU0sR0FBRyxnQkFBZ0I7SUFDL0IsQ0FBQztJQUNELFVBQVU7UUFDVCxPQUFPLElBQUksQ0FBQyxPQUFPO0lBQ3BCLENBQUM7SUFDRCxTQUFTO1FBQ1IsT0FBTyxJQUFJLENBQUMsTUFBTTtJQUNuQixDQUFDO0NBQ0Q7QUFaRCxrREFZQztBQUdNLElBQU0seUJBQXlCLEdBQS9CLE1BQU0seUJBQXlCO0lBQ3JDLEtBQUssQ0FBQyxTQUE4QixFQUFFLElBQW1CO1FBQ3hELE1BQU0sR0FBRyxHQUFHLElBQUksQ0FBQyxZQUFZLEVBQUU7UUFDL0IsTUFBTSxRQUFRLEdBQUcsR0FBRyxDQUFDLFdBQVcsRUFBWTtRQUM1QyxNQUFNLE9BQU8sR0FBRyxHQUFHLENBQUMsVUFBVSxFQUFXO1FBQ3pDLE1BQU0sVUFBVSxHQUFHLG1CQUFVLENBQUMsb0JBQW9CO1FBQ2xELE1BQU0sT0FBTyxHQUFHLFNBQVMsQ0FBQyxVQUFVLEVBQUU7UUFDdEMsTUFBTSxNQUFNLEdBQUcsU0FBUyxDQUFDLFNBQVMsRUFBRTtRQUVwQyxRQUFRLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLElBQUksQ0FBQztZQUNoQyxVQUFVO1lBQ1YsT0FBTztZQUNQLE1BQU07WUFDTixJQUFJLEVBQUUsT0FBTyxDQUFDLEdBQUc7WUFDakIsU0FBUyxFQUFFLElBQUksSUFBSSxFQUFFLENBQUMsV0FBVyxFQUFFO1NBQ25DLENBQUM7SUFDSCxDQUFDO0NBQ0Q7QUFqQlkseUJBQXlCO0lBRHJDLGtCQUFLLEVBQUMsbUJBQW1CLENBQUM7R0FDZCx5QkFBeUIsQ0FpQnJDO0FBakJZLDhEQUF5Qjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDbkJ0Qyw2RUFBdUY7QUFDdkYsdUVBQXdDO0FBSWpDLE1BQU0sS0FBSyxHQUFHLENBQUMsR0FBRyxLQUFjLEVBQUUsRUFBRSxDQUFDLHdCQUFXLEVBQUMsYUFBYSxFQUFFLEtBQUssQ0FBQztBQUFoRSxhQUFLLFNBQTJEO0FBR3RFLElBQU0sVUFBVSxHQUFoQixNQUFNLFVBQVU7SUFDdEIsWUFBb0IsU0FBb0I7UUFBcEIsY0FBUyxHQUFULFNBQVMsQ0FBVztJQUFJLENBQUM7SUFFN0MsV0FBVyxDQUFDLE9BQXlCO1FBQ3BDLE1BQU0sYUFBYSxHQUFHLElBQUksQ0FBQyxTQUFTLENBQUMsaUJBQWlCLENBQVUsYUFBYSxFQUFFO1lBQzlFLE9BQU8sQ0FBQyxVQUFVLEVBQUU7WUFDcEIsT0FBTyxDQUFDLFFBQVEsRUFBRTtTQUNsQixDQUFDO1FBQ0YsSUFBSSxDQUFDLGFBQWE7WUFBRSxPQUFPLElBQUk7UUFFL0IsTUFBTSxPQUFPLEdBQWlCLE9BQU8sQ0FBQyxZQUFZLEVBQUUsQ0FBQyxVQUFVLEVBQUU7UUFDakUsTUFBTSxFQUFFLElBQUksRUFBRSxHQUFHLE9BQU8sQ0FBQyxZQUFZO1FBRXJDLE9BQU8sYUFBYSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUM7SUFDcEMsQ0FBQztDQUNEO0FBZlksVUFBVTtJQUR0Qix1QkFBVSxHQUFFO3lEQUVtQixnQkFBUyxvQkFBVCxnQkFBUztHQUQ1QixVQUFVLENBZXRCO0FBZlksZ0NBQVU7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDUnZCLDZFQUFtRztBQUNuRyx5RUFBd0M7QUFFeEMsZ0ZBQW9DO0FBRzdCLElBQU0sb0JBQW9CLEdBQTFCLE1BQU0sb0JBQW9CO0lBQ2hDLFlBQTZCLFNBQVMsSUFBSSxlQUFNLENBQUMsWUFBWSxDQUFDO1FBQWpDLFdBQU0sR0FBTixNQUFNLENBQTJCO0lBQUksQ0FBQztJQUVuRSxTQUFTLENBQUMsT0FBeUIsRUFBRSxJQUFpQjtRQUNyRCxNQUFNLFNBQVMsR0FBRyxJQUFJLElBQUksRUFBRTtRQUM1QixNQUFNLEdBQUcsR0FBRyxPQUFPLENBQUMsWUFBWSxFQUFFO1FBQ2xDLE1BQU0sT0FBTyxHQUFHLEdBQUcsQ0FBQyxVQUFVLEVBQUU7UUFDaEMsTUFBTSxRQUFRLEdBQUcsR0FBRyxDQUFDLFVBQVUsRUFBRTtRQUVqQyxNQUFNLEVBQUUsR0FBRyxFQUFFLE1BQU0sRUFBRSxHQUFHLE9BQU87UUFDL0IsTUFBTSxFQUFFLFVBQVUsRUFBRSxHQUFHLFFBQVE7UUFDL0IsTUFBTSxFQUFFLEdBQUcsNEJBQVcsRUFBQyxPQUFPLENBQUM7UUFFL0IsT0FBTyxJQUFJLENBQUMsTUFBTSxFQUFFLENBQUMsSUFBSSxDQUFDLG1CQUFHLEVBQUMsR0FBRyxFQUFFO1lBQ2xDLE1BQU0sR0FBRyxHQUFHLEdBQUcsU0FBUyxDQUFDLFdBQVcsRUFBRSxNQUFNLEVBQUUsTUFBTSxNQUFNLE1BQU0sVUFBVSxNQUFNLEdBQUcsTUFBTSxJQUFJLENBQUMsR0FBRyxFQUFFLEdBQUcsU0FBUyxDQUFDLE9BQU8sRUFBRSxJQUFJO1lBQzdILE9BQU8sSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDO1FBQzVCLENBQUMsQ0FBQyxDQUFDO0lBQ0osQ0FBQztDQUNEO0FBbEJZLG9CQUFvQjtJQURoQyx1QkFBVSxHQUFFOztHQUNBLG9CQUFvQixDQWtCaEM7QUFsQlksb0RBQW9COzs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ05qQyw2RUFBb0g7QUFDcEgsdURBQTJEO0FBQzNELGdGQUFvRDtBQUc3QyxJQUFNLGtCQUFrQixHQUF4QixNQUFNLGtCQUFrQjtJQUM5QixTQUFTLENBQUMsT0FBeUIsRUFBRSxJQUFpQjtRQUNyRCxPQUFPLElBQUksQ0FBQyxNQUFNLEVBQUUsQ0FBQyxJQUFJLENBQ3hCLHVCQUFPLEVBQUMsS0FBSyxDQUFDLEVBQ2QsMEJBQVUsRUFBQyxHQUFHLENBQUMsRUFBRTtZQUNoQixJQUFJLEdBQUcsWUFBWSxtQkFBWSxFQUFFO2dCQUNoQyxPQUFPLHFCQUFVLEVBQUMsR0FBRyxFQUFFLENBQUMsSUFBSSxnQ0FBdUIsRUFBRSxDQUFDO2FBQ3REO1lBQ0QsT0FBTyxxQkFBVSxFQUFDLEdBQUcsRUFBRSxDQUFDLEdBQUcsQ0FBQztRQUM3QixDQUFDLENBQUMsQ0FDRjtJQUNGLENBQUM7Q0FDRDtBQVpZLGtCQUFrQjtJQUQ5Qix1QkFBVSxHQUFFO0dBQ0Esa0JBQWtCLENBWTlCO0FBWlksZ0RBQWtCOzs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ0wvQiw2RUFBMkQ7QUFJcEQsSUFBTSxnQkFBZ0IsR0FBdEIsTUFBTSxnQkFBZ0I7SUFDNUIsR0FBRyxDQUFDLEdBQVksRUFBRSxHQUFhLEVBQUUsSUFBa0I7UUFDbEQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUM7UUFDekIsSUFBSSxFQUFFO0lBQ1AsQ0FBQztDQUNEO0FBTFksZ0JBQWdCO0lBRDVCLHVCQUFVLEdBQUU7R0FDQSxnQkFBZ0IsQ0FLNUI7QUFMWSw0Q0FBZ0I7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ0o3Qiw2RUFBMkQ7QUFFM0QseUVBQXdDO0FBRXhDLGdKQUFxRTtBQUc5RCxJQUFNLDZCQUE2QixHQUFuQyxNQUFNLDZCQUE2QjtJQUN6QyxZQUE2QixnQkFBa0M7UUFBbEMscUJBQWdCLEdBQWhCLGdCQUFnQixDQUFrQjtJQUFJLENBQUM7SUFFcEUsS0FBSyxDQUFDLEdBQUcsQ0FBQyxHQUFpQixFQUFFLEdBQWEsRUFBRSxJQUFrQjtRQUM3RCxNQUFNLEVBQUUsR0FBRyw0QkFBVyxFQUFDLEdBQUcsQ0FBQztRQUMzQixNQUFNLGFBQWEsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLGVBQWUsQ0FBQyxJQUFJLEVBQUU7UUFDdkQsTUFBTSxDQUFDLEVBQUUsV0FBVyxDQUFDLEdBQUcsYUFBYSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUM7UUFDaEQsTUFBTSxNQUFNLEdBQWdCLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxpQkFBaUIsQ0FBQyxXQUFXLEVBQUUsRUFBRSxDQUFDO1FBQ3BGLEdBQUcsQ0FBQyxZQUFZLEdBQUcsTUFBTTtRQUN6QixJQUFJLEVBQUU7SUFDUCxDQUFDO0NBQ0Q7QUFYWSw2QkFBNkI7SUFEekMsdUJBQVUsR0FBRTt5REFFbUMscUNBQWdCLG9CQUFoQixxQ0FBZ0I7R0FEbkQsNkJBQTZCLENBV3pDO0FBWFksc0VBQTZCOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNQMUMsNkVBQW9HO0FBQ3BHLGdGQUF3RDtBQUN4RCw0SUFBK0Q7QUFDL0Qsd0hBQXdFO0FBQ3hFLG9JQUFzRDtBQU0vQyxJQUFNLG1CQUFtQixHQUF6QixNQUFNLG1CQUFtQjtJQUMvQixZQUE2QixnQkFBa0M7UUFBbEMscUJBQWdCLEdBQWhCLGdCQUFnQixDQUFrQjtJQUFJLENBQUM7SUFHcEUsT0FBTztRQUNOLE9BQU8sSUFBSSxDQUFDLGdCQUFnQixDQUFDLE9BQU8sRUFBRTtJQUN2QyxDQUFDO0lBR0QsT0FBTyxDQUFjLEVBQVU7UUFDOUIsT0FBTyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsT0FBTyxDQUFDLENBQUMsRUFBRSxDQUFDO0lBQzFDLENBQUM7SUFHSyxLQUFELENBQUMsTUFBTSxDQUFTLGtCQUFzQyxFQUFnQixHQUFXO1FBQ3JGLE9BQU8sTUFBTSxJQUFJLENBQUMsZ0JBQWdCLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxrQkFBa0IsQ0FBQztJQUNuRSxDQUFDO0lBR0QsTUFBTSxDQUFjLEVBQVUsRUFBVSxrQkFBc0M7UUFDN0UsT0FBTyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxFQUFFLGtCQUFrQixDQUFDO0lBQzdELENBQUM7SUFHRCxNQUFNLENBQWMsRUFBVTtRQUM3QixPQUFPLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUM7SUFDekMsQ0FBQztDQUNEO0FBeEJBO0lBQUMsZ0JBQUcsR0FBRTs7OztrREFHTDtBQUVEO0lBQUMsZ0JBQUcsRUFBQyxLQUFLLENBQUM7SUFDRiw2QkFBSyxFQUFDLElBQUksQ0FBQzs7OztrREFFbkI7QUFHSztJQURMLGlCQUFJLEdBQUU7SUFDTyw0QkFBSSxHQUFFO0lBQTBDLDZDQUFVLEdBQUU7O3lEQUFqQyxrQ0FBa0Isb0JBQWxCLGtDQUFrQjs7aURBRTFEO0FBRUQ7SUFBQyxrQkFBSyxFQUFDLEtBQUssQ0FBQztJQUNMLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsNEJBQUksR0FBRTs7aUVBQXFCLGtDQUFrQixvQkFBbEIsa0NBQWtCOztpREFFN0U7QUFFRDtJQUFDLG1CQUFNLEVBQUMsS0FBSyxDQUFDO0lBQ04sNkJBQUssRUFBQyxJQUFJLENBQUM7Ozs7aURBRWxCO0FBMUJXLG1CQUFtQjtJQUovQixxQkFBTyxFQUFDLFdBQVcsQ0FBQztJQUNwQiw2QkFBZ0IsRUFBQyxFQUFFLHVCQUF1QixFQUFFLElBQUksRUFBRSxpQkFBaUIsRUFBRSxLQUFLLEVBQUUsQ0FBQztJQUM3RSwyQkFBYSxFQUFDLGNBQWMsQ0FBQztJQUM3Qix1QkFBVSxFQUFDLFdBQVcsQ0FBQzt5REFFd0Isb0NBQWdCLG9CQUFoQixvQ0FBZ0I7R0FEbkQsbUJBQW1CLENBMkIvQjtBQTNCWSxrREFBbUI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1ZoQyxnRkFBK0U7QUFDL0UsOEZBQWdEO0FBQ2hELHdGQUFvRjtBQUNwRixnSEFBNEQ7QUFHNUQsTUFBYSxVQUFVO0NBZ0N0QjtBQS9CQTtJQUFDLGlDQUFtQixFQUFDLEVBQUUsT0FBTyxFQUFFLEVBQUUsRUFBRSxDQUFDO0lBQ3BDLDhCQUFNLEdBQUU7SUFDUiw0QkFBSSxFQUFDLEdBQUcsRUFBRSxDQUFDLE1BQU0sQ0FBQztJQUNsQiw4QkFBUSxHQUFFOztzQ0FDRDtBQUVWO0lBQUMsaUNBQW1CLEVBQUMsRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxDQUFDO0lBQ3JFLDhCQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFLENBQUM7SUFDN0IsOEJBQVEsR0FBRTs7NENBQ0s7QUFFaEI7SUFBQyxpQ0FBbUIsRUFBQyxFQUFFLE9BQU8sRUFBRSxZQUFZLEVBQUUsQ0FBQztJQUM5Qyw4QkFBTSxHQUFFO0lBQ1IsOEJBQVEsR0FBRTs7eUNBQ0U7QUFFYjtJQUFDLGlDQUFtQixFQUFDLEVBQUUsT0FBTyxFQUFFLDBCQUEwQixFQUFFLENBQUM7SUFDNUQsOEJBQU0sR0FBRTtJQUNSLDRCQUFJLEVBQUMsR0FBRyxFQUFFLENBQUMsSUFBSSxDQUFDO0lBQ2hCLDRCQUFNLEdBQUU7a0RBQ0MsSUFBSSxvQkFBSixJQUFJOzRDQUFBO0FBRWQ7SUFBQyxpQ0FBbUIsRUFBQyxFQUFFLElBQUksRUFBRSxxQkFBTyxFQUFFLE9BQU8sRUFBRSxxQkFBTyxDQUFDLE1BQU0sRUFBRSxDQUFDO0lBQy9ELDhCQUFNLEdBQUU7SUFDUiw0QkFBTSxFQUFDLHFCQUFPLENBQUM7a0RBQ1IscUJBQU8sb0JBQVAscUJBQU87MENBQUE7QUFFZjtJQUFDLGlDQUFtQixFQUFDLEVBQUUsT0FBTyxFQUFFLHVFQUF1RSxFQUFFLENBQUM7SUFDekcsOEJBQU0sR0FBRTtJQUNSLDhCQUFRLEdBQUU7OzJDQUNJO0FBL0JoQixnQ0FnQ0M7QUFFRCxNQUFhLGtCQUFrQjtDQVc5QjtBQVZBO0lBQUMseUJBQVcsRUFBQyxFQUFFLElBQUksRUFBRSxVQUFVLEVBQUUsQ0FBQztJQUNqQyw4QkFBTSxHQUFFO0lBQ1Isb0NBQWMsRUFBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUM5Qiw0QkFBSSxFQUFDLEdBQUcsRUFBRSxDQUFDLFVBQVUsQ0FBQzs4QkFDZCxVQUFVO21EQUFBO0FBRW5CO0lBQUMsaUNBQW1CLEVBQUMsRUFBRSxPQUFPLEVBQUUsb0JBQW9CLEVBQUUsQ0FBQztJQUN0RCw4QkFBTSxHQUFFO0lBQ1IsOEJBQVEsR0FBRTs7a0RBQ0c7QUFWZixnREFXQztBQUVELE1BQWEsa0JBQW1CLFNBQVEseUJBQVcsRUFBQyxrQkFBa0IsQ0FBQztDQUFJO0FBQTNFLGdEQUEyRTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNyRDNFLDZFQUF1QztBQUN2QyxnRkFBK0M7QUFDL0MsaUpBQThFO0FBQzlFLDJJQUEwRTtBQUMxRSw2SUFBNEQ7QUFDNUQsb0lBQXNEO0FBTy9DLElBQU0sZUFBZSxHQUFyQixNQUFNLGVBQWU7Q0FBSTtBQUFuQixlQUFlO0lBTDNCLG1CQUFNLEVBQUM7UUFDUCxPQUFPLEVBQUUsQ0FBQyx1QkFBYSxDQUFDLFVBQVUsQ0FBQyxDQUFDLDBCQUFlLEVBQUUsd0JBQWEsQ0FBQyxDQUFDLENBQUM7UUFDckUsV0FBVyxFQUFFLENBQUMsMENBQW1CLENBQUM7UUFDbEMsU0FBUyxFQUFFLENBQUMsb0NBQWdCLENBQUM7S0FDN0IsQ0FBQztHQUNXLGVBQWUsQ0FBSTtBQUFuQiwwQ0FBZTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDWjVCLDZFQUEyQztBQUMzQyxnRkFBa0Q7QUFDbEQsOEZBQW9FO0FBQ3BFLGdFQUFvQztBQUNwQyxpSkFBOEU7QUFDOUUsMklBQTBFO0FBSW5FLElBQU0sZ0JBQWdCLEdBQXRCLE1BQU0sZ0JBQWdCO0lBQzVCLFlBQzRDLG1CQUFnRCxFQUNsRCxpQkFBNEM7UUFEMUMsd0JBQW1CLEdBQW5CLG1CQUFtQixDQUE2QjtRQUNsRCxzQkFBaUIsR0FBakIsaUJBQWlCLENBQTJCO0lBQ2xGLENBQUM7SUFFTCxPQUFPO1FBQ04sT0FBTyxtQ0FBbUM7SUFDM0MsQ0FBQztJQUVELE9BQU8sQ0FBQyxFQUFVO1FBQ2pCLE9BQU8sMEJBQTBCLEVBQUUsWUFBWTtJQUNoRCxDQUFDO0lBRUQsS0FBSyxDQUFDLE1BQU0sQ0FBQyxRQUFnQixFQUFFLGtCQUFzQztRQUNwRSxNQUFNLFNBQVMsR0FBRyx1Q0FBZSxFQUFDLDBCQUFlLEVBQUUsa0JBQWtCLEVBQUUsRUFBRSxpQkFBaUIsRUFBRSxLQUFLLEVBQUUsQ0FBQztRQUNwRyxTQUFTLENBQUMsUUFBUSxHQUFHLFFBQVE7UUFDN0IsU0FBUyxDQUFDLE9BQU8sQ0FBQyxRQUFRLEdBQUcsUUFBUTtRQUVyQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxFQUFFLEVBQUU7WUFDMUIsU0FBUyxDQUFDLE9BQU8sR0FBRyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQztTQUN4RTthQUFNO1lBQ04sU0FBUyxDQUFDLE9BQU8sR0FBRyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxTQUFTLENBQUMsRUFBRSxFQUFFLEVBQUUsU0FBUyxDQUFDLE9BQU8sQ0FBQyxFQUFFLEVBQUUsQ0FBQztTQUN4RjtRQUVELFNBQVMsQ0FBQyxTQUFTLEdBQUcsU0FBUyxDQUFDLE9BQU8sQ0FBQyxFQUFFO1FBQzFDLE9BQU8sTUFBTSxJQUFJLENBQUMsbUJBQW1CLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQztJQUN0RCxDQUFDO0lBRUQsTUFBTSxDQUFDLEVBQVUsRUFBRSxrQkFBc0M7UUFDeEQsT0FBTywwQkFBMEIsRUFBRSxZQUFZO0lBQ2hELENBQUM7SUFFRCxNQUFNLENBQUMsRUFBVTtRQUNoQixPQUFPLDBCQUEwQixFQUFFLFlBQVk7SUFDaEQsQ0FBQztDQUNEO0FBcENZLGdCQUFnQjtJQUQ1Qix1QkFBVSxHQUFFO0lBR1YseUNBQWdCLEVBQUMsMEJBQWUsQ0FBQztJQUNqQyx5Q0FBZ0IsRUFBQyx3QkFBYSxDQUFDO3lEQURnQyxvQkFBVSxvQkFBVixvQkFBVSxvREFDZCxvQkFBVSxvQkFBVixvQkFBVTtHQUgzRCxnQkFBZ0IsQ0FvQzVCO0FBcENZLDRDQUFnQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDVDdCLDZFQUFnRjtBQUNoRixnRkFBeUM7QUFDekMsNElBQThEO0FBQzlELG9HQUFtRjtBQUNuRixnSEFBNEM7QUFDNUMsa0lBQXVEO0FBS2hELElBQU0sY0FBYyxHQUFwQixNQUFNLGNBQWM7SUFDMUIsWUFDa0IsV0FBd0IsRUFDeEIsZ0JBQWtDO1FBRGxDLGdCQUFXLEdBQVgsV0FBVyxDQUFhO1FBQ3hCLHFCQUFnQixHQUFoQixnQkFBZ0IsQ0FBa0I7SUFDaEQsQ0FBQztJQUdDLEtBQUQsQ0FBQyxRQUFRLENBQVMsV0FBd0IsRUFBZSxFQUFVO1FBQ3ZFLE1BQU0sUUFBUSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxRQUFRLENBQUMsV0FBVyxDQUFDO1FBQzdELE1BQU0sRUFBRSxXQUFXLEVBQUUsWUFBWSxFQUFFLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixDQUFDLG1CQUFtQixDQUFDLFFBQVEsRUFBRSxFQUFFLENBQUM7UUFDN0YsT0FBTyxJQUFJLHlCQUFjLENBQUMsRUFBRSxXQUFXLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDekQsQ0FBQztJQUdLLEtBQUQsQ0FBQyxLQUFLLENBQVMsUUFBa0IsRUFBZSxFQUFVO1FBQzlELE1BQU0sUUFBUSxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDO1FBQ3ZELE1BQU0sRUFBRSxXQUFXLEVBQUUsWUFBWSxFQUFFLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixDQUFDLG1CQUFtQixDQUFDLFFBQVEsRUFBRSxFQUFFLENBQUM7UUFDN0YsT0FBTyxJQUFJLHlCQUFjLENBQUMsRUFBRSxXQUFXLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDekQsQ0FBQztJQUdELE1BQU0sQ0FBYyxFQUFVO0lBRTlCLENBQUM7SUFHRCxjQUFjLENBQWMsRUFBVSxFQUFVLGFBQXVCO0lBRXZFLENBQUM7SUFHRCxjQUFjLENBQWMsRUFBVTtJQUV0QyxDQUFDO0lBR0ssS0FBRCxDQUFDLGdCQUFnQixDQUFTLGVBQWdDLEVBQWUsRUFBVTtRQUN2RixNQUFNLFdBQVcsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsZ0JBQWdCLENBQUMsZUFBZSxDQUFDLFlBQVksRUFBRSxFQUFFLENBQUM7UUFDN0YsT0FBTyxJQUFJLHlCQUFjLENBQUMsRUFBRSxXQUFXLEVBQUUsQ0FBQztJQUMzQyxDQUFDO0NBQ0Q7QUFqQ007SUFETCxpQkFBSSxFQUFDLFVBQVUsQ0FBQztJQUNELDRCQUFJLEdBQUU7SUFBNEIsNENBQVMsR0FBRTs7eURBQXpCLHNCQUFXLG9CQUFYLHNCQUFXO3dEQUE0QixPQUFPLG9CQUFQLE9BQU87OENBSWpGO0FBR0s7SUFETCxpQkFBSSxFQUFDLE9BQU8sQ0FBQztJQUNELDRCQUFJLEdBQUU7SUFBc0IsNENBQVMsR0FBRTs7eURBQXRCLG1CQUFRLG9CQUFSLG1CQUFRO3dEQUE0QixPQUFPLG9CQUFQLE9BQU87MkNBSXhFO0FBRUQ7SUFBQyxpQkFBSSxFQUFDLFFBQVEsQ0FBQztJQUNQLDZCQUFLLEVBQUMsSUFBSSxDQUFDOzs7OzRDQUVsQjtBQUVEO0lBQUMsaUJBQUksRUFBQyxpQkFBaUIsQ0FBQztJQUNSLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsNEJBQUksR0FBRTs7aUVBQWdCLG1CQUFRLG9CQUFSLG1CQUFROztvREFFdEU7QUFFRDtJQUFDLGlCQUFJLEVBQUMsaUJBQWlCLENBQUM7SUFDUiw2QkFBSyxFQUFDLElBQUksQ0FBQzs7OztvREFFMUI7QUFHSztJQURMLGlCQUFJLEVBQUMsZUFBZSxDQUFDO0lBQ0UsNEJBQUksR0FBRTtJQUFvQyw0Q0FBUyxHQUFFOzt5REFBN0IsMEJBQWUsb0JBQWYsMEJBQWU7d0RBQTRCLE9BQU8sb0JBQVAsT0FBTztzREFHakc7QUF2Q1csY0FBYztJQUgxQixxQkFBTyxFQUFDLE1BQU0sQ0FBQztJQUNmLDZCQUFnQixFQUFDLEVBQUUsdUJBQXVCLEVBQUUsSUFBSSxFQUFFLGlCQUFpQixFQUFFLEtBQUssRUFBRSxDQUFDO0lBQzdFLHVCQUFVLEVBQUMsTUFBTSxDQUFDO3lEQUdhLDBCQUFXLG9CQUFYLDBCQUFXLG9EQUNOLHFDQUFnQixvQkFBaEIscUNBQWdCO0dBSHhDLGNBQWMsQ0F3QzFCO0FBeENZLHdDQUFjOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1YzQixnRkFBNkM7QUFDN0MsOEZBQTBDO0FBQzFDLHdGQUFpRTtBQUNqRSxtSkFBc0U7QUFFdEUsTUFBYSxXQUFXO0NBdUJ2QjtBQXRCQTtJQUFDLHlCQUFXLEVBQUMsRUFBRSxPQUFPLEVBQUUscUJBQXFCLEVBQUUsQ0FBQztJQUMvQyw4QkFBTSxHQUFFO0lBQ1IsZ0NBQVUsR0FBRTtJQUNaLDhCQUFRLEVBQUMsZ0NBQU8sQ0FBQzs7MENBQ0w7QUFFYjtJQUFDLHlCQUFXLEVBQUMsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDdEMsOEJBQU0sR0FBRTtJQUNSLGdDQUFVLEdBQUU7SUFDWiw4QkFBUSxFQUFDLGdDQUFPLENBQUM7OzBDQUNMO0FBRWI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLE9BQU8sRUFBRSxDQUFDO0lBQ2pDLDhCQUFNLEdBQUU7SUFDUixnQ0FBVSxHQUFFOzs2Q0FDRztBQUVoQjtJQUFDLHlCQUFXLEVBQUMsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDdEMsOEJBQU0sR0FBRTtJQUNSLGdDQUFVLEdBQUU7SUFDWiwrQkFBUyxFQUFDLENBQUMsQ0FBQzs7NkNBQ0c7QUF0QmpCLGtDQXVCQztBQUVELE1BQWEsUUFBUTtDQWlCcEI7QUFoQkE7SUFBQyx5QkFBVyxFQUFDLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDdkQsOEJBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxTQUFTLEVBQUUsQ0FBQztJQUMzQixnQ0FBVSxHQUFFO0lBQ1osOEJBQVEsRUFBQyxnQ0FBTyxDQUFDOzt3Q0FDSjtBQUVkO0lBQUMseUJBQVcsRUFBQyxFQUFFLE9BQU8sRUFBRSxPQUFPLEVBQUUsQ0FBQztJQUNqQyw4QkFBTSxHQUFFO0lBQ1IsZ0NBQVUsR0FBRTs7MENBQ0c7QUFFaEI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQ3RDLDhCQUFNLEdBQUU7SUFDUixnQ0FBVSxHQUFFO0lBQ1osK0JBQVMsRUFBQyxDQUFDLENBQUM7OzBDQUNHO0FBaEJqQiw0QkFpQkM7QUFFRCxNQUFhLGVBQWU7Q0FLM0I7QUFKQTtJQUFDLHlCQUFXLEVBQUMsRUFBRSxJQUFJLEVBQUUsZUFBZSxFQUFFLENBQUM7SUFDdEMsOEJBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxlQUFlLEVBQUUsQ0FBQztJQUNqQyxnQ0FBVSxHQUFFOztxREFDTztBQUpyQiwwQ0FLQztBQUVELE1BQWEsY0FBYztJQU8xQixZQUFZLE9BQWdDO1FBQzNDLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQztJQUM3QixDQUFDO0NBQ0Q7QUFUQTtJQUFDLDhCQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsY0FBYyxFQUFFLENBQUM7O21EQUNkO0FBRW5CO0lBQUMsOEJBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxlQUFlLEVBQUUsQ0FBQzs7b0RBQ2Q7QUFMckIsd0NBVUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDbEVELDZFQUF1QztBQUN2Qyw2RUFBNkM7QUFDN0Msb0VBQXVDO0FBQ3ZDLGdGQUErQztBQUMvQyx3SUFBd0U7QUFDeEUsOElBQTRFO0FBQzVFLHVHQUE4QztBQUM5Qyx5SEFBa0Q7QUFDbEQsZ0hBQTRDO0FBQzVDLGtJQUF1RDtBQVloRCxJQUFNLFVBQVUsR0FBaEIsTUFBTSxVQUFVO0NBQUk7QUFBZCxVQUFVO0lBVnRCLG1CQUFNLEVBQUM7UUFDUCxPQUFPLEVBQUU7WUFDUix1QkFBYSxDQUFDLFVBQVUsQ0FBQyxDQUFDLHVCQUFZLEVBQUUseUJBQWMsQ0FBQyxDQUFDO1lBQ3hELHFCQUFZLENBQUMsVUFBVSxDQUFDLHdCQUFTLENBQUM7WUFDbEMsZUFBUztTQUNUO1FBQ0QsV0FBVyxFQUFFLENBQUMsZ0NBQWMsQ0FBQztRQUM3QixTQUFTLEVBQUUsQ0FBQywwQkFBVyxFQUFFLHFDQUFnQixDQUFDO1FBQzFDLE9BQU8sRUFBRSxDQUFDLHFDQUFnQixDQUFDO0tBQzNCLENBQUM7R0FDVyxVQUFVLENBQUk7QUFBZCxnQ0FBVTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDckJ2Qiw2RUFBc0U7QUFDdEUsMkRBQWdDO0FBQ2hDLGdFQUFvQztBQUNwQyx3SUFBd0U7QUFDeEUsOElBQXVGO0FBQ3ZGLGlKQUFvRjtBQUVwRixrSUFBdUQ7QUFHaEQsSUFBTSxXQUFXLEdBQWpCLE1BQU0sV0FBVztJQUN2QixZQUNTLFVBQXNCLEVBQ3RCLGdCQUFrQztRQURsQyxlQUFVLEdBQVYsVUFBVSxDQUFZO1FBQ3RCLHFCQUFnQixHQUFoQixnQkFBZ0IsQ0FBa0I7SUFDdkMsQ0FBQztJQUVMLEtBQUssQ0FBQyxRQUFRLENBQUMsV0FBd0I7UUFDdEMsTUFBTSxFQUFFLEtBQUssRUFBRSxLQUFLLEVBQUUsUUFBUSxFQUFFLFFBQVEsRUFBRSxHQUFHLFdBQVc7UUFDeEQsTUFBTSxZQUFZLEdBQUcsTUFBTSxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBRSxDQUFDLENBQUM7UUFFbkQsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsVUFBVSxDQUFDLFdBQVcsQ0FBQyxLQUFLLEVBQUUsT0FBTyxFQUFFLEVBQUU7WUFDcEUsTUFBTSxVQUFVLEdBQUcsTUFBTSxPQUFPLENBQUMsT0FBTyxDQUFDLHVCQUFZLEVBQUUsRUFBRSxLQUFLLEVBQUUsQ0FBQyxFQUFFLEtBQUssRUFBRSxFQUFFLEVBQUUsS0FBSyxFQUFFLENBQUMsRUFBRSxDQUFDO1lBQ3pGLElBQUksVUFBVSxFQUFFO2dCQUNmLElBQUksVUFBVSxDQUFDLEtBQUssS0FBSyxLQUFLLElBQUksVUFBVSxDQUFDLEtBQUssS0FBSyxLQUFLLEVBQUU7b0JBQzdELE1BQU0sSUFBSSxzQkFBYSxDQUFDLCtCQUFjLENBQUMsa0JBQWtCLEVBQUUsbUJBQVUsQ0FBQyxXQUFXLENBQUM7aUJBQ2xGO3FCQUNJLElBQUksVUFBVSxDQUFDLEtBQUssS0FBSyxLQUFLLEVBQUU7b0JBQ3BDLE1BQU0sSUFBSSxzQkFBYSxDQUFDLCtCQUFjLENBQUMsVUFBVSxFQUFFLG1CQUFVLENBQUMsV0FBVyxDQUFDO2lCQUMxRTtxQkFDSSxJQUFJLFVBQVUsQ0FBQyxLQUFLLEtBQUssS0FBSyxFQUFFO29CQUNwQyxNQUFNLElBQUksc0JBQWEsQ0FBQywrQkFBYyxDQUFDLFVBQVUsRUFBRSxtQkFBVSxDQUFDLFdBQVcsQ0FBQztpQkFDMUU7YUFDRDtZQUNELE1BQU0sVUFBVSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsdUJBQVksRUFBRTtnQkFDL0MsS0FBSztnQkFDTCxLQUFLO2dCQUNMLEtBQUssRUFBRSxDQUFDO2FBQ1IsQ0FBQztZQUNGLE1BQU0sU0FBUyxHQUFHLE1BQU0sT0FBTyxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUM7WUFFaEQsTUFBTSxZQUFZLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyx5QkFBYyxFQUFFO2dCQUNuRCxRQUFRLEVBQUUsU0FBUyxDQUFDLEVBQUU7Z0JBQ3RCLE1BQU0sRUFBRSxTQUFTO2dCQUNqQixRQUFRO2dCQUNSLFFBQVEsRUFBRSxZQUFZO2dCQUN0QixJQUFJLEVBQUUsdUJBQUssQ0FBQyxLQUFLO2FBQ2pCLENBQUM7WUFDRixNQUFNLFdBQVcsR0FBRyxNQUFNLE9BQU8sQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDO1lBRXBELE9BQU8sV0FBVztRQUNuQixDQUFDLENBQUM7UUFFRixPQUFPLFFBQVE7SUFDaEIsQ0FBQztJQUVELEtBQUssQ0FBQyxLQUFLLENBQUMsUUFBa0I7UUFDN0IsTUFBTSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMseUJBQWMsRUFBRTtZQUN0RSxTQUFTLEVBQUUsRUFBRSxNQUFNLEVBQUUsSUFBSSxFQUFFO1lBQzNCLEtBQUssRUFBRTtnQkFDTixRQUFRLEVBQUUsUUFBUSxDQUFDLFFBQVE7Z0JBQzNCLE1BQU0sRUFBRSxFQUFFLEtBQUssRUFBRSxRQUFRLENBQUMsTUFBTSxFQUFFO2FBQ2xDO1NBQ0QsQ0FBQztRQUNGLElBQUksQ0FBQyxRQUFRO1lBQUUsTUFBTSxJQUFJLHNCQUFhLENBQUMsNEJBQVcsQ0FBQyxvQkFBb0IsRUFBRSxtQkFBVSxDQUFDLFdBQVcsQ0FBQztRQUVoRyxNQUFNLGFBQWEsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLFFBQVEsRUFBRSxRQUFRLENBQUMsUUFBUSxDQUFDO1FBQ2hGLElBQUksQ0FBQyxhQUFhO1lBQUUsTUFBTSxJQUFJLHNCQUFhLENBQUMsNEJBQVcsQ0FBQyxhQUFhLEVBQUUsbUJBQVUsQ0FBQyxXQUFXLENBQUM7UUFFOUYsT0FBTyxRQUFRO0lBQ2hCLENBQUM7SUFFRCxLQUFLLENBQUMsZ0JBQWdCLENBQUMsWUFBb0IsRUFBRSxFQUFVO1FBQ3RELE1BQU0sRUFBRSxHQUFHLEVBQUUsR0FBRyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsa0JBQWtCLENBQUMsWUFBWSxFQUFFLEVBQUUsQ0FBQztRQUUxRSxNQUFNLFFBQVEsR0FBRyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsYUFBYSxDQUFDLHlCQUFjLENBQUMsQ0FBQyxPQUFPLENBQUM7WUFDNUUsU0FBUyxFQUFFLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRTtZQUMzQixLQUFLLEVBQUUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFO1NBQ2xCLENBQUM7UUFFRixNQUFNLFdBQVcsR0FBRyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsaUJBQWlCLENBQUMsUUFBUSxFQUFFLEVBQUUsQ0FBQztRQUN6RSxPQUFPLFdBQVc7SUFDbkIsQ0FBQztDQUNEO0FBeEVZLFdBQVc7SUFEdkIsdUJBQVUsR0FBRTt5REFHUyxvQkFBVSxvQkFBVixvQkFBVSxvREFDSixxQ0FBZ0Isb0JBQWhCLHFDQUFnQjtHQUgvQixXQUFXLENBd0V2QjtBQXhFWSxrQ0FBVzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDVnhCLDZFQUFrRTtBQUNsRSw2RUFBMkM7QUFDM0Msb0VBQXdDO0FBR3hDLHVHQUE4QztBQUM5QyxpSkFBNEU7QUFFckUsSUFBTSxnQkFBZ0IsR0FBdEIsTUFBTSxnQkFBZ0I7SUFDNUIsWUFDZ0MsU0FBdUMsRUFDckQsVUFBc0I7UUFEUixjQUFTLEdBQVQsU0FBUyxDQUE4QjtRQUNyRCxlQUFVLEdBQVYsVUFBVSxDQUFZO0lBQ3BDLENBQUM7SUFFTCxpQkFBaUIsQ0FBQyxJQUFnQixFQUFFLEVBQVU7UUFDN0MsTUFBTSxXQUFXLEdBQWdCO1lBQ2hDLEVBQUU7WUFDRixNQUFNLEVBQUUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLO1lBQ3pCLEdBQUcsRUFBRSxJQUFJLENBQUMsTUFBTSxDQUFDLEVBQUU7WUFDbkIsR0FBRyxFQUFFLElBQUksQ0FBQyxFQUFFO1lBQ1osUUFBUSxFQUFFLElBQUksQ0FBQyxRQUFRO1lBQ3ZCLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSTtTQUNmO1FBQ0QsT0FBTyxJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxXQUFXLEVBQUU7WUFDeEMsTUFBTSxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsU0FBUztZQUNoQyxTQUFTLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxVQUFVO1NBQ3BDLENBQUM7SUFDSCxDQUFDO0lBRUQsa0JBQWtCLENBQUMsR0FBVyxFQUFFLEVBQVU7UUFDekMsT0FBTyxJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsRUFBRTtZQUN4QyxNQUFNLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxVQUFVO1lBQ2pDLFNBQVMsRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFdBQVc7U0FDckMsQ0FBQztJQUNILENBQUM7SUFFRCxtQkFBbUIsQ0FBQyxJQUFnQixFQUFFLEVBQVU7UUFDL0MsTUFBTSxXQUFXLEdBQUcsSUFBSSxDQUFDLGlCQUFpQixDQUFDLElBQUksRUFBRSxFQUFFLENBQUM7UUFDcEQsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLElBQUksQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDO1FBQ3pELE9BQU8sRUFBRSxXQUFXLEVBQUUsWUFBWSxFQUFFO0lBQ3JDLENBQUM7SUFFRCxpQkFBaUIsQ0FBQyxXQUFtQixFQUFFLEVBQVU7UUFDaEQsSUFBSTtZQUNILE1BQU0sVUFBVSxHQUFnQixJQUFJLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxXQUFXLEVBQUUsRUFBRSxNQUFNLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxTQUFTLEVBQUUsQ0FBQztZQUN6RyxJQUFJLFVBQVUsQ0FBQyxFQUFFLEtBQUssRUFBRSxFQUFFO2dCQUN6QixNQUFNLElBQUksc0JBQWEsQ0FBQyw0QkFBVyxDQUFDLE9BQU8sRUFBRSxtQkFBVSxDQUFDLFlBQVksQ0FBQzthQUNyRTtZQUNELE9BQU8sVUFBVTtTQUNqQjtRQUFDLE9BQU8sS0FBSyxFQUFFO1lBQ2YsSUFBSSxLQUFLLENBQUMsSUFBSSxLQUFLLG1CQUFtQixFQUFFO2dCQUN2QyxNQUFNLElBQUksc0JBQWEsQ0FBQyw0QkFBVyxDQUFDLE9BQU8sRUFBRSxtQkFBVSxDQUFDLFlBQVksQ0FBQzthQUNyRTtpQkFBTSxJQUFJLEtBQUssQ0FBQyxJQUFJLEtBQUssbUJBQW1CLEVBQUU7Z0JBQzlDLE1BQU0sSUFBSSxzQkFBYSxDQUFDLDRCQUFXLENBQUMsT0FBTyxFQUFFLG1CQUFVLENBQUMsWUFBWSxDQUFDO2FBQ3JFO1lBQ0QsTUFBTSxJQUFJLHNCQUFhLENBQUMsdUJBQU0sQ0FBQyxPQUFPLEVBQUUsbUJBQVUsQ0FBQyxxQkFBcUIsQ0FBQztTQUN6RTtJQUNGLENBQUM7SUFFRCxrQkFBa0IsQ0FBQyxZQUFvQixFQUFFLEVBQVU7UUFDbEQsSUFBSTtZQUNILE1BQU0sVUFBVSxHQUFHLElBQUksQ0FBQyxVQUFVLENBQUMsTUFBTSxDQUFDLFlBQVksRUFBRSxFQUFFLE1BQU0sRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFVBQVUsRUFBRSxDQUFDO1lBQzlGLElBQUksVUFBVSxDQUFDLEVBQUUsS0FBSyxFQUFFLEVBQUU7Z0JBQ3pCLE1BQU0sSUFBSSxzQkFBYSxDQUFDLDRCQUFXLENBQUMsT0FBTyxFQUFFLG1CQUFVLENBQUMsWUFBWSxDQUFDO2FBQ3JFO1lBQ0QsT0FBTyxVQUFVO1NBQ2pCO1FBQUMsT0FBTyxLQUFLLEVBQUU7WUFDZixJQUFJLEtBQUssQ0FBQyxJQUFJLEtBQUssbUJBQW1CLEVBQUU7Z0JBQ3ZDLE1BQU0sSUFBSSxzQkFBYSxDQUFDLDRCQUFXLENBQUMsT0FBTyxFQUFFLG1CQUFVLENBQUMsU0FBUyxDQUFDO2FBQ2xFO2lCQUFNLElBQUksS0FBSyxDQUFDLElBQUksS0FBSyxtQkFBbUIsRUFBRTtnQkFDOUMsTUFBTSxJQUFJLHNCQUFhLENBQUMsNEJBQVcsQ0FBQyxPQUFPLEVBQUUsbUJBQVUsQ0FBQyxTQUFTLENBQUM7YUFDbEU7WUFDRCxNQUFNLElBQUksc0JBQWEsQ0FBQyx1QkFBTSxDQUFDLE9BQU8sRUFBRSxtQkFBVSxDQUFDLHFCQUFxQixDQUFDO1NBQ3pFO0lBQ0YsQ0FBQztDQUNEO0FBbkVZLGdCQUFnQjtJQUUxQiw4QkFBTSxFQUFDLHdCQUFTLENBQUMsR0FBRyxDQUFDO3lEQUFvQixtQkFBVSxvQkFBVixtQkFBVSxvREFDdkIsZ0JBQVUsb0JBQVYsZ0JBQVU7R0FINUIsZ0JBQWdCLENBbUU1QjtBQW5FWSw0Q0FBZ0I7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1I3Qiw2RUFBa0Y7QUFDbEYsd0hBQWdEO0FBQ2hELDRHQUErRDtBQUMvRCxnRkFBd0Q7QUFLakQsSUFBTSxnQkFBZ0IsR0FBdEIsTUFBTSxnQkFBZ0I7SUFDNUIsWUFBNkIsYUFBNEI7UUFBNUIsa0JBQWEsR0FBYixhQUFhLENBQWU7SUFBSSxDQUFDO0lBRzlELE1BQU0sQ0FBUyxlQUFnQztRQUM5QyxPQUFPLEVBQUU7SUFDVixDQUFDO0lBR0QsT0FBTztRQUNOLE9BQU8sSUFBSSxDQUFDLGFBQWEsQ0FBQyxPQUFPLEVBQUU7SUFDcEMsQ0FBQztJQUdELE9BQU8sQ0FBYyxFQUFVO1FBQzlCLE9BQU8sSUFBSSxDQUFDLGFBQWEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxFQUFFLENBQUM7SUFDdkMsQ0FBQztJQUdELE1BQU0sQ0FBYyxFQUFVO1FBQzdCLE9BQU8sSUFBSSxDQUFDLGFBQWEsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUM7SUFDdEMsQ0FBQztDQUNEO0FBbkJBO0lBQUMsaUJBQUksR0FBRTtJQUNDLDRCQUFJLEdBQUU7O3lEQUFrQiw0QkFBZSxvQkFBZiw0QkFBZTs7OENBRTlDO0FBRUQ7SUFBQyxnQkFBRyxHQUFFOzs7OytDQUdMO0FBRUQ7SUFBQyxnQkFBRyxFQUFDLEtBQUssQ0FBQztJQUNGLDZCQUFLLEVBQUMsSUFBSSxDQUFDOzs7OytDQUVuQjtBQUVEO0lBQUMsbUJBQU0sRUFBQyxLQUFLLENBQUM7SUFDTiw2QkFBSyxFQUFDLElBQUksQ0FBQzs7Ozs4Q0FFbEI7QUFyQlcsZ0JBQWdCO0lBSDVCLHFCQUFPLEVBQUMsUUFBUSxDQUFDO0lBQ2pCLDJCQUFhLEVBQUMsY0FBYyxDQUFDO0lBQzdCLHVCQUFVLEVBQUMsUUFBUSxDQUFDO3lEQUV3Qiw4QkFBYSxvQkFBYiw4QkFBYTtHQUQ3QyxnQkFBZ0IsQ0FzQjVCO0FBdEJZLDRDQUFnQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNSN0IsZ0ZBQTZDO0FBQzdDLHdGQUFpRDtBQUVqRCxNQUFhLGVBQWU7Q0FTM0I7QUFSQTtJQUFDLDZCQUFPLEdBQUU7OzhDQUNHO0FBRWI7SUFBQyw0QkFBTSxFQUFDLEVBQUUsRUFBRSxFQUFFLENBQUM7OzhDQUNGO0FBRWI7SUFBQyw0QkFBTSxFQUFDLENBQUMsQ0FBQzs7aURBQ007QUFSakIsMENBU0M7QUFFRCxNQUFhLGVBQWdCLFNBQVEseUJBQVcsRUFBQyxlQUFlLENBQUM7Q0FBSTtBQUFyRSwwQ0FBcUU7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDZHJFLDZFQUF1QztBQUN2QyxnRkFBK0M7QUFDL0Msd0lBQXdFO0FBQ3hFLGlJQUFzRDtBQUN0RCx3SEFBZ0Q7QUFRekMsSUFBTSxZQUFZLEdBQWxCLE1BQU0sWUFBWTtDQUFJO0FBQWhCLFlBQVk7SUFOeEIsbUJBQU0sRUFBQztRQUNQLE9BQU8sRUFBRSxDQUFDLHVCQUFhLENBQUMsVUFBVSxDQUFDLENBQUMsdUJBQVksQ0FBQyxDQUFDLENBQUM7UUFDbkQsV0FBVyxFQUFFLENBQUMsb0NBQWdCLENBQUM7UUFDL0IsU0FBUyxFQUFFLENBQUMsOEJBQWEsQ0FBQztRQUMxQixPQUFPLEVBQUUsQ0FBQyw4QkFBYSxDQUFDO0tBQ3hCLENBQUM7R0FDVyxZQUFZLENBQUk7QUFBaEIsb0NBQVk7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1p6Qiw2RUFBMkM7QUFDM0MsZ0ZBQWtEO0FBQ2xELGdFQUFnRDtBQUNoRCx3SUFBd0U7QUFHakUsSUFBTSxhQUFhLEdBQW5CLE1BQU0sYUFBYTtJQUN6QixZQUN5QyxnQkFBMEMsRUFDMUUsVUFBc0I7UUFEVSxxQkFBZ0IsR0FBaEIsZ0JBQWdCLENBQTBCO1FBQzFFLGVBQVUsR0FBVixVQUFVLENBQVk7SUFDM0IsQ0FBQztJQUVMLE9BQU87UUFDTixPQUFPLGdDQUFnQztJQUN4QyxDQUFDO0lBRUQsT0FBTyxDQUFDLEVBQVU7UUFDakIsT0FBTywwQkFBMEIsRUFBRSxTQUFTO0lBQzdDLENBQUM7SUFFRCxNQUFNLENBQUMsRUFBVTtRQUNoQixPQUFPLDBCQUEwQixFQUFFLFNBQVM7SUFDN0MsQ0FBQztJQUVELE1BQU0sQ0FBQyxFQUFVO1FBQ2hCLE9BQU8sMEJBQTBCLEVBQUUsU0FBUztJQUM3QyxDQUFDO0NBQ0Q7QUFyQlksYUFBYTtJQUR6Qix1QkFBVSxHQUFFO0lBR1YseUNBQWdCLEVBQUMsdUJBQVksQ0FBQzt5REFBMkIsb0JBQVUsb0JBQVYsb0JBQVUsb0RBQ2hELG9CQUFVLG9CQUFWLG9CQUFVO0dBSG5CLGFBQWEsQ0FxQnpCO0FBckJZLHNDQUFhOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNOMUIsNkVBQXVGO0FBQ3ZGLGdGQUFrRTtBQUNsRSw4SUFBdUU7QUFDdkUsNEdBQXFEO0FBQ3JELGtIQUFnRDtBQUNoRCxvSEFBcUU7QUFDckUsZ0lBQW9EO0FBTTdDLElBQU0sa0JBQWtCLEdBQXhCLE1BQU0sa0JBQWtCO0lBQzlCLFlBQTZCLGVBQWdDO1FBQWhDLG9CQUFlLEdBQWYsZUFBZSxDQUFpQjtJQUFJLENBQUM7SUFHbEUsT0FBTyxDQUFRLE9BQXFCO1FBQ25DLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQztJQUM5QyxDQUFDO0lBR0QsTUFBTSxDQUFTLGlCQUFvQyxFQUFTLE9BQXFCO1FBQ2hGLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxPQUFPLElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLFFBQVEsRUFBRSxpQkFBaUIsQ0FBQztJQUNoRSxDQUFDO0lBSUQsT0FBTyxDQUFjLEVBQVUsRUFBUyxPQUFxQjtRQUM1RCxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUc7UUFDekMsT0FBTyxJQUFJLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDbkQsQ0FBQztJQUlLLEtBQUQsQ0FBQyxNQUFNLENBQWMsRUFBVSxFQUFTLE9BQXFCLEVBQVUsaUJBQW9DO1FBQy9HLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxNQUFNLElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLFFBQVEsRUFBRSxDQUFDLEVBQUUsRUFBRSxpQkFBaUIsQ0FBQztRQUNuRSxPQUFPLEVBQUUsT0FBTyxFQUFFLFNBQVMsRUFBRTtJQUM5QixDQUFDO0lBSUssS0FBRCxDQUFDLE1BQU0sQ0FBYyxFQUFVLEVBQVMsT0FBcUI7UUFDakUsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLE1BQU0sSUFBSSxDQUFDLGVBQWUsQ0FBQyxNQUFNLENBQUMsUUFBUSxFQUFFLENBQUMsRUFBRSxDQUFDO1FBQ2hELE9BQU8sRUFBRSxPQUFPLEVBQUUsU0FBUyxFQUFFO0lBQzlCLENBQUM7SUFJSyxLQUFELENBQUMsT0FBTyxDQUFjLEVBQVUsRUFBUyxPQUFxQjtRQUNsRSxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUc7UUFDekMsTUFBTSxJQUFJLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsQ0FBQyxFQUFFLENBQUM7UUFDakQsT0FBTyxFQUFFLE9BQU8sRUFBRSxTQUFTLEVBQUU7SUFDOUIsQ0FBQztDQUNEO0FBMUNBO0lBQUMsZ0JBQUcsR0FBRTtJQUNHLDJCQUFHLEdBQUU7O3lEQUFVLHdCQUFZLG9CQUFaLHdCQUFZOztpREFHbkM7QUFFRDtJQUFDLGlCQUFJLEdBQUU7SUFDQyw0QkFBSSxHQUFFO0lBQXdDLDJCQUFHLEdBQUU7O3lEQUF6QixnQ0FBaUIsb0JBQWpCLGdDQUFpQixvREFBa0Isd0JBQVksb0JBQVosd0JBQVk7O2dEQUdoRjtBQUVEO0lBQUMsZ0JBQUcsRUFBQyxLQUFLLENBQUM7SUFDVixzQkFBUSxFQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDNUIsNkJBQUssRUFBQyxJQUFJLENBQUM7SUFBYywyQkFBRyxHQUFFOztpRUFBVSx3QkFBWSxvQkFBWix3QkFBWTs7aURBRzVEO0FBSUs7SUFGTCxrQkFBSyxFQUFDLFlBQVksQ0FBQztJQUNuQixzQkFBUSxFQUFDLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsQ0FBQyxFQUFFLENBQUM7SUFDdkIsNkJBQUssRUFBQyxJQUFJLENBQUM7SUFBYywyQkFBRyxHQUFFO0lBQXlCLDRCQUFJLEdBQUU7O2lFQUFyQix3QkFBWSxvQkFBWix3QkFBWSxvREFBNkIsZ0NBQWlCLG9CQUFqQixnQ0FBaUI7O2dEQUkvRztBQUlLO0lBRkwsbUJBQU0sRUFBQyxZQUFZLENBQUM7SUFDcEIsc0JBQVEsRUFBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUMsRUFBRSxDQUFDO0lBQ3ZCLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsMkJBQUcsR0FBRTs7aUVBQVUsd0JBQVksb0JBQVosd0JBQVk7O2dEQUlqRTtBQUlLO0lBRkwsa0JBQUssRUFBQyxhQUFhLENBQUM7SUFDcEIsc0JBQVEsRUFBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUMsRUFBRSxDQUFDO0lBQ3RCLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsMkJBQUcsR0FBRTs7aUVBQVUsd0JBQVksb0JBQVosd0JBQVk7O2lEQUlsRTtBQTVDVyxrQkFBa0I7SUFKOUIscUJBQU8sRUFBQyxVQUFVLENBQUM7SUFDbkIsMkJBQWEsRUFBQyxjQUFjLENBQUM7SUFDN0IsdUJBQUssRUFBQyx1QkFBSyxDQUFDLEtBQUssRUFBRSx1QkFBSyxDQUFDLEtBQUssQ0FBQztJQUMvQix1QkFBVSxFQUFDLFVBQVUsQ0FBQzt5REFFd0Isa0NBQWUsb0JBQWYsa0NBQWU7R0FEakQsa0JBQWtCLENBNkM5QjtBQTdDWSxnREFBa0I7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDWi9CLGdGQUEwRDtBQUMxRCx3RkFBc0Q7QUFFdEQsTUFBYSxpQkFBaUI7Q0FZN0I7QUFYQTtJQUFDLHlCQUFXLEVBQUMsRUFBRSxPQUFPLEVBQUUsZUFBZSxFQUFFLENBQUM7SUFDekMsK0JBQVMsR0FBRTs7bURBQ0k7QUFFaEI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQ3RDLCtCQUFTLEdBQUU7SUFDWCwrQkFBUyxFQUFDLENBQUMsQ0FBQzs7bURBQ0c7QUFFaEI7SUFBQyx5QkFBVyxFQUFDLEVBQUUsT0FBTyxFQUFFLGdCQUFnQixFQUFFLENBQUM7O21EQUMzQjtBQVhqQiw4Q0FZQztBQUVELE1BQWEsaUJBQWtCLFNBQVEseUJBQVcsRUFBQyxpQkFBaUIsQ0FBQztDQUFJO0FBQXpFLDhDQUF5RTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNqQnpFLDZFQUF1QztBQUN2QyxnRkFBK0M7QUFFL0MsOElBQTRFO0FBQzVFLHlJQUEwRDtBQUMxRCxnSUFBb0Q7QUFPN0MsSUFBTSxjQUFjLEdBQXBCLE1BQU0sY0FBYztDQUFJO0FBQWxCLGNBQWM7SUFMMUIsbUJBQU0sRUFBQztRQUNQLE9BQU8sRUFBRSxDQUFDLHVCQUFhLENBQUMsVUFBVSxDQUFDLENBQUMseUJBQWMsQ0FBQyxDQUFDLENBQUM7UUFDckQsV0FBVyxFQUFFLENBQUMsd0NBQWtCLENBQUM7UUFDakMsU0FBUyxFQUFFLENBQUMsa0NBQWUsQ0FBQztLQUM1QixDQUFDO0dBQ1csY0FBYyxDQUFJO0FBQWxCLHdDQUFjOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNaM0IsNkVBQTJDO0FBQzNDLHdGQUFpRDtBQUNqRCx1R0FBeUQ7QUFDekQsZ0ZBQWtEO0FBQ2xELDJEQUFnQztBQUNoQyw4RkFBZ0Q7QUFDaEQsZ0VBQW9DO0FBQ3BDLDhJQUF1RjtBQUN2RixpSkFBdUY7QUFJaEYsSUFBTSxlQUFlLEdBQXJCLE1BQU0sZUFBZTtJQUMzQixZQUFzRCxrQkFBOEM7UUFBOUMsdUJBQWtCLEdBQWxCLGtCQUFrQixDQUE0QjtJQUFJLENBQUM7SUFFekcsS0FBSyxDQUFDLE9BQU8sQ0FBQyxRQUFnQjtRQUM3QixPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLElBQUksQ0FBQyxFQUFFLEtBQUssRUFBRSxFQUFFLFFBQVEsRUFBRSxFQUFFLENBQUM7SUFDbkUsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxpQkFBb0M7UUFDbEUsTUFBTSxZQUFZLEdBQUcsTUFBTSxJQUFJLENBQUMsa0JBQWtCLENBQUMsU0FBUyxDQUFDO1lBQzVELFFBQVE7WUFDUixRQUFRLEVBQUUsaUJBQWlCLENBQUMsUUFBUTtTQUNwQyxDQUFDO1FBQ0YsSUFBSSxZQUFZLEVBQUU7WUFDakIsTUFBTSxJQUFJLDBCQUFhLENBQUMsK0JBQWMsQ0FBQyxhQUFhLEVBQUUsa0JBQVUsQ0FBQyxXQUFXLENBQUM7U0FDN0U7UUFDRCxNQUFNLFlBQVksR0FBRyxvQ0FBWSxFQUFDLHlCQUFjLEVBQUUsaUJBQWlCLENBQUM7UUFDcEUsWUFBWSxDQUFDLFFBQVEsR0FBRyxNQUFNLE1BQU0sQ0FBQyxJQUFJLENBQUMsaUJBQWlCLENBQUMsUUFBUSxFQUFFLENBQUMsQ0FBQztRQUN4RSxZQUFZLENBQUMsSUFBSSxHQUFHLHVCQUFLLENBQUMsSUFBSTtRQUM5QixPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQztJQUM3RCxDQUFDO0lBRUQsS0FBSyxDQUFDLE9BQU8sQ0FBQyxRQUFnQixFQUFFLEVBQVU7UUFDekMsT0FBTyxNQUFNLElBQUksQ0FBQyxrQkFBa0IsQ0FBQyxTQUFTLENBQUMsRUFBRSxRQUFRLEVBQUUsRUFBRSxFQUFFLENBQUM7SUFDakUsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxFQUFVLEVBQUUsaUJBQW9DO1FBQzlFLE1BQU0sWUFBWSxHQUFHLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLFNBQVMsQ0FBQyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsQ0FBQztRQUM5RSxJQUFJLENBQUMsWUFBWSxFQUFFO1lBQ2xCLE1BQU0sSUFBSSwwQkFBYSxDQUFDLCtCQUFjLENBQUMsU0FBUyxFQUFFLGtCQUFVLENBQUMsV0FBVyxDQUFDO1NBQ3pFO1FBQ0QsT0FBTyxNQUFNLElBQUksQ0FBQyxrQkFBa0IsQ0FBQyxNQUFNLENBQUMsRUFBRSxRQUFRLEVBQUUsRUFBRSxFQUFFLEVBQUUsaUJBQWlCLENBQUM7SUFDakYsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQUMsUUFBZ0IsRUFBRSxVQUFrQjtRQUNoRCxPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLFVBQVUsQ0FBQztZQUMvQyxRQUFRO1lBQ1IsRUFBRSxFQUFFLFVBQVU7U0FDZCxDQUFDO0lBQ0gsQ0FBQztJQUVELEtBQUssQ0FBQyxPQUFPLENBQUMsUUFBZ0IsRUFBRSxVQUFrQjtRQUNqRCxPQUFPLE1BQU0sSUFBSSxDQUFDLGtCQUFrQixDQUFDLE9BQU8sQ0FBQztZQUM1QyxRQUFRO1lBQ1IsRUFBRSxFQUFFLFVBQVU7U0FDZCxDQUFDO0lBQ0gsQ0FBQztDQUNEO0FBOUNZLGVBQWU7SUFEM0IsdUJBQVUsR0FBRTtJQUVDLHlDQUFnQixFQUFDLHlCQUFjLENBQUM7eURBQTZCLG9CQUFVLG9CQUFWLG9CQUFVO0dBRHhFLGVBQWUsQ0E4QzNCO0FBOUNZLDBDQUFlOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNaNUIsNkVBQWdEO0FBQ2hELGdGQUF5QztBQUN6QyxtRkFHeUI7QUFJbEIsSUFBTSxnQkFBZ0IsR0FBdEIsTUFBTSxnQkFBZ0I7SUFDNUIsWUFDa0IsTUFBMEIsRUFDMUIsSUFBeUIsRUFDekIsRUFBMEIsRUFDMUIsSUFBeUIsRUFDekIsTUFBNkI7UUFKN0IsV0FBTSxHQUFOLE1BQU0sQ0FBb0I7UUFDMUIsU0FBSSxHQUFKLElBQUksQ0FBcUI7UUFDekIsT0FBRSxHQUFGLEVBQUUsQ0FBd0I7UUFDMUIsU0FBSSxHQUFKLElBQUksQ0FBcUI7UUFDekIsV0FBTSxHQUFOLE1BQU0sQ0FBdUI7SUFDM0MsQ0FBQztJQUlMLEtBQUs7UUFDSixNQUFNLFdBQVcsR0FBRyxPQUFPLENBQUMsUUFBUSxLQUFLLE9BQU8sQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxHQUFHO1FBQy9ELE1BQU0sZ0JBQWdCLEdBQUcsT0FBTyxDQUFDLFFBQVEsS0FBSyxPQUFPLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsR0FBRztRQUVqRSxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDO1lBQ3hCLEdBQUcsRUFBRSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLGFBQWEsRUFBRSw4QkFBOEIsQ0FBQztZQUN4RSxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLFNBQVMsQ0FBQyxVQUFVLENBQUM7WUFDbkMsR0FBRyxFQUFFLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsU0FBUyxFQUFFLEVBQUUsSUFBSSxFQUFFLFdBQVcsRUFBRSxnQkFBZ0IsRUFBRSxDQUFDO1lBQ2hGLEdBQUcsRUFBRSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLGFBQWEsRUFBRSxHQUFHLEdBQUcsSUFBSSxHQUFHLElBQUksQ0FBQztZQUM3RCxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxZQUFZLEVBQUUsR0FBRyxHQUFHLElBQUksR0FBRyxJQUFJLENBQUM7U0FDM0QsQ0FBQztJQUNILENBQUM7Q0FDRDtBQWRBO0lBQUMsZ0JBQUcsR0FBRTtJQUNMLDBCQUFXLEdBQUU7Ozs7NkNBWWI7QUF0QlcsZ0JBQWdCO0lBRjVCLHFCQUFPLEVBQUMsUUFBUSxDQUFDO0lBQ2pCLHVCQUFVLEVBQUMsUUFBUSxDQUFDO3lEQUdNLDZCQUFrQixvQkFBbEIsNkJBQWtCLG9EQUNwQiw4QkFBbUIsb0JBQW5CLDhCQUFtQixvREFDckIsaUNBQXNCLG9CQUF0QixpQ0FBc0Isb0RBQ3BCLDhCQUFtQixvQkFBbkIsOEJBQW1CLG9EQUNqQixnQ0FBcUIsb0JBQXJCLGdDQUFxQjtHQU5uQyxnQkFBZ0IsQ0F1QjVCO0FBdkJZLDRDQUFnQjs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNUN0IsMEVBQTBDO0FBQzFDLDZFQUF1QztBQUN2QyxtRkFBaUQ7QUFDakQsaUlBQXNEO0FBTS9DLElBQU0sWUFBWSxHQUFsQixNQUFNLFlBQVk7Q0FBSTtBQUFoQixZQUFZO0lBSnhCLG1CQUFNLEVBQUM7UUFDUCxPQUFPLEVBQUUsQ0FBQyx5QkFBYyxFQUFFLGtCQUFVLENBQUM7UUFDckMsV0FBVyxFQUFFLENBQUMsb0NBQWdCLENBQUM7S0FDL0IsQ0FBQztHQUNXLFlBQVksQ0FBSTtBQUFoQixvQ0FBWTs7Ozs7Ozs7Ozs7Ozs7QUNUekIsTUFBYSxpQkFBaUI7Q0FBRztBQUFqQyw4Q0FBaUM7Ozs7Ozs7Ozs7Ozs7O0FDQWpDLGdGQUE2QztBQUM3Qyw2SUFBeUQ7QUFFekQsTUFBYSxpQkFBa0IsU0FBUSx5QkFBVyxFQUFDLHVDQUFpQixDQUFDO0NBQUc7QUFBeEUsOENBQXdFOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNIeEUsNkVBQWtGO0FBQ2xGLGdGQUF3RDtBQUN4RCxpSkFBNkQ7QUFDN0QsaUpBQTZEO0FBQzdELGdJQUFvRDtBQUs3QyxJQUFNLGtCQUFrQixHQUF4QixNQUFNLGtCQUFrQjtJQUM5QixZQUE2QixlQUFnQztRQUFoQyxvQkFBZSxHQUFmLGVBQWUsQ0FBaUI7SUFBSSxDQUFDO0lBR2xFLE1BQU0sQ0FBUyxpQkFBb0M7UUFDbEQsT0FBTyxJQUFJLENBQUMsZUFBZSxDQUFDLE1BQU0sQ0FBQyxpQkFBaUIsQ0FBQztJQUN0RCxDQUFDO0lBR0QsT0FBTztRQUNOLE9BQU8sSUFBSSxDQUFDLGVBQWUsQ0FBQyxPQUFPLEVBQUU7SUFDdEMsQ0FBQztJQUdELE9BQU8sQ0FBYyxFQUFVO1FBQzlCLE9BQU8sSUFBSSxDQUFDLGVBQWUsQ0FBQyxPQUFPLENBQUMsQ0FBQyxFQUFFLENBQUM7SUFDekMsQ0FBQztJQUdELE1BQU0sQ0FBYyxFQUFVLEVBQVUsaUJBQW9DO1FBQzNFLE9BQU8sSUFBSSxDQUFDLGVBQWUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLEVBQUUsaUJBQWlCLENBQUM7SUFDM0QsQ0FBQztJQUdELE1BQU0sQ0FBYyxFQUFVO1FBQzdCLE9BQU8sSUFBSSxDQUFDLGVBQWUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUM7SUFDeEMsQ0FBQztDQUNEO0FBeEJBO0lBQUMsaUJBQUksR0FBRTtJQUNDLDRCQUFJLEdBQUU7O3lEQUFvQix1Q0FBaUIsb0JBQWpCLHVDQUFpQjs7Z0RBRWxEO0FBRUQ7SUFBQyxnQkFBRyxHQUFFOzs7O2lEQUdMO0FBRUQ7SUFBQyxnQkFBRyxFQUFDLEtBQUssQ0FBQztJQUNGLDZCQUFLLEVBQUMsSUFBSSxDQUFDOzs7O2lEQUVuQjtBQUVEO0lBQUMsa0JBQUssRUFBQyxLQUFLLENBQUM7SUFDTCw2QkFBSyxFQUFDLElBQUksQ0FBQztJQUFjLDRCQUFJLEdBQUU7O2lFQUFvQix1Q0FBaUIsb0JBQWpCLHVDQUFpQjs7Z0RBRTNFO0FBRUQ7SUFBQyxtQkFBTSxFQUFDLEtBQUssQ0FBQztJQUNOLDZCQUFLLEVBQUMsSUFBSSxDQUFDOzs7O2dEQUVsQjtBQTFCVyxrQkFBa0I7SUFIOUIscUJBQU8sRUFBQyxVQUFVLENBQUM7SUFDbkIsMkJBQWEsRUFBQyxjQUFjLENBQUM7SUFDN0IsdUJBQVUsRUFBQyxVQUFVLENBQUM7eURBRXdCLGtDQUFlLG9CQUFmLGtDQUFlO0dBRGpELGtCQUFrQixDQTJCOUI7QUEzQlksZ0RBQWtCOzs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1QvQiw2RUFBdUM7QUFDdkMsZ0ZBQStDO0FBQy9DLDhJQUE0RTtBQUM1RSx5SUFBMEQ7QUFDMUQsZ0lBQW9EO0FBTzdDLElBQU0sY0FBYyxHQUFwQixNQUFNLGNBQWM7Q0FBSTtBQUFsQixjQUFjO0lBTDFCLG1CQUFNLEVBQUM7UUFDUCxPQUFPLEVBQUUsQ0FBQyx1QkFBYSxDQUFDLFVBQVUsQ0FBQyxDQUFDLHlCQUFjLENBQUMsQ0FBQyxDQUFDO1FBQ3JELFdBQVcsRUFBRSxDQUFDLHdDQUFrQixDQUFDO1FBQ2pDLFNBQVMsRUFBRSxDQUFDLGtDQUFlLENBQUM7S0FDNUIsQ0FBQztHQUNXLGNBQWMsQ0FBSTtBQUFsQix3Q0FBYzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNYM0IsNkVBQTJDO0FBS3BDLElBQU0sZUFBZSxHQUFyQixNQUFNLGVBQWU7SUFDM0IsTUFBTSxDQUFDLGlCQUFvQztRQUMxQyxPQUFPLGlDQUFpQztJQUN6QyxDQUFDO0lBRUQsT0FBTztRQUNOLE9BQU8sa0NBQWtDO0lBQzFDLENBQUM7SUFFRCxPQUFPLENBQUMsRUFBVTtRQUNqQixPQUFPLDBCQUEwQixFQUFFLFdBQVc7SUFDL0MsQ0FBQztJQUVELE1BQU0sQ0FBQyxFQUFVLEVBQUUsaUJBQW9DO1FBQ3RELE9BQU8sMEJBQTBCLEVBQUUsV0FBVztJQUMvQyxDQUFDO0lBRUQsTUFBTSxDQUFDLEVBQVU7UUFDaEIsT0FBTywwQkFBMEIsRUFBRSxXQUFXO0lBQy9DLENBQUM7Q0FDRDtBQXBCWSxlQUFlO0lBRDNCLHVCQUFVLEdBQUU7R0FDQSxlQUFlLENBb0IzQjtBQXBCWSwwQ0FBZTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDTDVCLDZFQUEySTtBQUMzSSxnRkFBNEU7QUFDNUUsNEdBQXFEO0FBQ3JELGdIQUFrRTtBQUNsRSw0SEFBa0Q7QUFNM0MsSUFBTSxpQkFBaUIsR0FBdkIsTUFBTSxpQkFBaUI7SUFDN0IsWUFBNkIsY0FBOEI7UUFBOUIsbUJBQWMsR0FBZCxjQUFjLENBQWdCO0lBQUksQ0FBQztJQUdoRSxPQUFPLENBQVEsT0FBcUI7UUFDbkMsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLE9BQU8sSUFBSSxDQUFDLGNBQWMsQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDO0lBQzdDLENBQUM7SUFJRCxNQUFNLENBQXNCLFVBQWtCLEVBQVMsT0FBcUI7UUFDM0UsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLElBQUksT0FBTyxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsRUFBRTtZQUM3QixPQUFPLElBQUksQ0FBQyxjQUFjLENBQUMsV0FBVyxDQUFDLFFBQVEsRUFBRSxVQUFVLENBQUM7U0FDNUQ7UUFDRCxPQUFPLElBQUksQ0FBQyxjQUFjLENBQUMsY0FBYyxDQUFDLFFBQVEsRUFBRSxVQUFVLENBQUM7SUFDaEUsQ0FBQztJQUdELE1BQU0sQ0FBUyxnQkFBa0MsRUFBUyxPQUFxQjtRQUM5RSxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUc7UUFDekMsT0FBTyxJQUFJLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FBQyxRQUFRLEVBQUUsZ0JBQWdCLENBQUM7SUFDOUQsQ0FBQztJQUlELE9BQU8sQ0FBYyxFQUFVLEVBQVMsT0FBcUI7UUFDNUQsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLE9BQU8sSUFBSSxDQUFDLGNBQWMsQ0FBQyxPQUFPLENBQUMsUUFBUSxFQUFFLENBQUMsRUFBRSxDQUFDO0lBQ2xELENBQUM7SUFJSyxLQUFELENBQUMsTUFBTSxDQUFjLEVBQVUsRUFBVSxnQkFBa0MsRUFBUyxPQUFxQjtRQUM3RyxNQUFNLFFBQVEsR0FBRyxPQUFPLENBQUMsWUFBWSxDQUFDLEdBQUc7UUFDekMsTUFBTSxJQUFJLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FBQyxRQUFRLEVBQUUsQ0FBQyxFQUFFLEVBQUUsZ0JBQWdCLENBQUM7UUFDakUsT0FBTyxFQUFFLE9BQU8sRUFBRSxTQUFTLEVBQUU7SUFDOUIsQ0FBQztJQUlLLEtBQUQsQ0FBQyxNQUFNLENBQWMsRUFBVSxFQUFTLE9BQXFCO1FBQ2pFLE1BQU0sUUFBUSxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsR0FBRztRQUN6QyxNQUFNLElBQUksQ0FBQyxjQUFjLENBQUMsTUFBTSxDQUFDLFFBQVEsRUFBRSxDQUFDLEVBQUUsQ0FBQztRQUMvQyxPQUFPLEVBQUUsT0FBTyxFQUFFLFNBQVMsRUFBRTtJQUM5QixDQUFDO0lBSUssS0FBRCxDQUFDLE9BQU8sQ0FBYyxFQUFVLEVBQVMsT0FBcUI7UUFDbEUsTUFBTSxRQUFRLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxHQUFHO1FBQ3pDLE1BQU0sSUFBSSxDQUFDLGNBQWMsQ0FBQyxPQUFPLENBQUMsUUFBUSxFQUFFLENBQUMsRUFBRSxDQUFDO1FBQ2hELE9BQU8sRUFBRSxPQUFPLEVBQUUsU0FBUyxFQUFFO0lBQzlCLENBQUM7Q0FDRDtBQXBEQTtJQUFDLGdCQUFHLEdBQUU7SUFDRywyQkFBRyxHQUFFOzt5REFBVSx3QkFBWSxvQkFBWix3QkFBWTs7Z0RBR25DO0FBRUQ7SUFBQyxnQkFBRyxFQUFDLFFBQVEsQ0FBQztJQUNiLHNCQUFRLEVBQUMsRUFBRSxJQUFJLEVBQUUsWUFBWSxFQUFFLE9BQU8sRUFBRSxZQUFZLEVBQUUsQ0FBQztJQUNoRCw2QkFBSyxFQUFDLFlBQVksQ0FBQztJQUFzQiwyQkFBRyxHQUFFOztpRUFBVSx3QkFBWSxvQkFBWix3QkFBWTs7K0NBTTNFO0FBRUQ7SUFBQyxpQkFBSSxHQUFFO0lBQ0MsNEJBQUksR0FBRTtJQUFzQywyQkFBRyxHQUFFOzt5REFBeEIsOEJBQWdCLG9CQUFoQiw4QkFBZ0Isb0RBQWtCLHdCQUFZLG9CQUFaLHdCQUFZOzsrQ0FHOUU7QUFFRDtJQUFDLGdCQUFHLEVBQUMsS0FBSyxDQUFDO0lBQ1Ysc0JBQVEsRUFBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUMsRUFBRSxDQUFDO0lBQzVCLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsMkJBQUcsR0FBRTs7aUVBQVUsd0JBQVksb0JBQVosd0JBQVk7O2dEQUc1RDtBQUlLO0lBRkwsa0JBQUssRUFBQyxZQUFZLENBQUM7SUFDbkIsc0JBQVEsRUFBQyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLENBQUMsRUFBRSxDQUFDO0lBQ3ZCLDZCQUFLLEVBQUMsSUFBSSxDQUFDO0lBQWMsNEJBQUksR0FBRTtJQUFzQywyQkFBRyxHQUFFOztpRUFBeEIsOEJBQWdCLG9CQUFoQiw4QkFBZ0Isb0RBQWtCLHdCQUFZLG9CQUFaLHdCQUFZOzsrQ0FJN0c7QUFJSztJQUZMLG1CQUFNLEVBQUMsWUFBWSxDQUFDO0lBQ3BCLHNCQUFRLEVBQUMsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE9BQU8sRUFBRSxDQUFDLEVBQUUsQ0FBQztJQUN2Qiw2QkFBSyxFQUFDLElBQUksQ0FBQztJQUFjLDJCQUFHLEdBQUU7O2lFQUFVLHdCQUFZLG9CQUFaLHdCQUFZOzsrQ0FJakU7QUFJSztJQUZMLGtCQUFLLEVBQUMsYUFBYSxDQUFDO0lBQ3BCLHNCQUFRLEVBQUMsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLE9BQU8sRUFBRSxDQUFDLEVBQUUsQ0FBQztJQUN0Qiw2QkFBSyxFQUFDLElBQUksQ0FBQztJQUFjLDJCQUFHLEdBQUU7O2lFQUFVLHdCQUFZLG9CQUFaLHdCQUFZOztnREFJbEU7QUF0RFcsaUJBQWlCO0lBSjdCLHFCQUFPLEVBQUMsU0FBUyxDQUFDO0lBQ2xCLDJCQUFhLEVBQUMsY0FBYyxDQUFDO0lBQzdCLDRCQUFlLEVBQUMsbUNBQTBCLENBQUM7SUFDM0MsdUJBQVUsRUFBQyxTQUFTLENBQUM7eURBRXdCLGdDQUFjLG9CQUFkLGdDQUFjO0dBRC9DLGlCQUFpQixDQXVEN0I7QUF2RFksOENBQWlCOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNWOUIsZ0ZBQWtFO0FBQ2xFLDhGQUF3QztBQUN4Qyx3RkFBK0U7QUFDL0UsZ0hBQTREO0FBQzVELG1KQUE2RDtBQUU3RCxNQUFhLGdCQUFnQjtDQXFCNUI7QUFwQkE7SUFBQyxpQ0FBbUIsRUFBQyxFQUFFLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxDQUFDO0lBQ2xELCtCQUFTLEdBQUU7O2tEQUNJO0FBRWhCO0lBQUMsaUNBQW1CLEVBQUMsRUFBRSxPQUFPLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDOUMsOEJBQVEsRUFBQyxnQ0FBTyxDQUFDOzsrQ0FDTDtBQUViO0lBQUMsaUNBQW1CLEVBQUMsRUFBRSxPQUFPLEVBQUUscUJBQU8sQ0FBQyxNQUFNLEVBQUUsQ0FBQztJQUNoRCw0QkFBTSxFQUFDLHFCQUFPLENBQUM7a0RBQ1IscUJBQU8sb0JBQVAscUJBQU87Z0RBQUE7QUFFZjtJQUFDLGlDQUFtQixFQUFDLEVBQUUsT0FBTyxFQUFFLHVGQUF1RixFQUFFLENBQUM7SUFDekgsOEJBQVEsR0FBRTs7aURBQ0k7QUFFZjtJQUFDLGlDQUFtQixFQUFDLEVBQUUsT0FBTyxFQUFFLDBCQUEwQixFQUFFLENBQUM7SUFDNUQsNEJBQUksRUFBQyxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUM7SUFDaEIsNEJBQU0sR0FBRTtrREFDQyxJQUFJLG9CQUFKLElBQUk7a0RBQUE7QUFwQmYsNENBcUJDO0FBRUQsTUFBYSxnQkFBaUIsU0FBUSx5QkFBVyxFQUFDLGdCQUFnQixDQUFDO0NBQUk7QUFBdkUsNENBQXVFOzs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQzdCdkUsNkVBQXVDO0FBQ3ZDLGdGQUErQztBQUMvQywySUFBMEU7QUFDMUUscUlBQXdEO0FBQ3hELDRIQUFrRDtBQU8zQyxJQUFNLGFBQWEsR0FBbkIsTUFBTSxhQUFhO0NBQUk7QUFBakIsYUFBYTtJQUx6QixtQkFBTSxFQUFDO1FBQ1AsT0FBTyxFQUFFLENBQUMsdUJBQWEsQ0FBQyxVQUFVLENBQUMsQ0FBQyx3QkFBYSxDQUFDLENBQUMsQ0FBQztRQUNwRCxXQUFXLEVBQUUsQ0FBQyxzQ0FBaUIsQ0FBQztRQUNoQyxTQUFTLEVBQUUsQ0FBQyxnQ0FBYyxDQUFDO0tBQzNCLENBQUM7R0FDVyxhQUFhLENBQUk7QUFBakIsc0NBQWE7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1gxQiw2RUFBdUQ7QUFDdkQsdUdBQXlEO0FBQ3pELGdGQUFrRDtBQUNsRCxnRUFBaUQ7QUFDakQsMklBQTBFO0FBQzFFLGlKQUFzRTtBQUkvRCxJQUFNLGNBQWMsR0FBcEIsTUFBTSxjQUFjO0lBQzFCLFlBQXFELGlCQUE0QztRQUE1QyxzQkFBaUIsR0FBakIsaUJBQWlCLENBQTJCO0lBQUksQ0FBQztJQUV0RyxLQUFLLENBQUMsT0FBTyxDQUFDLFFBQWdCO1FBQzdCLE1BQU0sV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLElBQUksQ0FBQyxFQUFFLEtBQUssRUFBRSxFQUFFLFFBQVEsRUFBRSxFQUFFLENBQUM7UUFDOUUsT0FBTyxXQUFXO0lBQ25CLENBQUM7SUFFRCxLQUFLLENBQUMsTUFBTSxDQUFDLFFBQWdCLEVBQUUsZ0JBQWtDO1FBQ2hFLE1BQU0sT0FBTyxHQUFHLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLElBQUksaUJBQ2hELFFBQVEsSUFDTCxnQkFBZ0IsRUFDbEI7UUFDRixPQUFPLE9BQU87SUFDZixDQUFDO0lBRUQsS0FBSyxDQUFDLE9BQU8sQ0FBQyxRQUFnQixFQUFFLEVBQVU7UUFDekMsTUFBTSxPQUFPLEdBQUcsTUFBTSxJQUFJLENBQUMsaUJBQWlCLENBQUMsU0FBUyxDQUFDLEVBQUUsUUFBUSxFQUFFLEVBQUUsRUFBRSxDQUFDO1FBQ3hFLE9BQU8sT0FBTztJQUNmLENBQUM7SUFFRCxLQUFLLENBQUMsV0FBVyxDQUFDLFFBQWdCLEVBQUUsS0FBYTtRQUNoRCxNQUFNLFdBQVcsR0FBRyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLENBQUM7WUFDckQsS0FBSyxFQUFFO2dCQUNOLFFBQVEsRUFBRSxtQkFBSyxFQUFDLFFBQVEsQ0FBQztnQkFDekIsS0FBSyxFQUFFLGtCQUFJLEVBQUMsR0FBRyxLQUFLLEdBQUcsQ0FBQzthQUN4QjtZQUNELElBQUksRUFBRSxDQUFDO1lBQ1AsSUFBSSxFQUFFLEVBQUU7U0FDUixDQUFDO1FBQ0YsT0FBTyxXQUFXO0lBQ25CLENBQUM7SUFDRCxLQUFLLENBQUMsY0FBYyxDQUFDLFFBQWdCLEVBQUUsUUFBZ0I7UUFDdEQsTUFBTSxXQUFXLEdBQUcsTUFBTSxJQUFJLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDO1lBQ3JELEtBQUssRUFBRTtnQkFDTixRQUFRLEVBQUUsbUJBQUssRUFBQyxRQUFRLENBQUM7Z0JBQ3pCLFFBQVEsRUFBRSxrQkFBSSxFQUFDLEdBQUcsUUFBUSxHQUFHLENBQUM7YUFDOUI7WUFDRCxJQUFJLEVBQUUsQ0FBQztZQUNQLElBQUksRUFBRSxFQUFFO1NBQ1IsQ0FBQztRQUNGLE9BQU8sV0FBVztJQUNuQixDQUFDO0lBRUQsS0FBSyxDQUFDLE1BQU0sQ0FBQyxRQUFnQixFQUFFLEVBQVUsRUFBRSxnQkFBa0M7UUFDNUUsTUFBTSxXQUFXLEdBQUcsTUFBTSxJQUFJLENBQUMsaUJBQWlCLENBQUMsU0FBUyxDQUFDLEVBQUUsUUFBUSxFQUFFLEVBQUUsRUFBRSxDQUFDO1FBQzVFLElBQUksQ0FBQyxXQUFXLEVBQUU7WUFDakIsTUFBTSxJQUFJLDBCQUFhLENBQUMsOEJBQWEsQ0FBQyxTQUFTLEVBQUUsbUJBQVUsQ0FBQyxXQUFXLENBQUM7U0FDeEU7UUFDRCxPQUFPLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLE1BQU0sQ0FBQyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsRUFBRSxnQkFBZ0IsQ0FBQztJQUMvRSxDQUFDO0lBRUQsS0FBSyxDQUFDLE1BQU0sQ0FBQyxRQUFnQixFQUFFLEVBQVU7UUFDeEMsT0FBTyxNQUFNLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxVQUFVLENBQUM7WUFDOUMsUUFBUTtZQUNSLEVBQUU7U0FDRixDQUFDO0lBQ0gsQ0FBQztJQUVELEtBQUssQ0FBQyxPQUFPLENBQUMsUUFBZ0IsRUFBRSxVQUFrQjtRQUNqRCxPQUFPLE1BQU0sSUFBSSxDQUFDLGlCQUFpQixDQUFDLE9BQU8sQ0FBQztZQUMzQyxRQUFRO1lBQ1IsRUFBRSxFQUFFLFVBQVU7U0FDZCxDQUFDO0lBQ0gsQ0FBQztDQUNEO0FBakVZLGNBQWM7SUFEMUIsdUJBQVUsR0FBRTtJQUVDLHlDQUFnQixFQUFDLHdCQUFhLENBQUM7eURBQTRCLG9CQUFVLG9CQUFWLG9CQUFVO0dBRHRFLGNBQWMsQ0FpRTFCO0FBakVZLHdDQUFjOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNUM0IsOEZBQW1EO0FBQ25ELGdFQUFzRztBQUV0RyxJQUFZLE9BR1g7QUFIRCxXQUFZLE9BQU87SUFDbEIsd0JBQWE7SUFDYiw0QkFBaUI7QUFDbEIsQ0FBQyxFQUhXLE9BQU8sR0FBUCxlQUFPLEtBQVAsZUFBTyxRQUdsQjtBQUlELE1BQWEsVUFBVTtDQWV0QjtBQWRBO0lBQUMsb0NBQXNCLEVBQUMsRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLENBQUM7SUFDdEMsOEJBQU0sR0FBRTs7c0NBQ0M7QUFFVjtJQUFDLDhCQUFnQixFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQ3hDLDhCQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsWUFBWSxFQUFFLENBQUM7a0RBQ3BCLElBQUksb0JBQUosSUFBSTs2Q0FBQTtBQUVmO0lBQUMsOEJBQWdCLEVBQUMsRUFBRSxJQUFJLEVBQUUsWUFBWSxFQUFFLENBQUM7a0RBQzlCLElBQUksb0JBQUosSUFBSTs2Q0FBQTtBQUVmO0lBQUMsOEJBQWdCLEVBQUMsRUFBRSxJQUFJLEVBQUUsWUFBWSxFQUFFLENBQUM7SUFDeEMsK0JBQU8sR0FBRTtrREFDQyxJQUFJLG9CQUFKLElBQUk7NkNBQUE7QUFkaEIsZ0NBZUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDekJELDhGQUF5RDtBQUN6RCxnRUFBK0Q7QUFDL0QsNEZBQTJDO0FBQzNDLDZHQUE0QztBQUc3QixJQUFNLGVBQWUsR0FBckIsTUFBTSxlQUFnQixTQUFRLHdCQUFVO0NBa0R0RDtBQWpEQTtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFLENBQUM7SUFDN0IsK0JBQU8sR0FBRTs7aURBQ007QUFFaEI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxDQUFDO0lBQzlCLDhCQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsWUFBWSxFQUFFLENBQUM7O2tEQUNkO0FBRWpCO0lBQUMsdUJBQVMsRUFBQyxJQUFJLENBQUMsRUFBRSxDQUFDLHdCQUFhLEVBQUUsRUFBRSwyQkFBMkIsRUFBRSxLQUFLLEVBQUUsQ0FBQztJQUN4RSx3QkFBVSxFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxvQkFBb0IsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUM5RCw0QkFBSSxFQUFDLEdBQUcsRUFBRSxDQUFDLHdCQUFhLENBQUM7SUFDekIsOEJBQU0sR0FBRTtrREFDQSx3QkFBYSxvQkFBYix3QkFBYTtnREFBQTtBQUV0QjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsUUFBUSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUMxQyw4QkFBTSxHQUFFOzsrQ0FDSztBQUVkO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxnQkFBZ0IsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUNoRSw4QkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLGdCQUFnQixFQUFFLENBQUM7O3NEQUNkO0FBRXJCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUMxQiw4QkFBTSxHQUFFOztrREFDUTtBQUVqQjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsU0FBUyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDO0lBQzNELDhCQUFNLEdBQUU7OzhDQUNJO0FBRWI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLE9BQU8sRUFBRSxTQUFTLEVBQUUsQ0FBQyxFQUFFLEtBQUssRUFBRSxDQUFDLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDO0lBQ2pFLDhCQUFNLEdBQUU7O29EQUNVO0FBRW5CO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLEVBQUUsRUFBRSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUM5RCw4QkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLGdCQUFnQixFQUFFLENBQUM7O3NEQUNkO0FBRXJCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxrQkFBa0IsRUFBRSxJQUFJLEVBQUUsU0FBUyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUNyRSw4QkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLGtCQUFrQixFQUFFLENBQUM7O3dEQUNkO0FBRXZCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxTQUFTLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDO0lBQzNDLDhCQUFNLEdBQUU7OzZDQUNHO0FBRVo7SUFBQyxvQkFBTSxFQUFDLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDO0lBQzFCLDhCQUFNLEdBQUU7OzZDQUNHO0FBakRRLGVBQWU7SUFEbkMsb0JBQU0sRUFBQyxXQUFXLENBQUM7R0FDQyxlQUFlLENBa0RuQztxQkFsRG9CLGVBQWU7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNOcEMsZ0VBQStDO0FBQy9DLDRGQUEyQztBQUc1QixJQUFNLFlBQVksR0FBbEIsTUFBTSxZQUFhLFNBQVEsd0JBQVU7Q0FlbkQ7QUFkQTtJQUFDLG9CQUFNLEVBQUMsRUFBRSxNQUFNLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxFQUFFLEVBQUUsUUFBUSxFQUFFLEtBQUssRUFBRSxDQUFDOzsyQ0FDekM7QUFFYjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxNQUFNLEVBQUUsSUFBSSxFQUFFLFFBQVEsRUFBRSxLQUFLLEVBQUUsQ0FBQzs7MkNBQzdCO0FBRWI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxPQUFPLEVBQUUsQ0FBQyxFQUFFLENBQUM7OzJDQUMzQjtBQUViO0lBQUMsb0JBQU0sRUFBQyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQzs7MENBQ2Y7QUFFWjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7OzZDQUNaO0FBZEssWUFBWTtJQURoQyxvQkFBTSxFQUFDLFFBQVEsQ0FBQztHQUNJLFlBQVksQ0FlaEM7cUJBZm9CLFlBQVk7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ0pqQyw4RkFBMkM7QUFDM0MsZ0VBQXNFO0FBQ3RFLDRGQUFvRDtBQUNwRCwwR0FBMEM7QUFFMUMsSUFBWSxLQUlYO0FBSkQsV0FBWSxLQUFLO0lBQ2hCLHdCQUFlO0lBQ2Ysd0JBQWU7SUFDZixzQkFBYTtBQUNkLENBQUMsRUFKVyxLQUFLLEdBQUwsYUFBSyxLQUFMLGFBQUssUUFJaEI7QUFNYyxJQUFNLGNBQWMsR0FBcEIsTUFBTSxjQUFlLFNBQVEsd0JBQVU7Q0E4QnJEO0FBN0JBO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsQ0FBQztJQUM3QiwrQkFBTyxHQUFFOztnREFDTTtBQUVoQjtJQUFDLHVCQUFTLEVBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyx1QkFBWSxFQUFFLEVBQUUsMkJBQTJCLEVBQUUsS0FBSyxFQUFFLENBQUM7SUFDdkUsd0JBQVUsRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsb0JBQW9CLEVBQUUsSUFBSSxFQUFFLENBQUM7a0RBQ3RELHVCQUFZLG9CQUFaLHVCQUFZOzhDQUFBO0FBRXBCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLE1BQU0sRUFBRSxFQUFFLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDOzs2Q0FDMUI7QUFFYjtJQUFDLG9CQUFNLEdBQUU7O2dEQUNPO0FBRWhCO0lBQUMsb0JBQU0sR0FBRTtJQUNSLCtCQUFPLEdBQUU7O2dEQUNNO0FBRWhCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsSUFBSSxFQUFFLEtBQUssRUFBRSxPQUFPLEVBQUUsS0FBSyxDQUFDLElBQUksRUFBRSxDQUFDOzs0Q0FDaEQ7QUFFWDtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsV0FBVyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQzs7Z0RBQzlCO0FBRWhCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDO2tEQUMvQixJQUFJLG9CQUFKLElBQUk7Z0RBQUE7QUFFZDtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxxQkFBTyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztrREFDaEQscUJBQU8sb0JBQVAscUJBQU87OENBQUE7QUE3QkssY0FBYztJQUZsQyxvQkFBTSxFQUFDLFVBQVUsQ0FBQztJQUNsQixtQkFBSyxFQUFDLENBQUMsVUFBVSxFQUFFLFVBQVUsQ0FBQyxFQUFFLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxDQUFDO0dBQzdCLGNBQWMsQ0E4QmxDO3FCQTlCb0IsY0FBYzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ2ZuQyxnRUFBK0M7QUFDL0MsNEZBQTJDO0FBSTVCLElBQU0sY0FBYyxHQUFwQixNQUFNLGNBQWUsU0FBUSx3QkFBVTtDQWVyRDtBQWRBO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsQ0FBQzs7Z0RBQ2Q7QUFFaEI7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7O2lEQUM5QjtBQUVqQjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsZUFBZSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQzs7b0RBQzlCO0FBRXBCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxrQkFBa0IsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7O3VEQUM5QjtBQUV2QjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQzs7NkNBQzdCO0FBZE8sY0FBYztJQUZsQyxvQkFBTSxFQUFDLFVBQVUsQ0FBQztJQUNsQixtQkFBSyxFQUFDLENBQUMsVUFBVSxFQUFFLElBQUksQ0FBQyxFQUFFLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxDQUFDO0dBQ3ZCLGNBQWMsQ0FlbEM7cUJBZm9CLGNBQWM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDTG5DLDhGQUFtRDtBQUNuRCxnRUFBK0M7QUFDL0MsNEZBQW9EO0FBS3JDLElBQU0sYUFBYSxHQUFuQixNQUFNLGFBQWMsU0FBUSx3QkFBVTtDQTRCcEQ7QUEzQkE7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLFdBQVcsRUFBRSxDQUFDO0lBQzdCLCtCQUFPLEdBQUU7OytDQUNNO0FBRWhCO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxXQUFXLEVBQUUsQ0FBQztJQUM3Qiw4QkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLFdBQVcsRUFBRSxDQUFDOzsrQ0FDZDtBQUVoQjtJQUFDLG9CQUFNLEVBQUMsRUFBRSxNQUFNLEVBQUUsRUFBRSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUN0Qyw4QkFBTSxHQUFFOzs0Q0FDSTtBQUViO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDO0lBQ3hDLDhCQUFNLEdBQUU7a0RBQ0MsSUFBSSxvQkFBSixJQUFJOytDQUFBO0FBRWQ7SUFBQyxvQkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxJQUFJLEVBQUUscUJBQU8sRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUM7SUFDdkQsOEJBQU0sR0FBRTtrREFDRCxxQkFBTyxvQkFBUCxxQkFBTzs2Q0FBQTtBQUVmO0lBQUMsb0JBQU0sRUFBQyxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUMxQiw4QkFBTSxHQUFFOzs4Q0FDTTtBQUVmO0lBQUMsb0JBQU0sRUFBQyxFQUFFLElBQUksRUFBRSxnQkFBZ0IsRUFBRSxJQUFJLEVBQUUsTUFBTSxFQUFFLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQztJQUNoRSw4QkFBTSxFQUFDLEVBQUUsSUFBSSxFQUFFLGdCQUFnQixFQUFFLENBQUM7O29EQUNkO0FBM0JELGFBQWE7SUFIakMsb0JBQU0sRUFBQyxTQUFTLENBQUM7SUFDakIsbUJBQUssRUFBQyxDQUFDLFVBQVUsRUFBRSxVQUFVLENBQUMsQ0FBQztJQUMvQixtQkFBSyxFQUFDLENBQUMsVUFBVSxFQUFFLE9BQU8sQ0FBQyxDQUFDO0dBQ1IsYUFBYSxDQTRCakM7cUJBNUJvQixhQUFhOzs7Ozs7Ozs7OztBQ1BsQzs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7O1VDQUE7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTs7VUFFQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTs7Ozs7Ozs7Ozs7O0FDdEJBLDZFQUFnRTtBQUNoRSw2RUFBOEM7QUFDOUMsdUVBQXFEO0FBQ3JELGlHQUEwQztBQUMxQyw2REFBMkI7QUFDM0Isc0VBQXVDO0FBQ3ZDLDZGQUF3QztBQUN4QyxrR0FBK0M7QUFDL0Msa0tBQStFO0FBQy9FLDJLQUFxRjtBQUNyRixvTEFBZ0g7QUFDaEgsOEdBQWlEO0FBQ2pELHlKQUEyRTtBQUMzRSxnSkFBc0U7QUFFdEUsS0FBSyxVQUFVLFNBQVM7SUFDdkIsTUFBTSxHQUFHLEdBQUcsTUFBTSxrQkFBVyxDQUFDLE1BQU0sQ0FBQyxzQkFBUyxDQUFDO0lBRS9DLE1BQU0sYUFBYSxHQUFHLEdBQUcsQ0FBQyxHQUFHLENBQUMsc0JBQWEsQ0FBQztJQUM1QyxNQUFNLElBQUksR0FBRyxhQUFhLENBQUMsR0FBRyxDQUFDLGFBQWEsQ0FBQztJQUM3QyxNQUFNLElBQUksR0FBRyxhQUFhLENBQUMsR0FBRyxDQUFDLGFBQWEsQ0FBQyxJQUFJLFdBQVc7SUFFNUQsR0FBRyxDQUFDLEdBQUcsQ0FBQyxvQkFBTSxHQUFFLENBQUM7SUFDakIsR0FBRyxDQUFDLEdBQUcsQ0FBQyxnQ0FBUyxFQUFDO1FBQ2pCLFFBQVEsRUFBRSxFQUFFLEdBQUcsSUFBSTtRQUNuQixHQUFHLEVBQUUsR0FBRztLQUNSLENBQUMsQ0FBQztJQUNILEdBQUcsQ0FBQyxVQUFVLEVBQUU7SUFFaEIsR0FBRyxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsRUFBRSxFQUFFLENBQUM7SUFFdkIsR0FBRyxDQUFDLHFCQUFxQixDQUN4QixJQUFJLDZDQUFvQixFQUFFLEVBQzFCLElBQUksd0NBQWtCLEVBQUUsQ0FDeEI7SUFDRCxHQUFHLENBQUMsZ0JBQWdCLENBQ25CLElBQUksaURBQXNCLEVBQUUsRUFDNUIsSUFBSSwyQ0FBbUIsRUFBRSxFQUN6QixJQUFJLHVEQUF5QixFQUFFLENBQy9CO0lBRUQsR0FBRyxDQUFDLGVBQWUsQ0FBQyxJQUFJLHdCQUFVLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxnQkFBUyxDQUFDLENBQUMsQ0FBQztJQUV2RCxHQUFHLENBQUMsY0FBYyxDQUFDLElBQUksdUJBQWMsQ0FBQztRQUNyQyxlQUFlLEVBQUUsRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFBRSxJQUFJLEVBQUU7UUFDL0MscUJBQXFCLEVBQUUsSUFBSTtRQUMzQixTQUFTLEVBQUUsSUFBSTtRQUNmLG9CQUFvQixFQUFFLElBQUk7UUFDMUIsU0FBUyxFQUFFLElBQUk7UUFDZixnQkFBZ0IsRUFBRTtZQUNqQix1QkFBdUIsRUFBRSxLQUFLO1lBQzlCLGlCQUFpQixFQUFFLEtBQUs7U0FDeEI7UUFDRCxnQkFBZ0IsRUFBRSxDQUFDLFNBQTRCLEVBQUUsRUFBRSxFQUFFLENBQUMsSUFBSSxpREFBbUIsQ0FBQyxNQUFNLENBQUM7S0FDckYsQ0FBQyxDQUFDO0lBRUgsSUFBSSxhQUFhLENBQUMsR0FBRyxDQUFDLFVBQVUsQ0FBQyxLQUFLLFlBQVksRUFBRTtRQUNuRCwwQkFBWSxFQUFDLEdBQUcsQ0FBQztLQUNqQjtJQUVELE1BQU0sR0FBRyxDQUFDLE1BQU0sQ0FBQyxJQUFJLEVBQUUsR0FBRyxFQUFFO1FBQzNCLE9BQU8sQ0FBQyxHQUFHLENBQUMsOEJBQThCLElBQUksSUFBSSxJQUFJLFdBQVcsQ0FBQztJQUNuRSxDQUFDLENBQUM7QUFDSCxDQUFDO0FBQ0QsU0FBUyxFQUFFIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2FwcC5tb2R1bGUudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2NvbW1vbi9jbGFzcy12YWxpZGF0b3IuY3VzdG9tLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9jb21tb24vc3dhZ2dlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZGVjb3JhdG9ycy9yZXF1ZXN0LmRlY29yYXRvci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZW52aXJvbm1lbnRzLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy9leGNlcHRpb24uZW51bS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZXhjZXB0aW9uLWZpbHRlcnMvaHR0cC1leGNlcHRpb24uZmlsdGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9leGNlcHRpb24tZmlsdGVycy91bmtub3duLWV4Y2VwdGlvbi5maWx0ZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL2V4Y2VwdGlvbi1maWx0ZXJzL3ZhbGlkYXRpb24tZXhjZXB0aW9uLmZpbHRlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvZ3VhcmRzL3JvbGVzLmd1YXJkLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9pbnRlcmNlcHRvci9hY2Nlc3MtbG9nLmludGVyY2VwdG9yLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9pbnRlcmNlcHRvci90aW1lb3V0LmludGVyY2VwdG9yLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9taWRkbGV3YXJlL2xvZ2dlci5taWRkbGV3YXJlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9taWRkbGV3YXJlL3ZhbGlkYXRlLWFjY2Vzcy10b2tlbi5taWRkbGV3YXJlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2FkbWlzc2lvbi9hZG1pc3Npb24uY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hZG1pc3Npb24vYWRtaXNzaW9uLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hZG1pc3Npb24vYWRtaXNzaW9uLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hZG1pc3Npb24vYWRtaXNzaW9uLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvYXV0aC9hdXRoLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvYXV0aC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2F1dGgvand0LWV4dGVuZC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2NsaW5pYy9jbGluaWMuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLm1vZHVsZS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9jbGluaWMvY2xpbmljLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUuY29udHJvbGxlci50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9lbXBsb3llZS9lbXBsb3llZS5kdG8udHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2VtcGxveWVlL2VtcGxveWVlLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvaGVhbHRoL2hlYWx0aC5jb250cm9sbGVyLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL2hlYWx0aC9oZWFsdGgubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL2R0by9jcmVhdGUtbWVkaWNpbmUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL2R0by91cGRhdGUtbWVkaWNpbmUuZHRvLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL21lZGljaW5lL21lZGljaW5lLnNlcnZpY2UudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LmNvbnRyb2xsZXIudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vYXBwcy9hcGkvc3JjL21vZHVsZXMvcGF0aWVudC9wYXRpZW50LmR0by50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbW9kdWxlcy9wYXRpZW50L3BhdGllbnQubW9kdWxlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL2FwcHMvYXBpL3NyYy9tb2R1bGVzL3BhdGllbnQvcGF0aWVudC5zZXJ2aWNlLnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vYmFzZS5lbnRpdHkudHMiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzLy4vdHlwZW9ybS9lbnRpdGllcy9hZG1pc3Npb24uZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy8uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2VudGl0aWVzL21lZGljaW5lLmVudGl0eS50cyIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi90eXBlb3JtL2VudGl0aWVzL3BhdGllbnQuZW50aXR5LnRzIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvYXhpb3NcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL2NvbW1vblwiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29tbW9uL2VudW1zXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb21tb24vZXhjZXB0aW9uc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcIkBuZXN0anMvY29uZmlnXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9jb3JlXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy9qd3RcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL3N3YWdnZXJcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJAbmVzdGpzL3Rlcm1pbnVzXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiQG5lc3Rqcy90eXBlb3JtXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiYmNyeXB0XCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwiY2xhc3MtdHJhbnNmb3JtZXJcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJjbGFzcy12YWxpZGF0b3JcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJleHByZXNzLXJhdGUtbGltaXRcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJoZWxtZXRcIiIsIndlYnBhY2s6Ly9taC1uZXN0anMvZXh0ZXJuYWwgY29tbW9uanMgXCJyZXF1ZXN0LWlwXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwicnhqc1wiIiwid2VicGFjazovL21oLW5lc3Rqcy9leHRlcm5hbCBjb21tb25qcyBcInJ4anMvb3BlcmF0b3JzXCIiLCJ3ZWJwYWNrOi8vbWgtbmVzdGpzL2V4dGVybmFsIGNvbW1vbmpzIFwidHlwZW9ybVwiIiwid2VicGFjazovL21oLW5lc3Rqcy93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9taC1uZXN0anMvLi9hcHBzL2FwaS9zcmMvbWFpbi50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBDbGFzc1NlcmlhbGl6ZXJJbnRlcmNlcHRvciwgTWlkZGxld2FyZUNvbnN1bWVyLCBNb2R1bGUsIE5lc3RNb2R1bGUsIFJlcXVlc3RNZXRob2QgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IENvbmZpZ01vZHVsZSwgQ29uZmlnVHlwZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgQVBQX0lOVEVSQ0VQVE9SIH0gZnJvbSAnQG5lc3Rqcy9jb3JlJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCB7IERhdGFTb3VyY2UgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgTWFyaWFkYkNvbmZpZyB9IGZyb20gJy4vZW52aXJvbm1lbnRzJ1xuaW1wb3J0IHsgTG9nZ2VyTWlkZGxld2FyZSB9IGZyb20gJy4vbWlkZGxld2FyZS9sb2dnZXIubWlkZGxld2FyZSdcbmltcG9ydCB7IFZhbGlkYXRlQWNjZXNzVG9rZW5NaWRkbGV3YXJlIH0gZnJvbSAnLi9taWRkbGV3YXJlL3ZhbGlkYXRlLWFjY2Vzcy10b2tlbi5taWRkbGV3YXJlJ1xuaW1wb3J0IHsgQWRtaXNzaW9uTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2FkbWlzc2lvbi9hZG1pc3Npb24ubW9kdWxlJ1xuaW1wb3J0IHsgQXV0aE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9hdXRoL2F1dGgubW9kdWxlJ1xuaW1wb3J0IHsgQ2xpbmljTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2NsaW5pYy9jbGluaWMubW9kdWxlJ1xuaW1wb3J0IHsgRW1wbG95ZWVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvZW1wbG95ZWUvZW1wbG95ZWUubW9kdWxlJ1xuaW1wb3J0IHsgSGVhbHRoTW9kdWxlIH0gZnJvbSAnLi9tb2R1bGVzL2hlYWx0aC9oZWFsdGgubW9kdWxlJ1xuaW1wb3J0IHsgTWVkaWNpbmVNb2R1bGUgfSBmcm9tICcuL21vZHVsZXMvbWVkaWNpbmUvbWVkaWNpbmUubW9kdWxlJ1xuaW1wb3J0IHsgUGF0aWVudE1vZHVsZSB9IGZyb20gJy4vbW9kdWxlcy9wYXRpZW50L3BhdGllbnQubW9kdWxlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1xuXHRcdENvbmZpZ01vZHVsZS5mb3JSb290KHtcblx0XHRcdGVudkZpbGVQYXRoOiBbYC5lbnYuJHtwcm9jZXNzLmVudi5OT0RFX0VOViB8fCAnbG9jYWwnfWAsICcuZW52J10sXG5cdFx0XHRpc0dsb2JhbDogdHJ1ZSxcblx0XHR9KSxcblx0XHRUeXBlT3JtTW9kdWxlLmZvclJvb3RBc3luYyh7XG5cdFx0XHRpbXBvcnRzOiBbQ29uZmlnTW9kdWxlLmZvckZlYXR1cmUoTWFyaWFkYkNvbmZpZyldLFxuXHRcdFx0aW5qZWN0OiBbTWFyaWFkYkNvbmZpZy5LRVldLFxuXHRcdFx0dXNlRmFjdG9yeTogKG1hcmlhZGJDb25maWc6IENvbmZpZ1R5cGU8dHlwZW9mIE1hcmlhZGJDb25maWc+KSA9PiBtYXJpYWRiQ29uZmlnLFxuXHRcdFx0Ly8gaW5qZWN0OiBbQ29uZmlnU2VydmljZV0sXG5cdFx0XHQvLyB1c2VGYWN0b3J5OiAoY29uZmlnU2VydmljZTogQ29uZmlnU2VydmljZSkgPT4gY29uZmlnU2VydmljZS5nZXQoJ215c3FsJyksXG5cdFx0fSksXG5cdFx0SGVhbHRoTW9kdWxlLFxuXHRcdEF1dGhNb2R1bGUsXG5cdFx0QWRtaXNzaW9uTW9kdWxlLFxuXHRcdEVtcGxveWVlTW9kdWxlLFxuXHRcdFBhdGllbnRNb2R1bGUsXG5cdFx0Q2xpbmljTW9kdWxlLFxuXHRcdE1lZGljaW5lTW9kdWxlLFxuXHRdLFxuXHRwcm92aWRlcnM6IFtcblx0XHR7XG5cdFx0XHRwcm92aWRlOiBBUFBfSU5URVJDRVBUT1IsXG5cdFx0XHR1c2VDbGFzczogQ2xhc3NTZXJpYWxpemVySW50ZXJjZXB0b3IsXG5cdFx0fSxcblx0XSxcbn0pXG5leHBvcnQgY2xhc3MgQXBwTW9kdWxlIGltcGxlbWVudHMgTmVzdE1vZHVsZSB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgZGF0YVNvdXJjZTogRGF0YVNvdXJjZSkgeyB9XG5cdGNvbmZpZ3VyZShjb25zdW1lcjogTWlkZGxld2FyZUNvbnN1bWVyKSB7XG5cdFx0Y29uc3VtZXIuYXBwbHkoTG9nZ2VyTWlkZGxld2FyZSkuZm9yUm91dGVzKCcqJylcblxuXHRcdGNvbnN1bWVyLmFwcGx5KFZhbGlkYXRlQWNjZXNzVG9rZW5NaWRkbGV3YXJlKVxuXHRcdFx0LmV4Y2x1ZGUoXG5cdFx0XHRcdCdhdXRoLyguKiknLFxuXHRcdFx0XHQnLycsXG5cdFx0XHRcdHsgcGF0aDogJ2hlYWx0aCcsIG1ldGhvZDogUmVxdWVzdE1ldGhvZC5HRVQgfVxuXHRcdFx0KVxuXHRcdFx0LmZvclJvdXRlcygnKicpXG5cdH1cbn1cbiIsImltcG9ydCB7IFZhbGlkYXRvckNvbnN0cmFpbnQsIFZhbGlkYXRvckNvbnN0cmFpbnRJbnRlcmZhY2UsIFZhbGlkYXRpb25Bcmd1bWVudHMgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5cbkBWYWxpZGF0b3JDb25zdHJhaW50KHsgbmFtZTogJ2lzUGhvbmUnLCBhc3luYzogZmFsc2UgfSlcbmV4cG9ydCBjbGFzcyBJc1Bob25lIGltcGxlbWVudHMgVmFsaWRhdG9yQ29uc3RyYWludEludGVyZmFjZSB7XG5cdHZhbGlkYXRlKHRleHQ6IHN0cmluZywgYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdGlmICh0eXBlb2YgdGV4dCAhPT0gJ3N0cmluZycgfHwgdGV4dC5sZW5ndGggIT09IDEwKSByZXR1cm4gZmFsc2Vcblx0XHRyZXR1cm4gLygoMDl8MDN8MDd8MDh8MDUpKyhbMC05XXs4fSlcXGIpL2cudGVzdCh0ZXh0KVxuXHR9XG5cblx0ZGVmYXVsdE1lc3NhZ2UoYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAnJHByb3BlcnR5IG11c3QgYmUgcmVhbCBwaG9uZSBudW1iZXIgISdcblx0fVxufVxuXG5AVmFsaWRhdG9yQ29uc3RyYWludCh7IG5hbWU6ICdpc0dtYWlsJywgYXN5bmM6IGZhbHNlIH0pXG5leHBvcnQgY2xhc3MgSXNHbWFpbCBpbXBsZW1lbnRzIFZhbGlkYXRvckNvbnN0cmFpbnRJbnRlcmZhY2Uge1xuXHR2YWxpZGF0ZSh0ZXh0OiBzdHJpbmcsIGFyZ3M6IFZhbGlkYXRpb25Bcmd1bWVudHMpIHtcblx0XHRpZiAodHlwZW9mIHRleHQgIT09ICdzdHJpbmcnKSByZXR1cm4gZmFsc2Vcblx0XHRyZXR1cm4gL14oW2EtekEtWjAtOV18XFwufC18XykrKEBnbWFpbC5jb20pJC8udGVzdCh0ZXh0KVxuXHR9XG5cblx0ZGVmYXVsdE1lc3NhZ2UoYXJnczogVmFsaWRhdGlvbkFyZ3VtZW50cykge1xuXHRcdHJldHVybiAnJHByb3BlcnR5IG11c3QgYmUgYSBnbWFpbCBhZGRyZXNzICEnXG5cdH1cbn1cbiIsImltcG9ydCB7IElOZXN0QXBwbGljYXRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFN3YWdnZXJNb2R1bGUsIERvY3VtZW50QnVpbGRlciB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcblxuZXhwb3J0IGNvbnN0IHNldHVwU3dhZ2dlciA9IChhcHA6IElOZXN0QXBwbGljYXRpb24pID0+IHtcblx0Y29uc3QgY29uZmlnID0gbmV3IERvY3VtZW50QnVpbGRlcigpXG5cdFx0LnNldFRpdGxlKCdTaW1wbGUgQVBJJylcblx0XHQuc2V0RGVzY3JpcHRpb24oJ01lZGlob21lIEFQSSB1c2UgU3dhZ2dlcicpXG5cdFx0LnNldFZlcnNpb24oJzEuMCcpXG5cdFx0LmFkZEJlYXJlckF1dGgoXG5cdFx0XHR7IHR5cGU6ICdodHRwJywgZGVzY3JpcHRpb246ICdBY2Nlc3MgdG9rZW4nIH0sXG5cdFx0XHQnYWNjZXNzLXRva2VuJ1xuXHRcdClcblx0XHQuYnVpbGQoKVxuXHRjb25zdCBkb2N1bWVudCA9IFN3YWdnZXJNb2R1bGUuY3JlYXRlRG9jdW1lbnQoYXBwLCBjb25maWcpXG5cdFN3YWdnZXJNb2R1bGUuc2V0dXAoJ2RvY3VtZW50JywgYXBwLCBkb2N1bWVudClcbn1cbiIsImltcG9ydCB7IGNyZWF0ZVBhcmFtRGVjb3JhdG9yLCBFeGVjdXRpb25Db250ZXh0IH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0IH0gZnJvbSAnZXhwcmVzcydcbmltcG9ydCB7IGdldENsaWVudElwIH0gZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IFJlcXVlc3RUb2tlbiB9IGZyb20gJy4uL2NvbW1vbi9jb25zdGFudHMnXG5cbmV4cG9ydCBjb25zdCBJcFJlcXVlc3QgPSBjcmVhdGVQYXJhbURlY29yYXRvcigoZGF0YTogdW5rbm93biwgY3R4OiBFeGVjdXRpb25Db250ZXh0KSA9PiB7XG5cdGNvbnN0IHJlcXVlc3Q6IFJlcXVlc3QgPSBjdHguc3dpdGNoVG9IdHRwKCkuZ2V0UmVxdWVzdCgpXG5cdHJldHVybiBnZXRDbGllbnRJcChyZXF1ZXN0KVxufSlcblxuZXhwb3J0IGNvbnN0IENpZFJlcXVlc3QgPSBjcmVhdGVQYXJhbURlY29yYXRvcigoZGF0YTogdW5rbm93biwgY3R4OiBFeGVjdXRpb25Db250ZXh0KSA9PiB7XG5cdGNvbnN0IHJlcXVlc3Q6IFJlcXVlc3RUb2tlbiA9IGN0eC5zd2l0Y2hUb0h0dHAoKS5nZXRSZXF1ZXN0KClcblx0cmV0dXJuIHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxufSlcbiIsImltcG9ydCB7IHJlZ2lzdGVyQXMgfSBmcm9tICdAbmVzdGpzL2NvbmZpZydcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGVPcHRpb25zIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuXG5leHBvcnQgY29uc3QgSnd0Q29uZmlnID0gcmVnaXN0ZXJBcygnand0JywgKCkgPT4gKHtcblx0YWNjZXNzS2V5OiBwcm9jZXNzLmVudi5KV1RfQUNDRVNTX0tFWSxcblx0cmVmcmVzaEtleTogcHJvY2Vzcy5lbnYuSldUX1JFRlJFU0hfS0VZLFxuXHRhY2Nlc3NUaW1lOiBOdW1iZXIocHJvY2Vzcy5lbnYuSldUX0FDQ0VTU19USU1FKSxcblx0cmVmcmVzaFRpbWU6IE51bWJlcihwcm9jZXNzLmVudi5KV1RfUkVGUkVTSF9USU1FKSxcbn0pKVxuXG5leHBvcnQgY29uc3QgTWFyaWFkYkNvbmZpZyA9IHJlZ2lzdGVyQXMoJ21hcmlhZGInLCAoKTogVHlwZU9ybU1vZHVsZU9wdGlvbnMgPT4gKHtcblx0dHlwZTogJ21hcmlhZGInLFxuXHRob3N0OiBwcm9jZXNzLmVudi5NQVJJQURCX0hPU1QsXG5cdHBvcnQ6IHBhcnNlSW50KHByb2Nlc3MuZW52Lk1BUklBREJfUE9SVCwgMTApLFxuXHRkYXRhYmFzZTogcHJvY2Vzcy5lbnYuTUFSSUFEQl9EQVRBQkFTRSxcblx0dXNlcm5hbWU6IHByb2Nlc3MuZW52Lk1BUklBREJfVVNFUk5BTUUsXG5cdHBhc3N3b3JkOiBwcm9jZXNzLmVudi5NQVJJQURCX1BBU1NXT1JELFxuXHRhdXRvTG9hZEVudGl0aWVzOiB0cnVlLFxuXHRsb2dnaW5nOiBwcm9jZXNzLmVudi5OT0RFX0VOViAhPT0gJ3Byb2R1Y3Rpb24nLFxuXHQvLyBzeW5jaHJvbml6ZTogcHJvY2Vzcy5lbnYuTk9ERV9FTlYgPT09ICdsb2NhbCcsXG59KSlcbiIsImV4cG9ydCBlbnVtIEVFcnJvciB7XG5cdFVua25vd24gPSAnQTAwLlVOS05PV04nXG59XG5cbmV4cG9ydCBlbnVtIEVWYWxpZGF0ZUVycm9yIHtcblx0RmFpbGVkID0gJ1YwMC5WQUxJREFURV9GQUlMRUQnXG59XG5cbmV4cG9ydCBlbnVtIEVSZWdpc3RlckVycm9yIHtcblx0RXhpc3RFbWFpbEFuZFBob25lID0gJ1IwMS5FWElTVF9FTUFJTF9BTkRfUEhPTkUnLFxuXHRFeGlzdEVtYWlsID0gJ1IwMi5FWElTVF9FTUFJTCcsXG5cdEV4aXN0UGhvbmUgPSAnUjAzLkVYSVNUX1BIT05FJyxcblx0RXhpc3RVc2VybmFtZSA9ICdSMDQuRVhJU1RfVVNFUk5BTUUnXG59XG5cbmV4cG9ydCBlbnVtIEVMb2dpbkVycm9yIHtcblx0RW1wbG95ZWVEb2VzTm90RXhpc3QgPSAnTDAxLkVNUExPWUVFX0RPRVNfTk9UX0VYSVNUJyxcblx0V3JvbmdQYXNzd29yZCA9ICdMMDIuV1JPTkdfUEFTU1dPUkQnXG59XG5cbmV4cG9ydCBlbnVtIEVUb2tlbkVycm9yIHtcblx0RXhwaXJlZCA9ICdUMDEuRVhQSVJFRCcsXG5cdEludmFsaWQgPSAnVDAyLklOVkFMSUQnXG59XG5cbmV4cG9ydCBlbnVtIEVFbXBsb3llZUVycm9yIHtcblx0VXNlcm5hbWVFeGlzdHMgPSAnVTAxLlVTRVJOQU1FX0VYSVNUUycsXG5cdE5vdEV4aXN0cyA9ICdVMDIuRU1QTE9ZRUVfRE9FU19OT1RfRVhJU1QnXG59XG5cbmV4cG9ydCBlbnVtIEVQYXRpZW50RXJyb3Ige1xuXHROb3RFeGlzdHMgPSAnUDAxLlBBVElFTlRfRE9FU19OT1RfRVhJU1QnXG59XG4iLCJpbXBvcnQgeyBFeGNlcHRpb25GaWx0ZXIsIENhdGNoLCBBcmd1bWVudHNIb3N0LCBIdHRwRXhjZXB0aW9uIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5cbkBDYXRjaChIdHRwRXhjZXB0aW9uKVxuZXhwb3J0IGNsYXNzIEh0dHBFeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjYXRjaChleGNlcHRpb246IEh0dHBFeGNlcHRpb24sIGhvc3Q6IEFyZ3VtZW50c0hvc3QpIHtcblx0XHRjb25zdCBjdHggPSBob3N0LnN3aXRjaFRvSHR0cCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVzcG9uc2U8UmVzcG9uc2U+KClcblx0XHRjb25zdCByZXF1ZXN0ID0gY3R4LmdldFJlcXVlc3Q8UmVxdWVzdD4oKVxuXHRcdGNvbnN0IGh0dHBTdGF0dXMgPSBleGNlcHRpb24uZ2V0U3RhdHVzKClcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlOiBleGNlcHRpb24uZ2V0UmVzcG9uc2UoKSxcblx0XHRcdHBhdGg6IHJlcXVlc3QudXJsLFxuXHRcdFx0dGltZXN0YW1wOiBuZXcgRGF0ZSgpLnRvSVNPU3RyaW5nKCksXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXJndW1lbnRzSG9zdCwgQ2F0Y2gsIEV4Y2VwdGlvbkZpbHRlciwgSHR0cFN0YXR1cywgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBSZXF1ZXN0LCBSZXNwb25zZSB9IGZyb20gJ2V4cHJlc3MnXG5cbkBDYXRjaChFcnJvcilcbmV4cG9ydCBjbGFzcyBVbmtub3duRXhjZXB0aW9uRmlsdGVyIGltcGxlbWVudHMgRXhjZXB0aW9uRmlsdGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBsb2dnZXIgPSBuZXcgTG9nZ2VyKCdTRVJWRVJfRVJST1InKSkgeyB9XG5cblx0Y2F0Y2goZXhjZXB0aW9uOiBFcnJvciwgaG9zdDogQXJndW1lbnRzSG9zdCkge1xuXHRcdGNvbnN0IGN0eCA9IGhvc3Quc3dpdGNoVG9IdHRwKClcblx0XHRjb25zdCByZXNwb25zZSA9IGN0eC5nZXRSZXNwb25zZTxSZXNwb25zZT4oKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdDxSZXF1ZXN0PigpXG5cdFx0Y29uc3QgaHR0cFN0YXR1cyA9IEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SXG5cblx0XHR0aGlzLmxvZ2dlci5lcnJvcihleGNlcHRpb24uc3RhY2spXG5cblx0XHRyZXNwb25zZS5zdGF0dXMoaHR0cFN0YXR1cykuanNvbih7XG5cdFx0XHRodHRwU3RhdHVzLFxuXHRcdFx0bWVzc2FnZTogZXhjZXB0aW9uLm1lc3NhZ2UsXG5cdFx0XHRwYXRoOiByZXF1ZXN0LnVybCxcblx0XHRcdHRpbWVzdGFtcDogbmV3IERhdGUoKS50b0lTT1N0cmluZygpLFxuXHRcdH0pXG5cdH1cbn1cbiIsImltcG9ydCB7IEFyZ3VtZW50c0hvc3QsIENhdGNoLCBFeGNlcHRpb25GaWx0ZXIsIEh0dHBTdGF0dXMsIFZhbGlkYXRpb25FcnJvciB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UgfSBmcm9tICdleHByZXNzJ1xuaW1wb3J0IHsgRVZhbGlkYXRlRXJyb3IgfSBmcm9tICcuL2V4Y2VwdGlvbi5lbnVtJ1xuXG5leHBvcnQgY2xhc3MgVmFsaWRhdGlvbkV4Y2VwdGlvbiBleHRlbmRzIEVycm9yIHtcblx0cHJpdmF0ZSByZWFkb25seSBlcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdXG5cdGNvbnN0cnVjdG9yKHZhbGlkYXRpb25FcnJvcnM6IFZhbGlkYXRpb25FcnJvcltdID0gW10pIHtcblx0XHRzdXBlcihFVmFsaWRhdGVFcnJvci5GYWlsZWQpXG5cdFx0dGhpcy5lcnJvcnMgPSB2YWxpZGF0aW9uRXJyb3JzXG5cdH1cblx0Z2V0TWVzc2FnZSgpIHtcblx0XHRyZXR1cm4gdGhpcy5tZXNzYWdlXG5cdH1cblx0Z2V0RXJyb3JzKCkge1xuXHRcdHJldHVybiB0aGlzLmVycm9yc1xuXHR9XG59XG5cbkBDYXRjaChWYWxpZGF0aW9uRXhjZXB0aW9uKVxuZXhwb3J0IGNsYXNzIFZhbGlkYXRpb25FeGNlcHRpb25GaWx0ZXIgaW1wbGVtZW50cyBFeGNlcHRpb25GaWx0ZXIge1xuXHRjYXRjaChleGNlcHRpb246IFZhbGlkYXRpb25FeGNlcHRpb24sIGhvc3Q6IEFyZ3VtZW50c0hvc3QpIHtcblx0XHRjb25zdCBjdHggPSBob3N0LnN3aXRjaFRvSHR0cCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVzcG9uc2U8UmVzcG9uc2U+KClcblx0XHRjb25zdCByZXF1ZXN0ID0gY3R4LmdldFJlcXVlc3Q8UmVxdWVzdD4oKVxuXHRcdGNvbnN0IGh0dHBTdGF0dXMgPSBIdHRwU3RhdHVzLlVOUFJPQ0VTU0FCTEVfRU5USVRZXG5cdFx0Y29uc3QgbWVzc2FnZSA9IGV4Y2VwdGlvbi5nZXRNZXNzYWdlKClcblx0XHRjb25zdCBlcnJvcnMgPSBleGNlcHRpb24uZ2V0RXJyb3JzKClcblxuXHRcdHJlc3BvbnNlLnN0YXR1cyhodHRwU3RhdHVzKS5qc29uKHtcblx0XHRcdGh0dHBTdGF0dXMsXG5cdFx0XHRtZXNzYWdlLFxuXHRcdFx0ZXJyb3JzLFxuXHRcdFx0cGF0aDogcmVxdWVzdC51cmwsXG5cdFx0XHR0aW1lc3RhbXA6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDYW5BY3RpdmF0ZSwgRXhlY3V0aW9uQ29udGV4dCwgSW5qZWN0YWJsZSwgU2V0TWV0YWRhdGEgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFJlZmxlY3RvciB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCB7IEVSb2xlIH0gZnJvbSAnLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuXG5leHBvcnQgY29uc3QgUm9sZXMgPSAoLi4ucm9sZXM6IEVSb2xlW10pID0+IFNldE1ldGFkYXRhKCdyb2xlc19ndWFyZCcsIHJvbGVzKVxuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgUm9sZXNHdWFyZCBpbXBsZW1lbnRzIENhbkFjdGl2YXRlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWZsZWN0b3I6IFJlZmxlY3RvcikgeyB9XG5cblx0Y2FuQWN0aXZhdGUoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCk6IGJvb2xlYW4ge1xuXHRcdGNvbnN0IHJlcXVpcmVkUm9sZXMgPSB0aGlzLnJlZmxlY3Rvci5nZXRBbGxBbmRPdmVycmlkZTxFUm9sZVtdPigncm9sZXNfZ3VhcmQnLCBbXG5cdFx0XHRjb250ZXh0LmdldEhhbmRsZXIoKSxcblx0XHRcdGNvbnRleHQuZ2V0Q2xhc3MoKSxcblx0XHRdKVxuXHRcdGlmICghcmVxdWlyZWRSb2xlcykgcmV0dXJuIHRydWVcblxuXHRcdGNvbnN0IHJlcXVlc3Q6IFJlcXVlc3RUb2tlbiA9IGNvbnRleHQuc3dpdGNoVG9IdHRwKCkuZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgeyByb2xlIH0gPSByZXF1ZXN0LnRva2VuUGF5bG9hZFxuXG5cdFx0cmV0dXJuIHJlcXVpcmVkUm9sZXMuaW5jbHVkZXMocm9sZSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQ2FsbEhhbmRsZXIsIEV4ZWN1dGlvbkNvbnRleHQsIEluamVjdGFibGUsIE5lc3RJbnRlcmNlcHRvciwgTG9nZ2VyIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBnZXRDbGllbnRJcCB9IGZyb20gJ3JlcXVlc3QtaXAnXG5pbXBvcnQgeyBPYnNlcnZhYmxlIH0gZnJvbSAncnhqcydcbmltcG9ydCB7IHRhcCB9IGZyb20gJ3J4anMvb3BlcmF0b3JzJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQWNjZXNzTG9nSW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGxvZ2dlciA9IG5ldyBMb2dnZXIoJ0FDQ0VTU19MT0cnKSkgeyB9XG5cblx0aW50ZXJjZXB0KGNvbnRleHQ6IEV4ZWN1dGlvbkNvbnRleHQsIG5leHQ6IENhbGxIYW5kbGVyKTogT2JzZXJ2YWJsZTxhbnk+IHtcblx0XHRjb25zdCBzdGFydFRpbWUgPSBuZXcgRGF0ZSgpXG5cdFx0Y29uc3QgY3R4ID0gY29udGV4dC5zd2l0Y2hUb0h0dHAoKVxuXHRcdGNvbnN0IHJlcXVlc3QgPSBjdHguZ2V0UmVxdWVzdCgpXG5cdFx0Y29uc3QgcmVzcG9uc2UgPSBjdHguZ2V0UmVxdWVzdCgpXG5cblx0XHRjb25zdCB7IHVybCwgbWV0aG9kIH0gPSByZXF1ZXN0XG5cdFx0Y29uc3QgeyBzdGF0dXNDb2RlIH0gPSByZXNwb25zZVxuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxdWVzdClcblxuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUodGFwKCgpID0+IHtcblx0XHRcdGNvbnN0IG1zZyA9IGAke3N0YXJ0VGltZS50b0lTT1N0cmluZygpfSB8ICR7aXB9IHwgJHttZXRob2R9IHwgJHtzdGF0dXNDb2RlfSB8ICR7dXJsfSB8ICR7RGF0ZS5ub3coKSAtIHN0YXJ0VGltZS5nZXRUaW1lKCl9bXNgXG5cdFx0XHRyZXR1cm4gdGhpcy5sb2dnZXIubG9nKG1zZylcblx0XHR9KSlcblx0fVxufVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmVzdEludGVyY2VwdG9yLCBFeGVjdXRpb25Db250ZXh0LCBDYWxsSGFuZGxlciwgUmVxdWVzdFRpbWVvdXRFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IE9ic2VydmFibGUsIHRocm93RXJyb3IsIFRpbWVvdXRFcnJvciB9IGZyb20gJ3J4anMnXG5pbXBvcnQgeyBjYXRjaEVycm9yLCB0aW1lb3V0IH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBUaW1lb3V0SW50ZXJjZXB0b3IgaW1wbGVtZW50cyBOZXN0SW50ZXJjZXB0b3Ige1xuXHRpbnRlcmNlcHQoY29udGV4dDogRXhlY3V0aW9uQ29udGV4dCwgbmV4dDogQ2FsbEhhbmRsZXIpOiBPYnNlcnZhYmxlPGFueT4ge1xuXHRcdHJldHVybiBuZXh0LmhhbmRsZSgpLnBpcGUoXG5cdFx0XHR0aW1lb3V0KDEwMDAwKSxcblx0XHRcdGNhdGNoRXJyb3IoZXJyID0+IHtcblx0XHRcdFx0aWYgKGVyciBpbnN0YW5jZW9mIFRpbWVvdXRFcnJvcikge1xuXHRcdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IG5ldyBSZXF1ZXN0VGltZW91dEV4Y2VwdGlvbigpKVxuXHRcdFx0XHR9XG5cdFx0XHRcdHJldHVybiB0aHJvd0Vycm9yKCgpID0+IGVycilcblx0XHRcdH0pXG5cdFx0KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlLCBOZXN0TWlkZGxld2FyZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgUmVxdWVzdCwgUmVzcG9uc2UsIE5leHRGdW5jdGlvbiB9IGZyb20gJ2V4cHJlc3MnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBMb2dnZXJNaWRkbGV3YXJlIGltcGxlbWVudHMgTmVzdE1pZGRsZXdhcmUge1xuXHR1c2UocmVxOiBSZXF1ZXN0LCByZXM6IFJlc3BvbnNlLCBuZXh0OiBOZXh0RnVuY3Rpb24pIHtcblx0XHRjb25zb2xlLmxvZygnUmVxdWVzdC4uLicpXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEluamVjdGFibGUsIE5lc3RNaWRkbGV3YXJlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBOZXh0RnVuY3Rpb24sIFJlc3BvbnNlIH0gZnJvbSAnZXhwcmVzcydcbmltcG9ydCB7IGdldENsaWVudElwIH0gZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IElKd3RQYXlsb2FkLCBSZXF1ZXN0VG9rZW4gfSBmcm9tICcuLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4uL21vZHVsZXMvYXV0aC9qd3QtZXh0ZW5kLnNlcnZpY2UnXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBWYWxpZGF0ZUFjY2Vzc1Rva2VuTWlkZGxld2FyZSBpbXBsZW1lbnRzIE5lc3RNaWRkbGV3YXJlIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlKSB7IH1cblxuXHRhc3luYyB1c2UocmVxOiBSZXF1ZXN0VG9rZW4sIHJlczogUmVzcG9uc2UsIG5leHQ6IE5leHRGdW5jdGlvbikge1xuXHRcdGNvbnN0IGlwID0gZ2V0Q2xpZW50SXAocmVxKVxuXHRcdGNvbnN0IGF1dGhvcml6YXRpb24gPSByZXEuaGVhZGVyKCdBdXRob3JpemF0aW9uJykgfHwgJydcblx0XHRjb25zdCBbLCBhY2Nlc3NUb2tlbl0gPSBhdXRob3JpemF0aW9uLnNwbGl0KCcgJylcblx0XHRjb25zdCBkZWNvZGU6IElKd3RQYXlsb2FkID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLnZlcmlmeUFjY2Vzc1Rva2VuKGFjY2Vzc1Rva2VuLCBpcClcblx0XHRyZXEudG9rZW5QYXlsb2FkID0gZGVjb2RlXG5cdFx0bmV4dCgpXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFNlcmlhbGl6ZU9wdGlvbnMgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBDaWRSZXF1ZXN0IH0gZnJvbSAnLi4vLi4vZGVjb3JhdG9ycy9yZXF1ZXN0LmRlY29yYXRvcidcbmltcG9ydCB7IENyZWF0ZUFkbWlzc2lvbkR0bywgVXBkYXRlQWRtaXNzaW9uRHRvIH0gZnJvbSAnLi9hZG1pc3Npb24uZHRvJ1xuaW1wb3J0IHsgQWRtaXNzaW9uU2VydmljZSB9IGZyb20gJy4vYWRtaXNzaW9uLnNlcnZpY2UnXG5cbkBBcGlUYWdzKCdBZG1pc3Npb24nKVxuQFNlcmlhbGl6ZU9wdGlvbnMoeyBleGNsdWRlRXh0cmFuZW91c1ZhbHVlczogdHJ1ZSwgZXhwb3NlVW5zZXRGaWVsZHM6IGZhbHNlIH0pXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBDb250cm9sbGVyKCdhZG1pc3Npb24nKVxuZXhwb3J0IGNsYXNzIEFkbWlzc2lvbkNvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihwcml2YXRlIHJlYWRvbmx5IGFkbWlzc2lvblNlcnZpY2U6IEFkbWlzc2lvblNlcnZpY2UpIHsgfVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiB0aGlzLmFkbWlzc2lvblNlcnZpY2UuZmluZEFsbCgpXG5cdH1cblxuXHRAR2V0KCc6aWQnKVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0cmV0dXJuIHRoaXMuYWRtaXNzaW9uU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBQb3N0KClcblx0YXN5bmMgY3JlYXRlKEBCb2R5KCkgY3JlYXRlQWRtaXNzaW9uRHRvOiBDcmVhdGVBZG1pc3Npb25EdG8sIEBDaWRSZXF1ZXN0KCkgY2lkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5hZG1pc3Npb25TZXJ2aWNlLmNyZWF0ZShjaWQsIGNyZWF0ZUFkbWlzc2lvbkR0bylcblx0fVxuXG5cdEBQYXRjaCgnOmlkJylcblx0dXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAQm9keSgpIHVwZGF0ZUFkbWlzc2lvbkR0bzogVXBkYXRlQWRtaXNzaW9uRHRvKSB7XG5cdFx0cmV0dXJuIHRoaXMuYWRtaXNzaW9uU2VydmljZS51cGRhdGUoK2lkLCB1cGRhdGVBZG1pc3Npb25EdG8pXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5hZG1pc3Npb25TZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IEFwaVByb3BlcnR5LCBBcGlQcm9wZXJ0eU9wdGlvbmFsLCBQYXJ0aWFsVHlwZSB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IEV4cG9zZSwgVHlwZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgSXNEYXRlLCBJc0VudW0sIElzTnVtYmVyLCBJc1N0cmluZywgVmFsaWRhdGVOZXN0ZWQgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5pbXBvcnQgeyBFR2VuZGVyIH0gZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9iYXNlLmVudGl0eSdcbmltcG9ydCBQYXRpZW50RW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvcGF0aWVudC5lbnRpdHknXG5cbmV4cG9ydCBjbGFzcyBQYXRpZW50RHRvIHtcblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnJyB9KVxuXHRARXhwb3NlKClcblx0QFR5cGUoKCkgPT4gTnVtYmVyKVxuXHRASXNOdW1iZXIoKVxuXHRpZDogbnVtYmVyXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBuYW1lOiAnZnVsbF9uYW1lJywgZXhhbXBsZTogJ05ndXnhu4VuIFRo4buLIMOBbmgnIH0pXG5cdEBFeHBvc2UoeyBuYW1lOiAnZnVsbF9uYW1lJyB9KVxuXHRASXNTdHJpbmcoKVxuXHRmdWxsTmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnMDk4NzQ0NTIyMycgfSlcblx0QEV4cG9zZSgpXG5cdEBJc1N0cmluZygpXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICcxOTI3LTA0LTI4VDAwOjAwOjAwLjAwMFonIH0pXG5cdEBFeHBvc2UoKVxuXHRAVHlwZSgoKSA9PiBEYXRlKVxuXHRASXNEYXRlKClcblx0YmlydGhkYXk6IERhdGVcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGVudW06IEVHZW5kZXIsIGV4YW1wbGU6IEVHZW5kZXIuRmVtYWxlIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNFbnVtKEVHZW5kZXIpXG5cdGdlbmRlcjogRUdlbmRlclxuXG5cdEBBcGlQcm9wZXJ0eU9wdGlvbmFsKHsgZXhhbXBsZTogJ1Thu4luaCBIw6AgVMSpbmggLS0gSHV54buHbiDEkOG7qWMgVGjhu40gLS0gWMOjIEzDom0gVHJ1bmcgVGjhu6d5IC0tIFRow7RuIFBoYW4gVGjhuq9uZycgfSlcblx0QEV4cG9zZSgpXG5cdEBJc1N0cmluZygpXG5cdGFkZHJlc3M6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgQ3JlYXRlQWRtaXNzaW9uRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgdHlwZTogUGF0aWVudER0byB9KVxuXHRARXhwb3NlKClcblx0QFZhbGlkYXRlTmVzdGVkKHsgZWFjaDogdHJ1ZSB9KVxuXHRAVHlwZSgoKSA9PiBQYXRpZW50RHRvKVxuXHRwYXRpZW50OiBQYXRpZW50RHRvXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnU+G7kXQgY2FvIG5nw6B5IHRo4bupIDMnIH0pXG5cdEBFeHBvc2UoKVxuXHRASXNTdHJpbmcoKVxuXHRyZWFzb246IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlQWRtaXNzaW9uRHRvIGV4dGVuZHMgUGFydGlhbFR5cGUoQ3JlYXRlQWRtaXNzaW9uRHRvKSB7IH1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgVHlwZU9ybU1vZHVsZSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCBBZG1pc3Npb25FbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9hZG1pc3Npb24uZW50aXR5J1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eSdcbmltcG9ydCB7IEFkbWlzc2lvbkNvbnRyb2xsZXIgfSBmcm9tICcuL2FkbWlzc2lvbi5jb250cm9sbGVyJ1xuaW1wb3J0IHsgQWRtaXNzaW9uU2VydmljZSB9IGZyb20gJy4vYWRtaXNzaW9uLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtBZG1pc3Npb25FbnRpdHksIFBhdGllbnRFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbQWRtaXNzaW9uQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0FkbWlzc2lvblNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBBZG1pc3Npb25Nb2R1bGUgeyB9XG4iLCJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBJbmplY3RSZXBvc2l0b3J5IH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IHsgaW5zdGFuY2VUb1BsYWluLCBwbGFpblRvSW5zdGFuY2UgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IFJlcG9zaXRvcnkgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IEFkbWlzc2lvbkVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2FkbWlzc2lvbi5lbnRpdHknXG5pbXBvcnQgUGF0aWVudEVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL3BhdGllbnQuZW50aXR5J1xuaW1wb3J0IHsgQ3JlYXRlQWRtaXNzaW9uRHRvLCBQYXRpZW50RHRvLCBVcGRhdGVBZG1pc3Npb25EdG8gfSBmcm9tICcuL2FkbWlzc2lvbi5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBBZG1pc3Npb25TZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0QEluamVjdFJlcG9zaXRvcnkoQWRtaXNzaW9uRW50aXR5KSBwcml2YXRlIGFkbWlzc2lvblJlcG9zaXRvcnk6IFJlcG9zaXRvcnk8QWRtaXNzaW9uRW50aXR5Pixcblx0XHRASW5qZWN0UmVwb3NpdG9yeShQYXRpZW50RW50aXR5KSBwcml2YXRlIHBhdGllbnRSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PFBhdGllbnRFbnRpdHk+XG5cdCkgeyB9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIGFkbWlzc2lvbmBcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBhZG1pc3Npb25gXG5cdH1cblxuXHRhc3luYyBjcmVhdGUoY2xpbmljSWQ6IG51bWJlciwgY3JlYXRlQWRtaXNzaW9uRHRvOiBDcmVhdGVBZG1pc3Npb25EdG8pIHtcblx0XHRjb25zdCBhZG1pc3Npb24gPSBwbGFpblRvSW5zdGFuY2UoQWRtaXNzaW9uRW50aXR5LCBjcmVhdGVBZG1pc3Npb25EdG8sIHsgZXhwb3NlVW5zZXRGaWVsZHM6IGZhbHNlIH0pXG5cdFx0YWRtaXNzaW9uLmNsaW5pY0lkID0gY2xpbmljSWRcblx0XHRhZG1pc3Npb24ucGF0aWVudC5jbGluaWNJZCA9IGNsaW5pY0lkXG5cblx0XHRpZiAoIWFkbWlzc2lvbi5wYXRpZW50LmlkKSB7XG5cdFx0XHRhZG1pc3Npb24ucGF0aWVudCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuc2F2ZShhZG1pc3Npb24ucGF0aWVudClcblx0XHR9IGVsc2Uge1xuXHRcdFx0YWRtaXNzaW9uLnBhdGllbnQgPSBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LmZpbmRPbmVCeSh7IGlkOiBhZG1pc3Npb24ucGF0aWVudC5pZCB9KVxuXHRcdH1cblxuXHRcdGFkbWlzc2lvbi5wYXRpZW50SWQgPSBhZG1pc3Npb24ucGF0aWVudC5pZFxuXHRcdHJldHVybiBhd2FpdCB0aGlzLmFkbWlzc2lvblJlcG9zaXRvcnkuc2F2ZShhZG1pc3Npb24pXG5cdH1cblxuXHR1cGRhdGUoaWQ6IG51bWJlciwgdXBkYXRlQWRtaXNzaW9uRHRvOiBVcGRhdGVBZG1pc3Npb25EdG8pIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHVwZGF0ZXMgYSAjJHtpZH0gYWRtaXNzaW9uYFxuXHR9XG5cblx0cmVtb3ZlKGlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJlbW92ZXMgYSAjJHtpZH0gYWRtaXNzaW9uYFxuXHR9XG59XG4iLCJpbXBvcnQgeyBCb2R5LCBDb250cm9sbGVyLCBQYXJhbSwgUG9zdCwgU2VyaWFsaXplT3B0aW9ucyB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IElwUmVxdWVzdCB9IGZyb20gJy4uLy4uL2RlY29yYXRvcnMvcmVxdWVzdC5kZWNvcmF0b3InXG5pbXBvcnQgeyBMb2dpbkR0bywgUmVmcmVzaFRva2VuRHRvLCBSZWdpc3RlckR0bywgVG9rZW5zUmVzcG9uc2UgfSBmcm9tICcuL2F1dGguZHRvJ1xuaW1wb3J0IHsgQXV0aFNlcnZpY2UgfSBmcm9tICcuL2F1dGguc2VydmljZSdcbmltcG9ydCB7IEp3dEV4dGVuZFNlcnZpY2UgfSBmcm9tICcuL2p3dC1leHRlbmQuc2VydmljZSdcblxuQEFwaVRhZ3MoJ0F1dGgnKVxuQFNlcmlhbGl6ZU9wdGlvbnMoeyBleGNsdWRlRXh0cmFuZW91c1ZhbHVlczogdHJ1ZSwgZXhwb3NlVW5zZXRGaWVsZHM6IGZhbHNlIH0pXG5AQ29udHJvbGxlcignYXV0aCcpXG5leHBvcnQgY2xhc3MgQXV0aENvbnRyb2xsZXIge1xuXHRjb25zdHJ1Y3Rvcihcblx0XHRwcml2YXRlIHJlYWRvbmx5IGF1dGhTZXJ2aWNlOiBBdXRoU2VydmljZSxcblx0XHRwcml2YXRlIHJlYWRvbmx5IGp3dEV4dGVuZFNlcnZpY2U6IEp3dEV4dGVuZFNlcnZpY2Vcblx0KSB7IH1cblxuXHRAUG9zdCgncmVnaXN0ZXInKVxuXHRhc3luYyByZWdpc3RlcihAQm9keSgpIHJlZ2lzdGVyRHRvOiBSZWdpc3RlckR0bywgQElwUmVxdWVzdCgpIGlwOiBzdHJpbmcpOiBQcm9taXNlPFRva2Vuc1Jlc3BvbnNlPiB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmF1dGhTZXJ2aWNlLnJlZ2lzdGVyKHJlZ2lzdGVyRHRvKVxuXHRcdGNvbnN0IHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9ID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLmNyZWF0ZVRva2VuRnJvbVVzZXIoZW1wbG95ZWUsIGlwKVxuXHRcdHJldHVybiBuZXcgVG9rZW5zUmVzcG9uc2UoeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0pXG5cdH1cblxuXHRAUG9zdCgnbG9naW4nKVxuXHRhc3luYyBsb2dpbihAQm9keSgpIGxvZ2luRHRvOiBMb2dpbkR0bywgQElwUmVxdWVzdCgpIGlwOiBzdHJpbmcpOiBQcm9taXNlPFRva2Vuc1Jlc3BvbnNlPiB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmF1dGhTZXJ2aWNlLmxvZ2luKGxvZ2luRHRvKVxuXHRcdGNvbnN0IHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9ID0gdGhpcy5qd3RFeHRlbmRTZXJ2aWNlLmNyZWF0ZVRva2VuRnJvbVVzZXIoZW1wbG95ZWUsIGlwKVxuXHRcdHJldHVybiBuZXcgVG9rZW5zUmVzcG9uc2UoeyBhY2Nlc3NUb2tlbiwgcmVmcmVzaFRva2VuIH0pXG5cdH1cblxuXHRAUG9zdCgnbG9nb3V0Jylcblx0bG9nb3V0KEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0Ly8gcmV0dXJuIHRoaXMuYXV0aFNlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRAUG9zdCgnY2hhbmdlLXBhc3N3b3JkJylcblx0Y2hhbmdlUGFzc3dvcmQoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBCb2R5KCkgdXBkYXRlQXV0aER0bzogTG9naW5EdG8pIHtcblx0XHQvLyByZXR1cm4gdGhpcy5hdXRoU2VydmljZS51cGRhdGUoK2lkLCB1cGRhdGVBdXRoRHRvKVxuXHR9XG5cblx0QFBvc3QoJ2ZvcmdvdC1wYXNzd29yZCcpXG5cdGZvcmdvdFBhc3N3b3JkKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nKSB7XG5cdFx0Ly8gcmV0dXJuIHRoaXMuYXV0aFNlcnZpY2UucmVtb3ZlKCtpZClcblx0fVxuXG5cdEBQb3N0KCdyZWZyZXNoLXRva2VuJylcblx0YXN5bmMgZ3JhbnRBY2Nlc3NUb2tlbihAQm9keSgpIHJlZnJlc2hUb2tlbkR0bzogUmVmcmVzaFRva2VuRHRvLCBASXBSZXF1ZXN0KCkgaXA6IHN0cmluZyk6IFByb21pc2U8VG9rZW5zUmVzcG9uc2U+IHtcblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IGF3YWl0IHRoaXMuYXV0aFNlcnZpY2UuZ3JhbnRBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW5EdG8ucmVmcmVzaFRva2VuLCBpcClcblx0XHRyZXR1cm4gbmV3IFRva2Vuc1Jlc3BvbnNlKHsgYWNjZXNzVG9rZW4gfSlcblx0fVxufVxuIiwiaW1wb3J0IHsgQXBpUHJvcGVydHkgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBFeHBvc2UgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IElzTm90RW1wdHksIE1pbkxlbmd0aCwgVmFsaWRhdGUgfSBmcm9tICdjbGFzcy12YWxpZGF0b3InXG5pbXBvcnQgeyBJc0dtYWlsLCBJc1Bob25lIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NsYXNzLXZhbGlkYXRvci5jdXN0b20nXG5cbmV4cG9ydCBjbGFzcyBSZWdpc3RlckR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdleGFtcGxlLTJAZ21haWwuY29tJyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHRAVmFsaWRhdGUoSXNHbWFpbClcblx0ZW1haWw6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICcwMzc2ODk5ODY2JyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHRAVmFsaWRhdGUoSXNQaG9uZSlcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdhZG1pbicgfSlcblx0QEV4cG9zZSgpXG5cdEBJc05vdEVtcHR5KClcblx0dXNlcm5hbWU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdBYmNAMTIzNDU2JyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIExvZ2luRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgbmFtZTogJ2NfcGhvbmUnLCBleGFtcGxlOiAnMDk4NjAyMTE5MCcgfSlcblx0QEV4cG9zZSh7IG5hbWU6ICdjX3Bob25lJyB9KVxuXHRASXNOb3RFbXB0eSgpXG5cdEBWYWxpZGF0ZShJc1Bob25lKVxuXHRjUGhvbmU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdhZG1pbicgfSlcblx0QEV4cG9zZSgpXG5cdEBJc05vdEVtcHR5KClcblx0dXNlcm5hbWU6IHN0cmluZ1xuXG5cdEBBcGlQcm9wZXJ0eSh7IGV4YW1wbGU6ICdBYmNAMTIzNDU2JyB9KVxuXHRARXhwb3NlKClcblx0QElzTm90RW1wdHkoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFJlZnJlc2hUb2tlbkR0byB7XG5cdEBBcGlQcm9wZXJ0eSh7IG5hbWU6ICdyZWZyZXNoX3Rva2VuJyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ3JlZnJlc2hfdG9rZW4nIH0pXG5cdEBJc05vdEVtcHR5KClcblx0cmVmcmVzaFRva2VuOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFRva2Vuc1Jlc3BvbnNlIHtcblx0QEV4cG9zZSh7IG5hbWU6ICdhY2Nlc3NfdG9rZW4nIH0pXG5cdGFjY2Vzc1Rva2VuOiBzdHJpbmdcblxuXHRARXhwb3NlKHsgbmFtZTogJ3JlZnJlc2hfdG9rZW4nIH0pXG5cdHJlZnJlc2hUb2tlbjogc3RyaW5nXG5cblx0Y29uc3RydWN0b3IocGFydGlhbDogUGFydGlhbDxUb2tlbnNSZXNwb25zZT4pIHtcblx0XHRPYmplY3QuYXNzaWduKHRoaXMsIHBhcnRpYWwpXG5cdH1cbn1cbiIsImltcG9ydCB7IE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb25maWcnXG5pbXBvcnQgeyBKd3RNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2p3dCdcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCBFbXBsb3llZUVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEp3dENvbmZpZyB9IGZyb20gJy4uLy4uL2Vudmlyb25tZW50cydcbmltcG9ydCB7IEF1dGhDb250cm9sbGVyIH0gZnJvbSAnLi9hdXRoLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBBdXRoU2VydmljZSB9IGZyb20gJy4vYXV0aC5zZXJ2aWNlJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4vand0LWV4dGVuZC5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1xuXHRcdFR5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbQ2xpbmljRW50aXR5LCBFbXBsb3llZUVudGl0eV0pLFxuXHRcdENvbmZpZ01vZHVsZS5mb3JGZWF0dXJlKEp3dENvbmZpZyksXG5cdFx0Snd0TW9kdWxlLFxuXHRdLFxuXHRjb250cm9sbGVyczogW0F1dGhDb250cm9sbGVyXSxcblx0cHJvdmlkZXJzOiBbQXV0aFNlcnZpY2UsIEp3dEV4dGVuZFNlcnZpY2VdLFxuXHRleHBvcnRzOiBbSnd0RXh0ZW5kU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIEF1dGhNb2R1bGUgeyB9XG4iLCJpbXBvcnQgeyBIdHRwRXhjZXB0aW9uLCBIdHRwU3RhdHVzLCBJbmplY3RhYmxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgKiBhcyBiY3J5cHQgZnJvbSAnYmNyeXB0J1xuaW1wb3J0IHsgRGF0YVNvdXJjZSB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCBFbXBsb3llZUVudGl0eSwgeyBFUm9sZSB9IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgRUxvZ2luRXJyb3IsIEVSZWdpc3RlckVycm9yIH0gZnJvbSAnLi4vLi4vZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0nXG5pbXBvcnQgeyBMb2dpbkR0bywgUmVnaXN0ZXJEdG8gfSBmcm9tICcuL2F1dGguZHRvJ1xuaW1wb3J0IHsgSnd0RXh0ZW5kU2VydmljZSB9IGZyb20gJy4vand0LWV4dGVuZC5zZXJ2aWNlJ1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQXV0aFNlcnZpY2Uge1xuXHRjb25zdHJ1Y3Rvcihcblx0XHRwcml2YXRlIGRhdGFTb3VyY2U6IERhdGFTb3VyY2UsXG5cdFx0cHJpdmF0ZSBqd3RFeHRlbmRTZXJ2aWNlOiBKd3RFeHRlbmRTZXJ2aWNlXG5cdCkgeyB9XG5cblx0YXN5bmMgcmVnaXN0ZXIocmVnaXN0ZXJEdG86IFJlZ2lzdGVyRHRvKTogUHJvbWlzZTxFbXBsb3llZUVudGl0eT4ge1xuXHRcdGNvbnN0IHsgZW1haWwsIHBob25lLCB1c2VybmFtZSwgcGFzc3dvcmQgfSA9IHJlZ2lzdGVyRHRvXG5cdFx0Y29uc3QgaGFzaFBhc3N3b3JkID0gYXdhaXQgYmNyeXB0Lmhhc2gocGFzc3dvcmQsIDUpXG5cblx0XHRjb25zdCBlbXBsb3llZSA9IGF3YWl0IHRoaXMuZGF0YVNvdXJjZS50cmFuc2FjdGlvbihhc3luYyAobWFuYWdlcikgPT4ge1xuXHRcdFx0Y29uc3QgZmluZENsaW5pYyA9IGF3YWl0IG1hbmFnZXIuZmluZE9uZShDbGluaWNFbnRpdHksIHsgd2hlcmU6IFt7IGVtYWlsIH0sIHsgcGhvbmUgfV0gfSlcblx0XHRcdGlmIChmaW5kQ2xpbmljKSB7XG5cdFx0XHRcdGlmIChmaW5kQ2xpbmljLmVtYWlsID09PSBlbWFpbCAmJiBmaW5kQ2xpbmljLnBob25lID09PSBwaG9uZSkge1xuXHRcdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVSZWdpc3RlckVycm9yLkV4aXN0RW1haWxBbmRQaG9uZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHRcdFx0fVxuXHRcdFx0XHRlbHNlIGlmIChmaW5kQ2xpbmljLmVtYWlsID09PSBlbWFpbCkge1xuXHRcdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVSZWdpc3RlckVycm9yLkV4aXN0RW1haWwsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZSBpZiAoZmluZENsaW5pYy5waG9uZSA9PT0gcGhvbmUpIHtcblx0XHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUmVnaXN0ZXJFcnJvci5FeGlzdFBob25lLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdFx0XHR9XG5cdFx0XHR9XG5cdFx0XHRjb25zdCBzbmFwQ2xpbmljID0gbWFuYWdlci5jcmVhdGUoQ2xpbmljRW50aXR5LCB7XG5cdFx0XHRcdHBob25lLFxuXHRcdFx0XHRlbWFpbCxcblx0XHRcdFx0bGV2ZWw6IDEsXG5cdFx0XHR9KVxuXHRcdFx0Y29uc3QgbmV3Q2xpbmljID0gYXdhaXQgbWFuYWdlci5zYXZlKHNuYXBDbGluaWMpXG5cblx0XHRcdGNvbnN0IHNuYXBFbXBsb3llZSA9IG1hbmFnZXIuY3JlYXRlKEVtcGxveWVlRW50aXR5LCB7XG5cdFx0XHRcdGNsaW5pY0lkOiBuZXdDbGluaWMuaWQsXG5cdFx0XHRcdGNsaW5pYzogbmV3Q2xpbmljLFxuXHRcdFx0XHR1c2VybmFtZSxcblx0XHRcdFx0cGFzc3dvcmQ6IGhhc2hQYXNzd29yZCxcblx0XHRcdFx0cm9sZTogRVJvbGUuT3duZXIsXG5cdFx0XHR9KVxuXHRcdFx0Y29uc3QgbmV3RW1wbG95ZWUgPSBhd2FpdCBtYW5hZ2VyLnNhdmUoc25hcEVtcGxveWVlKVxuXG5cdFx0XHRyZXR1cm4gbmV3RW1wbG95ZWVcblx0XHR9KVxuXG5cdFx0cmV0dXJuIGVtcGxveWVlXG5cdH1cblxuXHRhc3luYyBsb2dpbihsb2dpbkR0bzogTG9naW5EdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZW1wbG95ZWUgPSBhd2FpdCB0aGlzLmRhdGFTb3VyY2UubWFuYWdlci5maW5kT25lKEVtcGxveWVlRW50aXR5LCB7XG5cdFx0XHRyZWxhdGlvbnM6IHsgY2xpbmljOiB0cnVlIH0sXG5cdFx0XHR3aGVyZToge1xuXHRcdFx0XHR1c2VybmFtZTogbG9naW5EdG8udXNlcm5hbWUsXG5cdFx0XHRcdGNsaW5pYzogeyBwaG9uZTogbG9naW5EdG8uY1Bob25lIH0sXG5cdFx0XHR9LFxuXHRcdH0pXG5cdFx0aWYgKCFlbXBsb3llZSkgdGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuRW1wbG95ZWVEb2VzTm90RXhpc3QsIEh0dHBTdGF0dXMuQkFEX1JFUVVFU1QpXG5cblx0XHRjb25zdCBjaGVja1Bhc3N3b3JkID0gYXdhaXQgYmNyeXB0LmNvbXBhcmUobG9naW5EdG8ucGFzc3dvcmQsIGVtcGxveWVlLnBhc3N3b3JkKVxuXHRcdGlmICghY2hlY2tQYXNzd29yZCkgdGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUxvZ2luRXJyb3IuV3JvbmdQYXNzd29yZCwgSHR0cFN0YXR1cy5CQURfR0FURVdBWSlcblxuXHRcdHJldHVybiBlbXBsb3llZVxuXHR9XG5cblx0YXN5bmMgZ3JhbnRBY2Nlc3NUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZywgaXA6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG5cdFx0Y29uc3QgeyB1aWQgfSA9IHRoaXMuand0RXh0ZW5kU2VydmljZS52ZXJpZnlSZWZyZXNoVG9rZW4ocmVmcmVzaFRva2VuLCBpcClcblxuXHRcdGNvbnN0IGVtcGxveWVlID0gYXdhaXQgdGhpcy5kYXRhU291cmNlLmdldFJlcG9zaXRvcnkoRW1wbG95ZWVFbnRpdHkpLmZpbmRPbmUoe1xuXHRcdFx0cmVsYXRpb25zOiB7IGNsaW5pYzogdHJ1ZSB9LFxuXHRcdFx0d2hlcmU6IHsgaWQ6IHVpZCB9LFxuXHRcdH0pXG5cblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IHRoaXMuand0RXh0ZW5kU2VydmljZS5jcmVhdGVBY2Nlc3NUb2tlbihlbXBsb3llZSwgaXApXG5cdFx0cmV0dXJuIGFjY2Vzc1Rva2VuXG5cdH1cbn1cbiIsImltcG9ydCB7IEh0dHBFeGNlcHRpb24sIEh0dHBTdGF0dXMsIEluamVjdCB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnVHlwZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgSnd0U2VydmljZSB9IGZyb20gJ0BuZXN0anMvand0J1xuaW1wb3J0IFVzZXJFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9lbXBsb3llZS5lbnRpdHknXG5pbXBvcnQgeyBJSnd0UGF5bG9hZCB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnXG5pbXBvcnQgeyBKd3RDb25maWcgfSBmcm9tICcuLi8uLi9lbnZpcm9ubWVudHMnXG5pbXBvcnQgeyBFRXJyb3IsIEVUb2tlbkVycm9yIH0gZnJvbSAnLi4vLi4vZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0nXG5cbmV4cG9ydCBjbGFzcyBKd3RFeHRlbmRTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoXG5cdFx0QEluamVjdChKd3RDb25maWcuS0VZKSBwcml2YXRlIGp3dENvbmZpZzogQ29uZmlnVHlwZTx0eXBlb2YgSnd0Q29uZmlnPixcblx0XHRwcml2YXRlIHJlYWRvbmx5IGp3dFNlcnZpY2U6IEp3dFNlcnZpY2Vcblx0KSB7IH1cblxuXHRjcmVhdGVBY2Nlc3NUb2tlbih1c2VyOiBVc2VyRW50aXR5LCBpcDogc3RyaW5nKTogc3RyaW5nIHtcblx0XHRjb25zdCB1c2VyUGF5bG9hZDogSUp3dFBheWxvYWQgPSB7XG5cdFx0XHRpcCxcblx0XHRcdGNQaG9uZTogdXNlci5jbGluaWMucGhvbmUsXG5cdFx0XHRjaWQ6IHVzZXIuY2xpbmljLmlkLFxuXHRcdFx0dWlkOiB1c2VyLmlkLFxuXHRcdFx0dXNlcm5hbWU6IHVzZXIudXNlcm5hbWUsXG5cdFx0XHRyb2xlOiB1c2VyLnJvbGUsXG5cdFx0fVxuXHRcdHJldHVybiB0aGlzLmp3dFNlcnZpY2Uuc2lnbih1c2VyUGF5bG9hZCwge1xuXHRcdFx0c2VjcmV0OiB0aGlzLmp3dENvbmZpZy5hY2Nlc3NLZXksXG5cdFx0XHRleHBpcmVzSW46IHRoaXMuand0Q29uZmlnLmFjY2Vzc1RpbWUsXG5cdFx0fSlcblx0fVxuXG5cdGNyZWF0ZVJlZnJlc2hUb2tlbih1aWQ6IG51bWJlciwgaXA6IHN0cmluZyk6IHN0cmluZyB7XG5cdFx0cmV0dXJuIHRoaXMuand0U2VydmljZS5zaWduKHsgdWlkLCBpcCB9LCB7XG5cdFx0XHRzZWNyZXQ6IHRoaXMuand0Q29uZmlnLnJlZnJlc2hLZXksXG5cdFx0XHRleHBpcmVzSW46IHRoaXMuand0Q29uZmlnLnJlZnJlc2hUaW1lLFxuXHRcdH0pXG5cdH1cblxuXHRjcmVhdGVUb2tlbkZyb21Vc2VyKHVzZXI6IFVzZXJFbnRpdHksIGlwOiBzdHJpbmcpIHtcblx0XHRjb25zdCBhY2Nlc3NUb2tlbiA9IHRoaXMuY3JlYXRlQWNjZXNzVG9rZW4odXNlciwgaXApXG5cdFx0Y29uc3QgcmVmcmVzaFRva2VuID0gdGhpcy5jcmVhdGVSZWZyZXNoVG9rZW4odXNlci5pZCwgaXApXG5cdFx0cmV0dXJuIHsgYWNjZXNzVG9rZW4sIHJlZnJlc2hUb2tlbiB9XG5cdH1cblxuXHR2ZXJpZnlBY2Nlc3NUb2tlbihhY2Nlc3NUb2tlbjogc3RyaW5nLCBpcDogc3RyaW5nKTogSUp3dFBheWxvYWQge1xuXHRcdHRyeSB7XG5cdFx0XHRjb25zdCBqd3RQYXlsb2FkOiBJSnd0UGF5bG9hZCA9IHRoaXMuand0U2VydmljZS52ZXJpZnkoYWNjZXNzVG9rZW4sIHsgc2VjcmV0OiB0aGlzLmp3dENvbmZpZy5hY2Nlc3NLZXkgfSlcblx0XHRcdGlmIChqd3RQYXlsb2FkLmlwICE9PSBpcCkge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5JbnZhbGlkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH1cblx0XHRcdHJldHVybiBqd3RQYXlsb2FkXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuVU5BVVRIT1JJWkVEKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vd24sIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxuXG5cdHZlcmlmeVJlZnJlc2hUb2tlbihyZWZyZXNoVG9rZW46IHN0cmluZywgaXA6IHN0cmluZyk6IHsgdWlkOiBudW1iZXIgfSB7XG5cdFx0dHJ5IHtcblx0XHRcdGNvbnN0IGp3dFBheWxvYWQgPSB0aGlzLmp3dFNlcnZpY2UudmVyaWZ5KHJlZnJlc2hUb2tlbiwgeyBzZWNyZXQ6IHRoaXMuand0Q29uZmlnLnJlZnJlc2hLZXkgfSlcblx0XHRcdGlmIChqd3RQYXlsb2FkLmlwICE9PSBpcCkge1xuXHRcdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFVG9rZW5FcnJvci5JbnZhbGlkLCBIdHRwU3RhdHVzLlVOQVVUSE9SSVpFRClcblx0XHRcdH1cblx0XHRcdHJldHVybiBqd3RQYXlsb2FkXG5cdFx0fSBjYXRjaCAoZXJyb3IpIHtcblx0XHRcdGlmIChlcnJvci5uYW1lID09PSAnVG9rZW5FeHBpcmVkRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkV4cGlyZWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fSBlbHNlIGlmIChlcnJvci5uYW1lID09PSAnSnNvbldlYlRva2VuRXJyb3InKSB7XG5cdFx0XHRcdHRocm93IG5ldyBIdHRwRXhjZXB0aW9uKEVUb2tlbkVycm9yLkludmFsaWQsIEh0dHBTdGF0dXMuRk9SQklEREVOKVxuXHRcdFx0fVxuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVycm9yLlVua25vd24sIEh0dHBTdGF0dXMuSU5URVJOQUxfU0VSVkVSX0VSUk9SKVxuXHRcdH1cblx0fVxufVxuIiwiaW1wb3J0IHsgQ29udHJvbGxlciwgR2V0LCBQb3N0LCBCb2R5LCBQYXRjaCwgUGFyYW0sIERlbGV0ZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5pbXBvcnQgeyBDcmVhdGVDbGluaWNEdG8sIFVwZGF0ZUNsaW5pY0R0byB9IGZyb20gJy4vY2xpbmljLmR0bydcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5cbkBBcGlUYWdzKCdDbGluaWMnKVxuQEFwaUJlYXJlckF1dGgoJ2FjY2Vzcy10b2tlbicpXG5AQ29udHJvbGxlcignY2xpbmljJylcbmV4cG9ydCBjbGFzcyBDbGluaWNDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBjbGluaWNTZXJ2aWNlOiBDbGluaWNTZXJ2aWNlKSB7IH1cblxuXHRAUG9zdCgpXG5cdGNyZWF0ZShAQm9keSgpIGNyZWF0ZUNsaW5pY0R0bzogQ3JlYXRlQ2xpbmljRHRvKSB7XG5cdFx0cmV0dXJuICcnXG5cdH1cblxuXHRAR2V0KClcblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLmZpbmRBbGwoKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLmNsaW5pY1NlcnZpY2UuZmluZE9uZSgraWQpXG5cdH1cblxuXHRARGVsZXRlKCc6aWQnKVxuXHRyZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcpIHtcblx0XHRyZXR1cm4gdGhpcy5jbGluaWNTZXJ2aWNlLnJlbW92ZSgraWQpXG5cdH1cbn1cbiIsImltcG9ydCB7IFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgSXNFbWFpbCwgTGVuZ3RoIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuXG5leHBvcnQgY2xhc3MgQ3JlYXRlQ2xpbmljRHRvIHtcblx0QElzRW1haWwoKVxuXHRlbWFpbDogc3RyaW5nXG5cblx0QExlbmd0aCgxMCwgMTApXG5cdHBob25lOiBzdHJpbmdcblxuXHRATGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcbn1cblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUNsaW5pY0R0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZUNsaW5pY0R0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCB7IENsaW5pY0NvbnRyb2xsZXIgfSBmcm9tICcuL2NsaW5pYy5jb250cm9sbGVyJ1xuaW1wb3J0IHsgQ2xpbmljU2VydmljZSB9IGZyb20gJy4vY2xpbmljLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtDbGluaWNFbnRpdHldKV0sXG5cdGNvbnRyb2xsZXJzOiBbQ2xpbmljQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0NsaW5pY1NlcnZpY2VdLFxuXHRleHBvcnRzOiBbQ2xpbmljU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIENsaW5pY01vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEluamVjdFJlcG9zaXRvcnkgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgeyBEYXRhU291cmNlLCBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBDbGluaWNFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9jbGluaWMuZW50aXR5J1xuXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgQ2xpbmljU2VydmljZSB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdEBJbmplY3RSZXBvc2l0b3J5KENsaW5pY0VudGl0eSkgcHJpdmF0ZSBjbGluaWNSZXBvc2l0b3J5OiBSZXBvc2l0b3J5PENsaW5pY0VudGl0eT4sXG5cdFx0cHJpdmF0ZSBkYXRhU291cmNlOiBEYXRhU291cmNlXG5cdCkgeyB9XG5cblx0ZmluZEFsbCgpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYWxsIGNsaW5pY2Bcblx0fVxuXG5cdGZpbmRPbmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHR1cGRhdGUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gdXBkYXRlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cblxuXHRyZW1vdmUoaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmVtb3ZlcyBhICMke2lkfSBjbGluaWNgXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QsIFJlcSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQXBpQmVhcmVyQXV0aCwgQXBpUGFyYW0sIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBFUm9sZSB9IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvZW1wbG95ZWUuZW50aXR5J1xuaW1wb3J0IHsgUmVxdWVzdFRva2VuIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cydcbmltcG9ydCB7IFJvbGVzIH0gZnJvbSAnLi4vLi4vZ3VhcmRzL3JvbGVzLmd1YXJkJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8sIFVwZGF0ZUVtcGxveWVlRHRvIH0gZnJvbSAnLi9lbXBsb3llZS5kdG8nXG5pbXBvcnQgeyBFbXBsb3llZVNlcnZpY2UgfSBmcm9tICcuL2VtcGxveWVlLnNlcnZpY2UnXG5cbkBBcGlUYWdzKCdFbXBsb3llZScpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBSb2xlcyhFUm9sZS5BZG1pbiwgRVJvbGUuT3duZXIpXG5AQ29udHJvbGxlcignZW1wbG95ZWUnKVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgZW1wbG95ZWVTZXJ2aWNlOiBFbXBsb3llZVNlcnZpY2UpIHsgfVxuXG5cdEBHZXQoKVxuXHRmaW5kQWxsKEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5maW5kQWxsKGNsaW5pY0lkKVxuXHR9XG5cblx0QFBvc3QoKVxuXHRjcmVhdGUoQEJvZHkoKSBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8sIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdHJldHVybiB0aGlzLmVtcGxveWVlU2VydmljZS5jcmVhdGUoY2xpbmljSWQsIGNyZWF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5lbXBsb3llZVNlcnZpY2UuZmluZE9uZShjbGluaWNJZCwgK2lkKVxuXHR9XG5cblx0QFBhdGNoKCd1cGRhdGUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyB1cGRhdGUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4sIEBCb2R5KCkgdXBkYXRlRW1wbG95ZWVEdG86IFVwZGF0ZUVtcGxveWVlRHRvKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLmVtcGxveWVlU2VydmljZS51cGRhdGUoY2xpbmljSWQsICtpZCwgdXBkYXRlRW1wbG95ZWVEdG8pXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBEZWxldGUoJ3JlbW92ZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0YXdhaXQgdGhpcy5lbXBsb3llZVNlcnZpY2UucmVtb3ZlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBQYXRjaCgncmVzdG9yZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlc3RvcmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMuZW1wbG95ZWVTZXJ2aWNlLnJlc3RvcmUoY2xpbmljSWQsICtpZClcblx0XHRyZXR1cm4geyBtZXNzYWdlOiAnc3VjY2VzcycgfVxuXHR9XG59XG4iLCJpbXBvcnQgeyBBcGlQcm9wZXJ0eSwgUGFydGlhbFR5cGUgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBJc0RlZmluZWQsIE1pbkxlbmd0aCB9IGZyb20gJ2NsYXNzLXZhbGlkYXRvcidcblxuZXhwb3J0IGNsYXNzIENyZWF0ZUVtcGxveWVlRHRvIHtcblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ25oYXRkdW9uZzIwMTknIH0pXG5cdEBJc0RlZmluZWQoKVxuXHR1c2VybmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5KHsgZXhhbXBsZTogJ0FiY0AxMjM0NTYnIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRATWluTGVuZ3RoKDYpXG5cdHBhc3N3b3JkOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHkoeyBleGFtcGxlOiAnTmfDtCBOaOG6rXQgRMawxqFuZycgfSlcblx0ZnVsbE5hbWU6IHN0cmluZ1xufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlRW1wbG95ZWVEdG8gZXh0ZW5kcyBQYXJ0aWFsVHlwZShDcmVhdGVFbXBsb3llZUR0bykgeyB9XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgQ2xpbmljRW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvY2xpbmljLmVudGl0eSdcbmltcG9ydCBFbXBsb3llZUVudGl0eSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVtcGxveWVlQ29udHJvbGxlciB9IGZyb20gJy4vZW1wbG95ZWUuY29udHJvbGxlcidcbmltcG9ydCB7IEVtcGxveWVlU2VydmljZSB9IGZyb20gJy4vZW1wbG95ZWUuc2VydmljZSdcblxuQE1vZHVsZSh7XG5cdGltcG9ydHM6IFtUeXBlT3JtTW9kdWxlLmZvckZlYXR1cmUoW0VtcGxveWVlRW50aXR5XSldLFxuXHRjb250cm9sbGVyczogW0VtcGxveWVlQ29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW0VtcGxveWVlU2VydmljZV0sXG59KVxuZXhwb3J0IGNsYXNzIEVtcGxveWVlTW9kdWxlIHsgfVxuIiwiaW1wb3J0IHsgSW5qZWN0YWJsZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgSHR0cFN0YXR1cyB9IGZyb20gJ0BuZXN0anMvY29tbW9uL2VudW1zJ1xuaW1wb3J0IHsgSHR0cEV4Y2VwdGlvbiB9IGZyb20gJ0BuZXN0anMvY29tbW9uL2V4Y2VwdGlvbnMnXG5pbXBvcnQgeyBJbmplY3RSZXBvc2l0b3J5IH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0ICogYXMgYmNyeXB0IGZyb20gJ2JjcnlwdCdcbmltcG9ydCB7IHBsYWluVG9DbGFzcyB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgUmVwb3NpdG9yeSB9IGZyb20gJ3R5cGVvcm0nXG5pbXBvcnQgRW1wbG95ZWVFbnRpdHksIHsgRVJvbGUgfSBmcm9tICcuLi8uLi8uLi8uLi8uLi90eXBlb3JtL2VudGl0aWVzL2VtcGxveWVlLmVudGl0eSdcbmltcG9ydCB7IEVFbXBsb3llZUVycm9yLCBFUmVnaXN0ZXJFcnJvciB9IGZyb20gJy4uLy4uL2V4Y2VwdGlvbi1maWx0ZXJzL2V4Y2VwdGlvbi5lbnVtJ1xuaW1wb3J0IHsgQ3JlYXRlRW1wbG95ZWVEdG8sIFVwZGF0ZUVtcGxveWVlRHRvIH0gZnJvbSAnLi9lbXBsb3llZS5kdG8nXG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBFbXBsb3llZVNlcnZpY2Uge1xuXHRjb25zdHJ1Y3RvcihASW5qZWN0UmVwb3NpdG9yeShFbXBsb3llZUVudGl0eSkgcHJpdmF0ZSBlbXBsb3llZVJlcG9zaXRvcnk6IFJlcG9zaXRvcnk8RW1wbG95ZWVFbnRpdHk+KSB7IH1cblxuXHRhc3luYyBmaW5kQWxsKGNsaW5pY0lkOiBudW1iZXIpOiBQcm9taXNlPEVtcGxveWVlRW50aXR5W10+IHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZCh7IHdoZXJlOiB7IGNsaW5pY0lkIH0gfSlcblx0fVxuXG5cdGFzeW5jIGNyZWF0ZShjbGluaWNJZDogbnVtYmVyLCBjcmVhdGVFbXBsb3llZUR0bzogQ3JlYXRlRW1wbG95ZWVEdG8pOiBQcm9taXNlPEVtcGxveWVlRW50aXR5PiB7XG5cdFx0Y29uc3QgZmluZEVtcGxveWVlID0gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuZmluZE9uZUJ5KHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0dXNlcm5hbWU6IGNyZWF0ZUVtcGxveWVlRHRvLnVzZXJuYW1lLFxuXHRcdH0pXG5cdFx0aWYgKGZpbmRFbXBsb3llZSkge1xuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRVJlZ2lzdGVyRXJyb3IuRXhpc3RVc2VybmFtZSwgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHR9XG5cdFx0Y29uc3Qgc25hcEVtcGxveWVlID0gcGxhaW5Ub0NsYXNzKEVtcGxveWVlRW50aXR5LCBjcmVhdGVFbXBsb3llZUR0bylcblx0XHRzbmFwRW1wbG95ZWUucGFzc3dvcmQgPSBhd2FpdCBiY3J5cHQuaGFzaChjcmVhdGVFbXBsb3llZUR0by5wYXNzd29yZCwgNSlcblx0XHRzbmFwRW1wbG95ZWUucm9sZSA9IEVSb2xlLlVzZXJcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkuc2F2ZShjcmVhdGVFbXBsb3llZUR0bylcblx0fVxuXG5cdGFzeW5jIGZpbmRPbmUoY2xpbmljSWQ6IG51bWJlciwgaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5maW5kT25lQnkoeyBjbGluaWNJZCwgaWQgfSlcblx0fVxuXG5cdGFzeW5jIHVwZGF0ZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyLCB1cGRhdGVFbXBsb3llZUR0bzogVXBkYXRlRW1wbG95ZWVEdG8pIHtcblx0XHRjb25zdCBmaW5kRW1wbG95ZWUgPSBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5maW5kT25lQnkoeyBjbGluaWNJZCwgaWQgfSlcblx0XHRpZiAoIWZpbmRFbXBsb3llZSkge1xuXHRcdFx0dGhyb3cgbmV3IEh0dHBFeGNlcHRpb24oRUVtcGxveWVlRXJyb3IuTm90RXhpc3RzLCBIdHRwU3RhdHVzLkJBRF9SRVFVRVNUKVxuXHRcdH1cblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5lbXBsb3llZVJlcG9zaXRvcnkudXBkYXRlKHsgY2xpbmljSWQsIGlkIH0sIHVwZGF0ZUVtcGxveWVlRHRvKVxuXHR9XG5cblx0YXN5bmMgcmVtb3ZlKGNsaW5pY0lkOiBudW1iZXIsIGVtcGxveWVlSWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLmVtcGxveWVlUmVwb3NpdG9yeS5zb2Z0RGVsZXRlKHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0aWQ6IGVtcGxveWVlSWQsXG5cdFx0fSlcblx0fVxuXG5cdGFzeW5jIHJlc3RvcmUoY2xpbmljSWQ6IG51bWJlciwgZW1wbG95ZWVJZDogbnVtYmVyKSB7XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMuZW1wbG95ZWVSZXBvc2l0b3J5LnJlc3RvcmUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZDogZW1wbG95ZWVJZCxcblx0XHR9KVxuXHR9XG59XG4iLCJpbXBvcnQgeyBDb250cm9sbGVyLCBHZXQgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQge1xuXHREaXNrSGVhbHRoSW5kaWNhdG9yLCBIZWFsdGhDaGVjaywgSGVhbHRoQ2hlY2tTZXJ2aWNlLCBIdHRwSGVhbHRoSW5kaWNhdG9yLFxuXHRNZW1vcnlIZWFsdGhJbmRpY2F0b3IsIFR5cGVPcm1IZWFsdGhJbmRpY2F0b3IsXG59IGZyb20gJ0BuZXN0anMvdGVybWludXMnXG5cbkBBcGlUYWdzKCdIZWFsdGgnKVxuQENvbnRyb2xsZXIoJ2hlYWx0aCcpXG5leHBvcnQgY2xhc3MgSGVhbHRoQ29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgaGVhbHRoOiBIZWFsdGhDaGVja1NlcnZpY2UsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBodHRwOiBIdHRwSGVhbHRoSW5kaWNhdG9yLFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgZGI6IFR5cGVPcm1IZWFsdGhJbmRpY2F0b3IsXG5cdFx0cHJpdmF0ZSByZWFkb25seSBkaXNrOiBEaXNrSGVhbHRoSW5kaWNhdG9yLFxuXHRcdHByaXZhdGUgcmVhZG9ubHkgbWVtb3J5OiBNZW1vcnlIZWFsdGhJbmRpY2F0b3Jcblx0KSB7IH1cblxuXHRAR2V0KClcblx0QEhlYWx0aENoZWNrKClcblx0Y2hlY2soKSB7XG5cdFx0Y29uc3QgcGF0aFN0b3JhZ2UgPSBwcm9jZXNzLnBsYXRmb3JtID09PSAnd2luMzInID8gJ0M6XFxcXCcgOiAnLydcblx0XHRjb25zdCB0aHJlc2hvbGRQZXJjZW50ID0gcHJvY2Vzcy5wbGF0Zm9ybSA9PT0gJ3dpbjMyJyA/IDAuOSA6IDAuNVxuXG5cdFx0cmV0dXJuIHRoaXMuaGVhbHRoLmNoZWNrKFtcblx0XHRcdCgpID0+IHRoaXMuaHR0cC5waW5nQ2hlY2soJ25lc3Rqcy1kb2NzJywgJ2h0dHBzOi8vbWVkaWhvbWUudm4vZG9jdW1lbnQnKSxcblx0XHRcdCgpID0+IHRoaXMuZGIucGluZ0NoZWNrKCdkYXRhYmFzZScpLFxuXHRcdFx0KCkgPT4gdGhpcy5kaXNrLmNoZWNrU3RvcmFnZSgnc3RvcmFnZScsIHsgcGF0aDogcGF0aFN0b3JhZ2UsIHRocmVzaG9sZFBlcmNlbnQgfSksXG5cdFx0XHQoKSA9PiB0aGlzLm1lbW9yeS5jaGVja0hlYXAoJ21lbW9yeV9oZWFwJywgMTUwICogMTAyNCAqIDEwMjQpLFxuXHRcdFx0KCkgPT4gdGhpcy5tZW1vcnkuY2hlY2tSU1MoJ21lbW9yeV9yc3MnLCAxNTAgKiAxMDI0ICogMTAyNCksXG5cdFx0XSlcblx0fVxufVxuIiwiaW1wb3J0IHsgSHR0cE1vZHVsZSB9IGZyb20gJ0BuZXN0anMvYXhpb3MnXG5pbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFRlcm1pbnVzTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90ZXJtaW51cydcbmltcG9ydCB7IEhlYWx0aENvbnRyb2xsZXIgfSBmcm9tICcuL2hlYWx0aC5jb250cm9sbGVyJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1Rlcm1pbnVzTW9kdWxlLCBIdHRwTW9kdWxlXSxcblx0Y29udHJvbGxlcnM6IFtIZWFsdGhDb250cm9sbGVyXSxcbn0pXG5leHBvcnQgY2xhc3MgSGVhbHRoTW9kdWxlIHsgfVxuIiwiZXhwb3J0IGNsYXNzIENyZWF0ZU1lZGljaW5lRHRvIHt9XG4iLCJpbXBvcnQgeyBQYXJ0aWFsVHlwZSB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IENyZWF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9jcmVhdGUtbWVkaWNpbmUuZHRvJ1xuXG5leHBvcnQgY2xhc3MgVXBkYXRlTWVkaWNpbmVEdG8gZXh0ZW5kcyBQYXJ0aWFsVHlwZShDcmVhdGVNZWRpY2luZUR0bykge31cbiIsImltcG9ydCB7IEJvZHksIENvbnRyb2xsZXIsIERlbGV0ZSwgR2V0LCBQYXJhbSwgUGF0Y2gsIFBvc3QgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVRhZ3MgfSBmcm9tICdAbmVzdGpzL3N3YWdnZXInXG5pbXBvcnQgeyBDcmVhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL2NyZWF0ZS1tZWRpY2luZS5kdG8nXG5pbXBvcnQgeyBVcGRhdGVNZWRpY2luZUR0byB9IGZyb20gJy4vZHRvL3VwZGF0ZS1tZWRpY2luZS5kdG8nXG5pbXBvcnQgeyBNZWRpY2luZVNlcnZpY2UgfSBmcm9tICcuL21lZGljaW5lLnNlcnZpY2UnXG5cbkBBcGlUYWdzKCdNZWRpY2luZScpXG5AQXBpQmVhcmVyQXV0aCgnYWNjZXNzLXRva2VuJylcbkBDb250cm9sbGVyKCdtZWRpY2luZScpXG5leHBvcnQgY2xhc3MgTWVkaWNpbmVDb250cm9sbGVyIHtcblx0Y29uc3RydWN0b3IocHJpdmF0ZSByZWFkb25seSBtZWRpY2luZVNlcnZpY2U6IE1lZGljaW5lU2VydmljZSkgeyB9XG5cblx0QFBvc3QoKVxuXHRjcmVhdGUoQEJvZHkoKSBjcmVhdGVNZWRpY2luZUR0bzogQ3JlYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gdGhpcy5tZWRpY2luZVNlcnZpY2UuY3JlYXRlKGNyZWF0ZU1lZGljaW5lRHRvKVxuXHR9XG5cblx0QEdldCgpXG5cdGZpbmRBbGwoKSB7XG5cdFx0cmV0dXJuIHRoaXMubWVkaWNpbmVTZXJ2aWNlLmZpbmRBbGwoKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0ZmluZE9uZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5maW5kT25lKCtpZClcblx0fVxuXG5cdEBQYXRjaCgnOmlkJylcblx0dXBkYXRlKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAQm9keSgpIHVwZGF0ZU1lZGljaW5lRHRvOiBVcGRhdGVNZWRpY2luZUR0bykge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS51cGRhdGUoK2lkLCB1cGRhdGVNZWRpY2luZUR0bylcblx0fVxuXG5cdEBEZWxldGUoJzppZCcpXG5cdHJlbW92ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZykge1xuXHRcdHJldHVybiB0aGlzLm1lZGljaW5lU2VydmljZS5yZW1vdmUoK2lkKVxuXHR9XG59XG4iLCJpbXBvcnQgeyBNb2R1bGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IFR5cGVPcm1Nb2R1bGUgfSBmcm9tICdAbmVzdGpzL3R5cGVvcm0nXG5pbXBvcnQgTWVkaWNpbmVFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9tZWRpY2luZS5lbnRpdHknXG5pbXBvcnQgeyBNZWRpY2luZUNvbnRyb2xsZXIgfSBmcm9tICcuL21lZGljaW5lLmNvbnRyb2xsZXInXG5pbXBvcnQgeyBNZWRpY2luZVNlcnZpY2UgfSBmcm9tICcuL21lZGljaW5lLnNlcnZpY2UnXG5cbkBNb2R1bGUoe1xuXHRpbXBvcnRzOiBbVHlwZU9ybU1vZHVsZS5mb3JGZWF0dXJlKFtNZWRpY2luZUVudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtNZWRpY2luZUNvbnRyb2xsZXJdLFxuXHRwcm92aWRlcnM6IFtNZWRpY2luZVNlcnZpY2VdLFxufSlcbmV4cG9ydCBjbGFzcyBNZWRpY2luZU1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IENyZWF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vY3JlYXRlLW1lZGljaW5lLmR0bydcbmltcG9ydCB7IFVwZGF0ZU1lZGljaW5lRHRvIH0gZnJvbSAnLi9kdG8vdXBkYXRlLW1lZGljaW5lLmR0bydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIE1lZGljaW5lU2VydmljZSB7XG5cdGNyZWF0ZShjcmVhdGVNZWRpY2luZUR0bzogQ3JlYXRlTWVkaWNpbmVEdG8pIHtcblx0XHRyZXR1cm4gJ1RoaXMgYWN0aW9uIGFkZHMgYSBuZXcgbWVkaWNpbmUnXG5cdH1cblxuXHRmaW5kQWxsKCkge1xuXHRcdHJldHVybiBgVGhpcyBhY3Rpb24gcmV0dXJucyBhbGwgbWVkaWNpbmVgXG5cdH1cblxuXHRmaW5kT25lKGlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJldHVybnMgYSAjJHtpZH0gbWVkaWNpbmVgXG5cdH1cblxuXHR1cGRhdGUoaWQ6IG51bWJlciwgdXBkYXRlTWVkaWNpbmVEdG86IFVwZGF0ZU1lZGljaW5lRHRvKSB7XG5cdFx0cmV0dXJuIGBUaGlzIGFjdGlvbiB1cGRhdGVzIGEgIyR7aWR9IG1lZGljaW5lYFxuXHR9XG5cblx0cmVtb3ZlKGlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYFRoaXMgYWN0aW9uIHJlbW92ZXMgYSAjJHtpZH0gbWVkaWNpbmVgXG5cdH1cbn1cbiIsImltcG9ydCB7IEJvZHksIENsYXNzU2VyaWFsaXplckludGVyY2VwdG9yLCBDb250cm9sbGVyLCBEZWxldGUsIEdldCwgUGFyYW0sIFBhdGNoLCBQb3N0LCBRdWVyeSwgUmVxLCBVc2VJbnRlcmNlcHRvcnMgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEFwaUJlYXJlckF1dGgsIEFwaVBhcmFtLCBBcGlRdWVyeSwgQXBpVGFncyB9IGZyb20gJ0BuZXN0anMvc3dhZ2dlcidcbmltcG9ydCB7IFJlcXVlc3RUb2tlbiB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnXG5pbXBvcnQgeyBDcmVhdGVQYXRpZW50RHRvLCBVcGRhdGVQYXRpZW50RHRvIH0gZnJvbSAnLi9wYXRpZW50LmR0bydcbmltcG9ydCB7IFBhdGllbnRTZXJ2aWNlIH0gZnJvbSAnLi9wYXRpZW50LnNlcnZpY2UnXG5cbkBBcGlUYWdzKCdQYXRpZW50JylcbkBBcGlCZWFyZXJBdXRoKCdhY2Nlc3MtdG9rZW4nKVxuQFVzZUludGVyY2VwdG9ycyhDbGFzc1NlcmlhbGl6ZXJJbnRlcmNlcHRvcilcbkBDb250cm9sbGVyKCdwYXRpZW50JylcbmV4cG9ydCBjbGFzcyBQYXRpZW50Q29udHJvbGxlciB7XG5cdGNvbnN0cnVjdG9yKHByaXZhdGUgcmVhZG9ubHkgcGF0aWVudFNlcnZpY2U6IFBhdGllbnRTZXJ2aWNlKSB7IH1cblxuXHRAR2V0KClcblx0ZmluZEFsbChAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS5maW5kQWxsKGNsaW5pY0lkKVxuXHR9XG5cblx0QEdldCgnc2VhcmNoJylcblx0QEFwaVF1ZXJ5KHsgbmFtZTogJ3NlYXJjaFRleHQnLCBleGFtcGxlOiAnMDk4NjEyMzQ1NicgfSlcblx0c2VhcmNoKEBRdWVyeSgnc2VhcmNoVGV4dCcpIHNlYXJjaFRleHQ6IHN0cmluZywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0aWYgKC9eXFxkKyQvLnRlc3Qoc2VhcmNoVGV4dCkpIHtcblx0XHRcdHJldHVybiB0aGlzLnBhdGllbnRTZXJ2aWNlLmZpbmRCeVBob25lKGNsaW5pY0lkLCBzZWFyY2hUZXh0KVxuXHRcdH1cblx0XHRyZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS5maW5kQnlGdWxsTmFtZShjbGluaWNJZCwgc2VhcmNoVGV4dClcblx0fVxuXG5cdEBQb3N0KClcblx0Y3JlYXRlKEBCb2R5KCkgY3JlYXRlUGF0aWVudER0bzogQ3JlYXRlUGF0aWVudER0bywgQFJlcSgpIHJlcXVlc3Q6IFJlcXVlc3RUb2tlbikge1xuXHRcdGNvbnN0IGNsaW5pY0lkID0gcmVxdWVzdC50b2tlblBheWxvYWQuY2lkXG5cdFx0cmV0dXJuIHRoaXMucGF0aWVudFNlcnZpY2UuY3JlYXRlKGNsaW5pY0lkLCBjcmVhdGVQYXRpZW50RHRvKVxuXHR9XG5cblx0QEdldCgnOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRmaW5kT25lKEBQYXJhbSgnaWQnKSBpZDogc3RyaW5nLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRyZXR1cm4gdGhpcy5wYXRpZW50U2VydmljZS5maW5kT25lKGNsaW5pY0lkLCAraWQpXG5cdH1cblxuXHRAUGF0Y2goJ3VwZGF0ZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHVwZGF0ZShAUGFyYW0oJ2lkJykgaWQ6IHN0cmluZywgQEJvZHkoKSB1cGRhdGVQYXRpZW50RHRvOiBVcGRhdGVQYXRpZW50RHRvLCBAUmVxKCkgcmVxdWVzdDogUmVxdWVzdFRva2VuKSB7XG5cdFx0Y29uc3QgY2xpbmljSWQgPSByZXF1ZXN0LnRva2VuUGF5bG9hZC5jaWRcblx0XHRhd2FpdCB0aGlzLnBhdGllbnRTZXJ2aWNlLnVwZGF0ZShjbGluaWNJZCwgK2lkLCB1cGRhdGVQYXRpZW50RHRvKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cblxuXHRARGVsZXRlKCdyZW1vdmUvOmlkJylcblx0QEFwaVBhcmFtKHsgbmFtZTogJ2lkJywgZXhhbXBsZTogMSB9KVxuXHRhc3luYyByZW1vdmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMucGF0aWVudFNlcnZpY2UucmVtb3ZlKGNsaW5pY0lkLCAraWQpXG5cdFx0cmV0dXJuIHsgbWVzc2FnZTogJ3N1Y2Nlc3MnIH1cblx0fVxuXG5cdEBQYXRjaCgncmVzdG9yZS86aWQnKVxuXHRAQXBpUGFyYW0oeyBuYW1lOiAnaWQnLCBleGFtcGxlOiAxIH0pXG5cdGFzeW5jIHJlc3RvcmUoQFBhcmFtKCdpZCcpIGlkOiBzdHJpbmcsIEBSZXEoKSByZXF1ZXN0OiBSZXF1ZXN0VG9rZW4pIHtcblx0XHRjb25zdCBjbGluaWNJZCA9IHJlcXVlc3QudG9rZW5QYXlsb2FkLmNpZFxuXHRcdGF3YWl0IHRoaXMucGF0aWVudFNlcnZpY2UucmVzdG9yZShjbGluaWNJZCwgK2lkKVxuXHRcdHJldHVybiB7IG1lc3NhZ2U6ICdzdWNjZXNzJyB9XG5cdH1cbn1cbiIsImltcG9ydCB7IEFwaVByb3BlcnR5T3B0aW9uYWwsIFBhcnRpYWxUeXBlIH0gZnJvbSAnQG5lc3Rqcy9zd2FnZ2VyJ1xuaW1wb3J0IHsgVHlwZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgSXNEYXRlLCBJc0RlZmluZWQsIElzRW51bSwgSXNTdHJpbmcsIFZhbGlkYXRlIH0gZnJvbSAnY2xhc3MtdmFsaWRhdG9yJ1xuaW1wb3J0IHsgRUdlbmRlciB9IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vYmFzZS5lbnRpdHknXG5pbXBvcnQgeyBJc1Bob25lIH0gZnJvbSAnLi4vLi4vY29tbW9uL2NsYXNzLXZhbGlkYXRvci5jdXN0b20nXG5cbmV4cG9ydCBjbGFzcyBDcmVhdGVQYXRpZW50RHRvIHtcblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnUGjhuqFtIEhvw6BuZyBNYWknIH0pXG5cdEBJc0RlZmluZWQoKVxuXHRmdWxsTmFtZTogc3RyaW5nXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnMDk4NjEyMzQ1NicgfSlcblx0QFZhbGlkYXRlKElzUGhvbmUpXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6IEVHZW5kZXIuRmVtYWxlIH0pXG5cdEBJc0VudW0oRUdlbmRlcilcblx0Z2VuZGVyOiBFR2VuZGVyXG5cblx0QEFwaVByb3BlcnR5T3B0aW9uYWwoeyBleGFtcGxlOiAnVGjDoG5oIHBo4buRIEjDoCBO4buZaSAtLSBRdeG6rW4gTG9uZyBCacOqbiAtLSBQaMaw4budbmcgVGjhuqFjaCBCw6BuIC0tIHPhu5EgOCAtIHTDsmEgbmjDoCDEkOG6o28gQ+G6p3UgVuG7k25nJyB9KVxuXHRASXNTdHJpbmcoKVxuXHRhZGRyZXNzOiBzdHJpbmdcblxuXHRAQXBpUHJvcGVydHlPcHRpb25hbCh7IGV4YW1wbGU6ICcxOTk4LTExLTI4VDAwOjAwOjAwLjAwMFonIH0pXG5cdEBUeXBlKCgpID0+IERhdGUpXG5cdEBJc0RhdGUoKVxuXHRiaXJ0aGRheTogRGF0ZVxufVxuXG5leHBvcnQgY2xhc3MgVXBkYXRlUGF0aWVudER0byBleHRlbmRzIFBhcnRpYWxUeXBlKENyZWF0ZVBhdGllbnREdG8pIHsgfVxuIiwiaW1wb3J0IHsgTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy9jb21tb24nXG5pbXBvcnQgeyBUeXBlT3JtTW9kdWxlIH0gZnJvbSAnQG5lc3Rqcy90eXBlb3JtJ1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi4vLi4vLi4vLi4vLi4vdHlwZW9ybS9lbnRpdGllcy9wYXRpZW50LmVudGl0eSdcbmltcG9ydCB7IFBhdGllbnRDb250cm9sbGVyIH0gZnJvbSAnLi9wYXRpZW50LmNvbnRyb2xsZXInXG5pbXBvcnQgeyBQYXRpZW50U2VydmljZSB9IGZyb20gJy4vcGF0aWVudC5zZXJ2aWNlJ1xuXG5ATW9kdWxlKHtcblx0aW1wb3J0czogW1R5cGVPcm1Nb2R1bGUuZm9yRmVhdHVyZShbUGF0aWVudEVudGl0eV0pXSxcblx0Y29udHJvbGxlcnM6IFtQYXRpZW50Q29udHJvbGxlcl0sXG5cdHByb3ZpZGVyczogW1BhdGllbnRTZXJ2aWNlXSxcbn0pXG5leHBvcnQgY2xhc3MgUGF0aWVudE1vZHVsZSB7IH1cbiIsImltcG9ydCB7IEh0dHBTdGF0dXMsIEluamVjdGFibGUgfSBmcm9tICdAbmVzdGpzL2NvbW1vbidcbmltcG9ydCB7IEh0dHBFeGNlcHRpb24gfSBmcm9tICdAbmVzdGpzL2NvbW1vbi9leGNlcHRpb25zJ1xuaW1wb3J0IHsgSW5qZWN0UmVwb3NpdG9yeSB9IGZyb20gJ0BuZXN0anMvdHlwZW9ybSdcbmltcG9ydCB7IEVxdWFsLCBMaWtlLCBSZXBvc2l0b3J5IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCBQYXRpZW50RW50aXR5IGZyb20gJy4uLy4uLy4uLy4uLy4uL3R5cGVvcm0vZW50aXRpZXMvcGF0aWVudC5lbnRpdHknXG5pbXBvcnQgeyBFUGF0aWVudEVycm9yIH0gZnJvbSAnLi4vLi4vZXhjZXB0aW9uLWZpbHRlcnMvZXhjZXB0aW9uLmVudW0nXG5pbXBvcnQgeyBDcmVhdGVQYXRpZW50RHRvLCBVcGRhdGVQYXRpZW50RHRvIH0gZnJvbSAnLi9wYXRpZW50LmR0bydcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFBhdGllbnRTZXJ2aWNlIHtcblx0Y29uc3RydWN0b3IoQEluamVjdFJlcG9zaXRvcnkoUGF0aWVudEVudGl0eSkgcHJpdmF0ZSBwYXRpZW50UmVwb3NpdG9yeTogUmVwb3NpdG9yeTxQYXRpZW50RW50aXR5PikgeyB9XG5cblx0YXN5bmMgZmluZEFsbChjbGluaWNJZDogbnVtYmVyKTogUHJvbWlzZTxQYXRpZW50RW50aXR5W10+IHtcblx0XHRjb25zdCBwYXRpZW50TGlzdCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuZmluZCh7IHdoZXJlOiB7IGNsaW5pY0lkIH0gfSlcblx0XHRyZXR1cm4gcGF0aWVudExpc3Rcblx0fVxuXG5cdGFzeW5jIGNyZWF0ZShjbGluaWNJZDogbnVtYmVyLCBjcmVhdGVQYXRpZW50RHRvOiBDcmVhdGVQYXRpZW50RHRvKTogUHJvbWlzZTxQYXRpZW50RW50aXR5PiB7XG5cdFx0Y29uc3QgcGF0aWVudCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuc2F2ZSh7XG5cdFx0XHRjbGluaWNJZCxcblx0XHRcdC4uLmNyZWF0ZVBhdGllbnREdG8sXG5cdFx0fSlcblx0XHRyZXR1cm4gcGF0aWVudFxuXHR9XG5cblx0YXN5bmMgZmluZE9uZShjbGluaWNJZDogbnVtYmVyLCBpZDogbnVtYmVyKSB7XG5cdFx0Y29uc3QgcGF0aWVudCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuZmluZE9uZUJ5KHsgY2xpbmljSWQsIGlkIH0pXG5cdFx0cmV0dXJuIHBhdGllbnRcblx0fVxuXG5cdGFzeW5jIGZpbmRCeVBob25lKGNsaW5pY0lkOiBudW1iZXIsIHBob25lOiBzdHJpbmcpOiBQcm9taXNlPFBhdGllbnRFbnRpdHlbXT4ge1xuXHRcdGNvbnN0IHBhdGllbnRMaXN0ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kKHtcblx0XHRcdHdoZXJlOiB7XG5cdFx0XHRcdGNsaW5pY0lkOiBFcXVhbChjbGluaWNJZCksXG5cdFx0XHRcdHBob25lOiBMaWtlKGAke3Bob25lfSVgKSxcblx0XHRcdH0sXG5cdFx0XHRza2lwOiAwLFxuXHRcdFx0dGFrZTogMTAsXG5cdFx0fSlcblx0XHRyZXR1cm4gcGF0aWVudExpc3Rcblx0fVxuXHRhc3luYyBmaW5kQnlGdWxsTmFtZShjbGluaWNJZDogbnVtYmVyLCBmdWxsTmFtZTogc3RyaW5nKTogUHJvbWlzZTxQYXRpZW50RW50aXR5W10+IHtcblx0XHRjb25zdCBwYXRpZW50TGlzdCA9IGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkuZmluZCh7XG5cdFx0XHR3aGVyZToge1xuXHRcdFx0XHRjbGluaWNJZDogRXF1YWwoY2xpbmljSWQpLFxuXHRcdFx0XHRmdWxsTmFtZTogTGlrZShgJHtmdWxsTmFtZX0lYCksXG5cdFx0XHR9LFxuXHRcdFx0c2tpcDogMCxcblx0XHRcdHRha2U6IDEwLFxuXHRcdH0pXG5cdFx0cmV0dXJuIHBhdGllbnRMaXN0XG5cdH1cblxuXHRhc3luYyB1cGRhdGUoY2xpbmljSWQ6IG51bWJlciwgaWQ6IG51bWJlciwgdXBkYXRlUGF0aWVudER0bzogVXBkYXRlUGF0aWVudER0bykge1xuXHRcdGNvbnN0IGZpbmRQYXRpZW50ID0gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5maW5kT25lQnkoeyBjbGluaWNJZCwgaWQgfSlcblx0XHRpZiAoIWZpbmRQYXRpZW50KSB7XG5cdFx0XHR0aHJvdyBuZXcgSHR0cEV4Y2VwdGlvbihFUGF0aWVudEVycm9yLk5vdEV4aXN0cywgSHR0cFN0YXR1cy5CQURfUkVRVUVTVClcblx0XHR9XG5cdFx0cmV0dXJuIGF3YWl0IHRoaXMucGF0aWVudFJlcG9zaXRvcnkudXBkYXRlKHsgY2xpbmljSWQsIGlkIH0sIHVwZGF0ZVBhdGllbnREdG8pXG5cdH1cblxuXHRhc3luYyByZW1vdmUoY2xpbmljSWQ6IG51bWJlciwgaWQ6IG51bWJlcikge1xuXHRcdHJldHVybiBhd2FpdCB0aGlzLnBhdGllbnRSZXBvc2l0b3J5LnNvZnREZWxldGUoe1xuXHRcdFx0Y2xpbmljSWQsXG5cdFx0XHRpZCxcblx0XHR9KVxuXHR9XG5cblx0YXN5bmMgcmVzdG9yZShjbGluaWNJZDogbnVtYmVyLCBlbXBsb3llZUlkOiBudW1iZXIpIHtcblx0XHRyZXR1cm4gYXdhaXQgdGhpcy5wYXRpZW50UmVwb3NpdG9yeS5yZXN0b3JlKHtcblx0XHRcdGNsaW5pY0lkLFxuXHRcdFx0aWQ6IGVtcGxveWVlSWQsXG5cdFx0fSlcblx0fVxufVxuIiwiaW1wb3J0IHsgRXhjbHVkZSwgRXhwb3NlIH0gZnJvbSAnY2xhc3MtdHJhbnNmb3JtZXInXG5pbXBvcnQgeyBDcmVhdGVEYXRlQ29sdW1uLCBEZWxldGVEYXRlQ29sdW1uLCBQcmltYXJ5R2VuZXJhdGVkQ29sdW1uLCBVcGRhdGVEYXRlQ29sdW1uIH0gZnJvbSAndHlwZW9ybSdcblxuZXhwb3J0IGVudW0gRUdlbmRlciB7XG5cdE1hbGUgPSAnTWFsZScsXG5cdEZlbWFsZSA9ICdGZW1hbGUnLFxufVxuXG5leHBvcnQgdHlwZSBUR2VuZGVyID0ga2V5b2YgdHlwZW9mIEVHZW5kZXJcblxuZXhwb3J0IGNsYXNzIEJhc2VFbnRpdHkge1xuXHRAUHJpbWFyeUdlbmVyYXRlZENvbHVtbih7IG5hbWU6ICdpZCcgfSlcblx0QEV4cG9zZSgpXG5cdGlkOiBudW1iZXJcblxuXHRAQ3JlYXRlRGF0ZUNvbHVtbih7IG5hbWU6ICdjcmVhdGVkX2F0JyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ2NyZWF0ZWRfYXQnIH0pXG5cdGNyZWF0ZWRBdDogRGF0ZVxuXG5cdEBVcGRhdGVEYXRlQ29sdW1uKHsgbmFtZTogJ3VwZGF0ZWRfYXQnIH0pXG5cdHVwZGF0ZWRBdDogRGF0ZVxuXG5cdEBEZWxldGVEYXRlQ29sdW1uKHsgbmFtZTogJ2RlbGV0ZWRfYXQnIH0pXG5cdEBFeGNsdWRlKClcblx0ZGVsZXRlZEF0OiBEYXRlXG59XG4iLCJpbXBvcnQgeyBFeGNsdWRlLCBFeHBvc2UsIFR5cGUgfSBmcm9tICdjbGFzcy10cmFuc2Zvcm1lcidcbmltcG9ydCB7IENvbHVtbiwgRW50aXR5LCBKb2luQ29sdW1uLCBNYW55VG9PbmUgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuaW1wb3J0IFBhdGllbnRFbnRpdHkgZnJvbSAnLi9wYXRpZW50LmVudGl0eSdcblxuQEVudGl0eSgnYWRtaXNzaW9uJylcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIEFkbWlzc2lvbkVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QENvbHVtbih7IG5hbWU6ICdwYXRpZW50X2lkJyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ3BhdGllbnRfaWQnIH0pXG5cdHBhdGllbnRJZDogbnVtYmVyXG5cblx0QE1hbnlUb09uZSh0eXBlID0+IFBhdGllbnRFbnRpdHksIHsgY3JlYXRlRm9yZWlnbktleUNvbnN0cmFpbnRzOiBmYWxzZSB9KVxuXHRASm9pbkNvbHVtbih7IG5hbWU6ICdwYXRpZW50X2lkJywgcmVmZXJlbmNlZENvbHVtbk5hbWU6ICdpZCcgfSlcblx0QFR5cGUoKCkgPT4gUGF0aWVudEVudGl0eSlcblx0QEV4cG9zZSgpXG5cdHBhdGllbnQ6IFBhdGllbnRFbnRpdHlcblxuXHRAQ29sdW1uKHsgbmFtZTogJ3JlYXNvbicsIG51bGxhYmxlOiB0cnVlIH0pXG5cdEBFeHBvc2UoKVxuXHRyZWFzb246IHN0cmluZyAvLyBMw70gZG8gdsOgbyB2aeG7h25cblxuXHRAQ29sdW1uKHsgbmFtZTogJ21lZGljYWxfcmVjb3JkJywgdHlwZTogJ3RleHQnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ21lZGljYWxfcmVjb3JkJyB9KVxuXHRtZWRpY2FsUmVjb3JkOiBzdHJpbmcgLy8gVMOzbSB0xIN0IGLhu4duaCDDoW5cblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0QEV4cG9zZSgpXG5cdGRpYWdub3Npczogc3RyaW5nIC8vIENo4bqpbiDEkW/DoW5cblxuXHRAQ29sdW1uKHsgdHlwZTogJ3RpbnlpbnQnLCB1bnNpZ25lZDogdHJ1ZSwgbnVsbGFibGU6IHRydWUgfSkgICAgICAgICAgICAgICAvLyAtLS0tLSB0aW55aW50X3Vuc2lnbmVkOiAwIC0+IDI1NlxuXHRARXhwb3NlKClcblx0cHVsc2U6IG51bWJlclxuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZmxvYXQnLCBwcmVjaXNpb246IDMsIHNjYWxlOiAxLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRARXhwb3NlKClcblx0dGVtcGVyYXR1cmU6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnYmxvb2RfcHJlc3N1cmUnLCBsZW5ndGg6IDEwLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ2Jsb29kX3ByZXNzdXJlJyB9KVxuXHRibG9vZFByZXNzdXJlOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgbmFtZTogJ3Jlc3BpcmF0b3J5X3JhdGUnLCB0eXBlOiAndGlueWludCcsIG51bGxhYmxlOiB0cnVlIH0pICAgICAvLyAtLS0tLSB0aW55aW50OiAtMTI4IC0+IDEyN1xuXHRARXhwb3NlKHsgbmFtZTogJ3Jlc3BpcmF0b3J5X3JhdGUnIH0pXG5cdHJlc3BpcmF0b3J5UmF0ZTogbnVtYmVyXG5cblx0QENvbHVtbih7IHR5cGU6ICd0aW55aW50JywgbnVsbGFibGU6IHRydWUgfSlcblx0QEV4cG9zZSgpXG5cdHNwTzI6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBudWxsYWJsZTogdHJ1ZSB9KVxuXHRARXhwb3NlKClcblx0bm90ZTogc3RyaW5nIC8vIEdoaSBjaMO6XG59XG4iLCJpbXBvcnQgeyBDb2x1bW4sIEVudGl0eSwgSW5kZXggfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuXG5ARW50aXR5KCdjbGluaWMnKVxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgQ2xpbmljRW50aXR5IGV4dGVuZHMgQmFzZUVudGl0eSB7XG5cdEBDb2x1bW4oeyB1bmlxdWU6IHRydWUsIGxlbmd0aDogMTAsIG51bGxhYmxlOiBmYWxzZSB9KVxuXHRwaG9uZTogc3RyaW5nXG5cblx0QENvbHVtbih7IHVuaXF1ZTogdHJ1ZSwgbnVsbGFibGU6IGZhbHNlIH0pXG5cdGVtYWlsOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ3RpbnlpbnQnLCBkZWZhdWx0OiAxIH0pXG5cdGxldmVsOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0bmFtZTogc3RyaW5nXG5cblx0QENvbHVtbih7IG51bGxhYmxlOiB0cnVlIH0pXG5cdGFkZHJlc3M6IHN0cmluZ1xufVxuIiwiaW1wb3J0IHsgRXhjbHVkZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgQ29sdW1uLCBFbnRpdHksIEluZGV4LCBKb2luQ29sdW1uLCBNYW55VG9PbmUgfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSwgRUdlbmRlciB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuaW1wb3J0IENsaW5pY0VudGl0eSBmcm9tICcuL2NsaW5pYy5lbnRpdHknXG5cbmV4cG9ydCBlbnVtIEVSb2xlIHtcblx0T3duZXIgPSAnT3duZXInLFxuXHRBZG1pbiA9ICdBZG1pbicsXG5cdFVzZXIgPSAnVXNlcicsXG59XG5cbmV4cG9ydCB0eXBlIFRSb2xlID0ga2V5b2YgdHlwZW9mIEVSb2xlXG5cbkBFbnRpdHkoJ2VtcGxveWVlJylcbkBJbmRleChbJ2NsaW5pY0lkJywgJ3VzZXJuYW1lJ10sIHsgdW5pcXVlOiB0cnVlIH0pXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBFbXBsb3llZUVudGl0eSBleHRlbmRzIEJhc2VFbnRpdHkge1xuXHRAQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcgfSlcblx0QEV4Y2x1ZGUoKVxuXHRjbGluaWNJZDogbnVtYmVyXG5cblx0QE1hbnlUb09uZSh0eXBlID0+IENsaW5pY0VudGl0eSwgeyBjcmVhdGVGb3JlaWduS2V5Q29uc3RyYWludHM6IGZhbHNlIH0pXG5cdEBKb2luQ29sdW1uKHsgbmFtZTogJ2NsaW5pY19pZCcsIHJlZmVyZW5jZWRDb2x1bW5OYW1lOiAnaWQnIH0pXG5cdGNsaW5pYzogQ2xpbmljRW50aXR5XG5cblx0QENvbHVtbih7IGxlbmd0aDogMTAsIG51bGxhYmxlOiB0cnVlIH0pXG5cdHBob25lOiBzdHJpbmdcblxuXHRAQ29sdW1uKClcblx0dXNlcm5hbWU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oKVxuXHRARXhjbHVkZSgpXG5cdHBhc3N3b3JkOiBzdHJpbmdcblxuXHRAQ29sdW1uKHsgdHlwZTogJ2VudW0nLCBlbnVtOiBFUm9sZSwgZGVmYXVsdDogRVJvbGUuVXNlciB9KVxuXHRyb2xlOiBFUm9sZVxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnZnVsbF9uYW1lJywgbnVsbGFibGU6IHRydWUgfSlcblx0ZnVsbE5hbWU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZGF0ZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGJpcnRoZGF5OiBEYXRlXG5cblx0QENvbHVtbih7IHR5cGU6ICdlbnVtJywgZW51bTogRUdlbmRlciwgbnVsbGFibGU6IHRydWUgfSlcblx0Z2VuZGVyOiBFR2VuZGVyXG59XG4iLCJpbXBvcnQgeyBFbnRpdHksIENvbHVtbiwgSW5kZXggfSBmcm9tICd0eXBlb3JtJ1xuaW1wb3J0IHsgQmFzZUVudGl0eSB9IGZyb20gJy4uL2Jhc2UuZW50aXR5J1xuXG5ARW50aXR5KCdtZWRpY2luZScpXG5ASW5kZXgoWydjbGluaWNJZCcsICdpZCddLCB7IHVuaXF1ZTogdHJ1ZSB9KVxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgTWVkaWNpbmVFbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IG5hbWU6ICdjbGluaWNfaWQnIH0pXG5cdGNsaW5pY0lkOiBudW1iZXJcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2JyYW5kX25hbWUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRicmFuZE5hbWU6IHN0cmluZyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHTDqm4gYmnhu4d0IGTGsOG7o2NcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2NoZW1pY2FsX25hbWUnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRjaGVtaWNhbE5hbWU6IHN0cmluZyAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vIHTDqm4gZ+G7kWNcblxuXHRAQ29sdW1uKHsgbmFtZTogJ2NhbGN1bGF0aW9uX3VuaXQnLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRjYWxjdWxhdGlvblVuaXQ6IHN0cmluZyAgICAgICAgICAgICAgICAgICAgICAgIC8vIMSRxqFuIHbhu4sgdMOtbmg6IGzhu40sIOG7kW5nLCB24buJXG5cblx0QENvbHVtbih7IG5hbWU6ICdpbWFnZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdGltYWdlOiBzdHJpbmdcbn1cbiIsImltcG9ydCB7IEV4Y2x1ZGUsIEV4cG9zZSB9IGZyb20gJ2NsYXNzLXRyYW5zZm9ybWVyJ1xuaW1wb3J0IHsgQ29sdW1uLCBFbnRpdHksIEluZGV4IH0gZnJvbSAndHlwZW9ybSdcbmltcG9ydCB7IEJhc2VFbnRpdHksIEVHZW5kZXIgfSBmcm9tICcuLi9iYXNlLmVudGl0eSdcblxuQEVudGl0eSgncGF0aWVudCcpXG5ASW5kZXgoWydjbGluaWNJZCcsICdmdWxsTmFtZSddKVxuQEluZGV4KFsnY2xpbmljSWQnLCAncGhvbmUnXSlcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIFBhdGllbnRFbnRpdHkgZXh0ZW5kcyBCYXNlRW50aXR5IHtcblx0QENvbHVtbih7IG5hbWU6ICdjbGluaWNfaWQnIH0pXG5cdEBFeGNsdWRlKClcblx0Y2xpbmljSWQ6IG51bWJlclxuXG5cdEBDb2x1bW4oeyBuYW1lOiAnZnVsbF9uYW1lJyB9KVxuXHRARXhwb3NlKHsgbmFtZTogJ2Z1bGxfbmFtZScgfSlcblx0ZnVsbE5hbWU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBsZW5ndGg6IDEwLCBudWxsYWJsZTogdHJ1ZSB9KVxuXHRARXhwb3NlKClcblx0cGhvbmU6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZGF0ZScsIG51bGxhYmxlOiB0cnVlIH0pXG5cdEBFeHBvc2UoKVxuXHRiaXJ0aGRheTogRGF0ZVxuXG5cdEBDb2x1bW4oeyB0eXBlOiAnZW51bScsIGVudW06IEVHZW5kZXIsIG51bGxhYmxlOiB0cnVlIH0pXG5cdEBFeHBvc2UoKVxuXHRnZW5kZXI6IEVHZW5kZXJcblxuXHRAQ29sdW1uKHsgbnVsbGFibGU6IHRydWUgfSlcblx0QEV4cG9zZSgpXG5cdGFkZHJlc3M6IHN0cmluZ1xuXG5cdEBDb2x1bW4oeyBuYW1lOiAnaGVhbHRoX2hpc3RvcnknLCB0eXBlOiAndGV4dCcsIG51bGxhYmxlOiB0cnVlIH0pXG5cdEBFeHBvc2UoeyBuYW1lOiAnaGVhbHRoX2hpc3RvcnknIH0pXG5cdGhlYWx0aEhpc3Rvcnk6IHN0cmluZyAvLyBUaeG7gW4gc+G7rSBi4buHbmhcbn1cbiIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvYXhpb3NcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb25cIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb24vZW51bXNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9jb21tb24vZXhjZXB0aW9uc1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvbmZpZ1wiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJAbmVzdGpzL2NvcmVcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9qd3RcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy9zd2FnZ2VyXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcIkBuZXN0anMvdGVybWludXNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiQG5lc3Rqcy90eXBlb3JtXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImJjcnlwdFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJjbGFzcy10cmFuc2Zvcm1lclwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJjbGFzcy12YWxpZGF0b3JcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwiZXhwcmVzcy1yYXRlLWxpbWl0XCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcImhlbG1ldFwiKTsiLCJtb2R1bGUuZXhwb3J0cyA9IHJlcXVpcmUoXCJyZXF1ZXN0LWlwXCIpOyIsIm1vZHVsZS5leHBvcnRzID0gcmVxdWlyZShcInJ4anNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwicnhqcy9vcGVyYXRvcnNcIik7IiwibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKFwidHlwZW9ybVwiKTsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiaW1wb3J0IHsgVmFsaWRhdGlvbkVycm9yLCBWYWxpZGF0aW9uUGlwZSB9IGZyb20gJ0BuZXN0anMvY29tbW9uJ1xuaW1wb3J0IHsgQ29uZmlnU2VydmljZSB9IGZyb20gJ0BuZXN0anMvY29uZmlnJ1xuaW1wb3J0IHsgTmVzdEZhY3RvcnksIFJlZmxlY3RvciB9IGZyb20gJ0BuZXN0anMvY29yZSdcbmltcG9ydCByYXRlTGltaXQgZnJvbSAnZXhwcmVzcy1yYXRlLWxpbWl0J1xuaW1wb3J0IGhlbG1ldCBmcm9tICdoZWxtZXQnXG5pbXBvcnQgKiBhcyByZXF1ZXN0SXAgZnJvbSAncmVxdWVzdC1pcCdcbmltcG9ydCB7IEFwcE1vZHVsZSB9IGZyb20gJy4vYXBwLm1vZHVsZSdcbmltcG9ydCB7IHNldHVwU3dhZ2dlciB9IGZyb20gJy4vY29tbW9uL3N3YWdnZXInXG5pbXBvcnQgeyBIdHRwRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy9odHRwLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBVbmtub3duRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy91bmtub3duLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBWYWxpZGF0aW9uRXhjZXB0aW9uLCBWYWxpZGF0aW9uRXhjZXB0aW9uRmlsdGVyIH0gZnJvbSAnLi9leGNlcHRpb24tZmlsdGVycy92YWxpZGF0aW9uLWV4Y2VwdGlvbi5maWx0ZXInXG5pbXBvcnQgeyBSb2xlc0d1YXJkIH0gZnJvbSAnLi9ndWFyZHMvcm9sZXMuZ3VhcmQnXG5pbXBvcnQgeyBBY2Nlc3NMb2dJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvYWNjZXNzLWxvZy5pbnRlcmNlcHRvcidcbmltcG9ydCB7IFRpbWVvdXRJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3IvdGltZW91dC5pbnRlcmNlcHRvcidcblxuYXN5bmMgZnVuY3Rpb24gYm9vdHN0cmFwKCkge1xuXHRjb25zdCBhcHAgPSBhd2FpdCBOZXN0RmFjdG9yeS5jcmVhdGUoQXBwTW9kdWxlKVxuXG5cdGNvbnN0IGNvbmZpZ1NlcnZpY2UgPSBhcHAuZ2V0KENvbmZpZ1NlcnZpY2UpXG5cdGNvbnN0IFBPUlQgPSBjb25maWdTZXJ2aWNlLmdldCgnTkVTVEpTX1BPUlQnKVxuXHRjb25zdCBIT1NUID0gY29uZmlnU2VydmljZS5nZXQoJ05FU1RKU19IT1NUJykgfHwgJ2xvY2FsaG9zdCdcblxuXHRhcHAudXNlKGhlbG1ldCgpKVxuXHRhcHAudXNlKHJhdGVMaW1pdCh7XG5cdFx0d2luZG93TXM6IDYwICogMTAwMCwgLy8gMSBtaW51dGVzXG5cdFx0bWF4OiAxMDAsIC8vIGxpbWl0IGVhY2ggSVAgdG8gMTAwIHJlcXVlc3RzIHBlciB3aW5kb3dNc1xuXHR9KSlcblx0YXBwLmVuYWJsZUNvcnMoKVxuXG5cdGFwcC51c2UocmVxdWVzdElwLm13KCkpXG5cblx0YXBwLnVzZUdsb2JhbEludGVyY2VwdG9ycyhcblx0XHRuZXcgQWNjZXNzTG9nSW50ZXJjZXB0b3IoKSxcblx0XHRuZXcgVGltZW91dEludGVyY2VwdG9yKClcblx0KVxuXHRhcHAudXNlR2xvYmFsRmlsdGVycyhcblx0XHRuZXcgVW5rbm93bkV4Y2VwdGlvbkZpbHRlcigpLFxuXHRcdG5ldyBIdHRwRXhjZXB0aW9uRmlsdGVyKCksXG5cdFx0bmV3IFZhbGlkYXRpb25FeGNlcHRpb25GaWx0ZXIoKVxuXHQpXG5cdFxuXHRhcHAudXNlR2xvYmFsR3VhcmRzKG5ldyBSb2xlc0d1YXJkKGFwcC5nZXQoUmVmbGVjdG9yKSkpXG5cblx0YXBwLnVzZUdsb2JhbFBpcGVzKG5ldyBWYWxpZGF0aW9uUGlwZSh7XG5cdFx0dmFsaWRhdGlvbkVycm9yOiB7IHRhcmdldDogZmFsc2UsIHZhbHVlOiB0cnVlIH0sXG5cdFx0c2tpcE1pc3NpbmdQcm9wZXJ0aWVzOiB0cnVlLCAvLyBraMO0bmcgdmFsaWRhdGUgbmjhu69uZyBwcm9wZXJ0eSB1bmRlZmluZWRcblx0XHR3aGl0ZWxpc3Q6IHRydWUsIC8vIGxv4bqhaSBi4buPIGPDoWMgcHJvcGVydHkga2jDtG5nIGPDsyB0cm9uZyBEVE9cblx0XHRmb3JiaWROb25XaGl0ZWxpc3RlZDogdHJ1ZSwgLy8geHXhuqV0IGhp4buHbiBwcm9wZXJ0eSBraMO0bmcgY8OzIHRyb25nIERUTyBz4bq9IGLhuq90IGzhu5dpXG5cdFx0dHJhbnNmb3JtOiB0cnVlLCAvLyB1c2UgZm9yIERUT1xuXHRcdHRyYW5zZm9ybU9wdGlvbnM6IHtcblx0XHRcdGV4Y2x1ZGVFeHRyYW5lb3VzVmFsdWVzOiBmYWxzZSwgLy8gZXhjbHVkZSBmaWVsZCBub3QgaW4gY2xhc3MgRFRPID0+IG5vXG5cdFx0XHRleHBvc2VVbnNldEZpZWxkczogZmFsc2UsIC8vIGV4cG9zZSBmaWVsZCB1bmRlZmluZWQgaW4gRFRPID0+IG5vXG5cdFx0fSxcblx0XHRleGNlcHRpb25GYWN0b3J5OiAoZXJyb3JzOiBWYWxpZGF0aW9uRXJyb3JbXSA9IFtdKSA9PiBuZXcgVmFsaWRhdGlvbkV4Y2VwdGlvbihlcnJvcnMpLFxuXHR9KSlcblxuXHRpZiAoY29uZmlnU2VydmljZS5nZXQoJ05PREVfRU5WJykgIT09ICdwcm9kdWN0aW9uJykge1xuXHRcdHNldHVwU3dhZ2dlcihhcHApXG5cdH1cblxuXHRhd2FpdCBhcHAubGlzdGVuKFBPUlQsICgpID0+IHtcblx0XHRjb25zb2xlLmxvZyhg8J+agCBTZXJ2ZXIgZG9jdW1lbnQ6IGh0dHA6Ly8ke0hPU1R9OiR7UE9SVH0vZG9jdW1lbnRgKVxuXHR9KVxufVxuYm9vdHN0cmFwKClcbiJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==