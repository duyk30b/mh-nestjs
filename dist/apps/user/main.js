/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */,
/* 1 */
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
__exportStar(__webpack_require__(2), exports);
__exportStar(__webpack_require__(3), exports);
__exportStar(__webpack_require__(4), exports);
__exportStar(__webpack_require__(6), exports);
__exportStar(__webpack_require__(7), exports);


/***/ }),
/* 2 */
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
/* 3 */
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
/* 4 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HttpExceptionFilter = void 0;
const common_1 = __webpack_require__(5);
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
/* 5 */
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),
/* 6 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UnknowExceptionFilter = void 0;
const common_1 = __webpack_require__(5);
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
/* 7 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ValidationExceptionFilter = exports.ValidationException = void 0;
const common_1 = __webpack_require__(5);
const exception_enum_1 = __webpack_require__(3);
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
/* 8 */
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),
/* 9 */
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),
/* 10 */
/***/ ((module) => {

module.exports = require("express-rate-limit");

/***/ }),
/* 11 */
/***/ ((module) => {

module.exports = require("helmet");

/***/ }),
/* 12 */
/***/ ((module) => {

module.exports = require("request-ip");

/***/ }),
/* 13 */
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
const common_1 = __webpack_require__(5);
const config_1 = __webpack_require__(8);
const typeorm_1 = __webpack_require__(14);
const typeorm_2 = __webpack_require__(15);
const enviroments_1 = __webpack_require__(16);
const logger_middleware_1 = __webpack_require__(17);
const validate_access_token_middleware_1 = __webpack_require__(18);
const auth_module_1 = __webpack_require__(21);
const clinic_module_1 = __webpack_require__(34);
const employee_module_1 = __webpack_require__(38);
const medicine_module_1 = __webpack_require__(44);
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
                imports: [config_1.ConfigModule.forFeature(enviroments_1.MysqlConfig)],
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
/* 14 */
/***/ ((module) => {

module.exports = require("@nestjs/typeorm");

/***/ }),
/* 15 */
/***/ ((module) => {

module.exports = require("typeorm");

/***/ }),
/* 16 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MysqlConfig = exports.JwtConfig = void 0;
const config_1 = __webpack_require__(8);
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
/* 17 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoggerMiddleware = void 0;
const common_1 = __webpack_require__(5);
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
/* 18 */
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
const common_1 = __webpack_require__(5);
const jwt_extend_service_1 = __webpack_require__(19);
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
/* 19 */
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
const utils_1 = __webpack_require__(1);
const common_1 = __webpack_require__(5);
const config_1 = __webpack_require__(8);
const jwt_1 = __webpack_require__(20);
const enviroments_1 = __webpack_require__(16);
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
/* 20 */
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),
/* 21 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(5);
const config_1 = __webpack_require__(8);
const jwt_1 = __webpack_require__(20);
const typeorm_1 = __webpack_require__(14);
const clinic_entity_1 = __webpack_require__(22);
const employee_entity_1 = __webpack_require__(24);
const enviroments_1 = __webpack_require__(16);
const auth_controller_1 = __webpack_require__(26);
const auth_service_1 = __webpack_require__(32);
const jwt_extend_service_1 = __webpack_require__(19);
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([clinic_entity_1.default, employee_entity_1.default]),
            config_1.ConfigModule.forFeature(enviroments_1.JwtConfig),
            jwt_1.JwtModule,
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, jwt_extend_service_1.JwtExtendService],
        exports: [jwt_extend_service_1.JwtExtendService],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),
/* 22 */
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
const typeorm_1 = __webpack_require__(15);
const base_entity_1 = __webpack_require__(23);
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
/* 23 */
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
const typeorm_1 = __webpack_require__(15);
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
/* 24 */
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
const typeorm_1 = __webpack_require__(15);
const constants_1 = __webpack_require__(25);
const base_entity_1 = __webpack_require__(23);
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
/* 25 */
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
/* 26 */
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
const common_1 = __webpack_require__(5);
const swagger_1 = __webpack_require__(27);
const express_1 = __webpack_require__(28);
const request_ip_1 = __webpack_require__(12);
const auth_dto_1 = __webpack_require__(29);
const auth_service_1 = __webpack_require__(32);
const jwt_extend_service_1 = __webpack_require__(19);
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
/* 27 */
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),
/* 28 */
/***/ ((module) => {

module.exports = require("express");

/***/ }),
/* 29 */
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
const swagger_1 = __webpack_require__(27);
const class_validator_1 = __webpack_require__(30);
const class_validator_custom_1 = __webpack_require__(31);
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
/* 30 */
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),
/* 31 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IsGmail = exports.IsPhone = void 0;
const class_validator_1 = __webpack_require__(30);
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
/* 32 */
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
const utils_1 = __webpack_require__(1);
const common_1 = __webpack_require__(5);
const bcrypt = __webpack_require__(33);
const typeorm_1 = __webpack_require__(15);
const clinic_entity_1 = __webpack_require__(22);
const employee_entity_1 = __webpack_require__(24);
const constants_1 = __webpack_require__(25);
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
/* 33 */
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),
/* 34 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ClinicModule = void 0;
const common_1 = __webpack_require__(5);
const typeorm_1 = __webpack_require__(14);
const clinic_entity_1 = __webpack_require__(22);
const clinic_controller_1 = __webpack_require__(35);
const clinic_service_1 = __webpack_require__(36);
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
/* 35 */
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
const common_1 = __webpack_require__(5);
const clinic_service_1 = __webpack_require__(36);
const clinic_dto_1 = __webpack_require__(37);
const swagger_1 = __webpack_require__(27);
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
/* 36 */
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
const common_1 = __webpack_require__(5);
const typeorm_1 = __webpack_require__(14);
const typeorm_2 = __webpack_require__(15);
const clinic_entity_1 = __webpack_require__(22);
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
/* 37 */
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
const swagger_1 = __webpack_require__(27);
const class_validator_1 = __webpack_require__(30);
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
/* 38 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmployeeModule = void 0;
const common_1 = __webpack_require__(5);
const employee_service_1 = __webpack_require__(39);
const employee_controller_1 = __webpack_require__(40);
const typeorm_1 = __webpack_require__(14);
const employee_entity_1 = __webpack_require__(24);
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
/* 39 */
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
const common_1 = __webpack_require__(5);
const bcrypt = __webpack_require__(33);
const typeorm_1 = __webpack_require__(15);
const employee_entity_1 = __webpack_require__(24);
const utils_1 = __webpack_require__(1);
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
/* 40 */
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
const common_1 = __webpack_require__(5);
const swagger_1 = __webpack_require__(27);
const constants_1 = __webpack_require__(25);
const user_roles_guard_1 = __webpack_require__(41);
const create_employee_dto_1 = __webpack_require__(42);
const update_employee_dto_1 = __webpack_require__(43);
const employee_service_1 = __webpack_require__(39);
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
/* 41 */
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
const common_1 = __webpack_require__(5);
const core_1 = __webpack_require__(9);
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
/* 42 */
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
const swagger_1 = __webpack_require__(27);
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
/* 43 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateEmployeeDto = void 0;
const swagger_1 = __webpack_require__(27);
const create_employee_dto_1 = __webpack_require__(42);
class UpdateEmployeeDto extends (0, swagger_1.PartialType)(create_employee_dto_1.CreateEmployeeDto) {
}
exports.UpdateEmployeeDto = UpdateEmployeeDto;


/***/ }),
/* 44 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MedicineModule = void 0;
const common_1 = __webpack_require__(5);
const typeorm_1 = __webpack_require__(14);
const medicine_entity_1 = __webpack_require__(45);
const medicine_controller_1 = __webpack_require__(46);
const medicine_service_1 = __webpack_require__(49);
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
/* 45 */
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
const typeorm_1 = __webpack_require__(15);
const base_entity_1 = __webpack_require__(23);
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
/* 46 */
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
const common_1 = __webpack_require__(5);
const swagger_1 = __webpack_require__(27);
const create_medicine_dto_1 = __webpack_require__(47);
const update_medicine_dto_1 = __webpack_require__(48);
const medicine_service_1 = __webpack_require__(49);
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
/* 47 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CreateMedicineDto = void 0;
class CreateMedicineDto {
}
exports.CreateMedicineDto = CreateMedicineDto;


/***/ }),
/* 48 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateMedicineDto = void 0;
const swagger_1 = __webpack_require__(27);
const create_medicine_dto_1 = __webpack_require__(47);
class UpdateMedicineDto extends (0, swagger_1.PartialType)(create_medicine_dto_1.CreateMedicineDto) {
}
exports.UpdateMedicineDto = UpdateMedicineDto;


/***/ }),
/* 49 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MedicineService = void 0;
const common_1 = __webpack_require__(5);
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
/* 50 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.setupSwagger = void 0;
const swagger_1 = __webpack_require__(27);
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
/* 51 */
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
const common_1 = __webpack_require__(5);
const request_ip_1 = __webpack_require__(12);
const operators_1 = __webpack_require__(52);
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
/* 52 */
/***/ ((module) => {

module.exports = require("rxjs/operators");

/***/ }),
/* 53 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TimeoutInterceptor = void 0;
const common_1 = __webpack_require__(5);
const rxjs_1 = __webpack_require__(54);
const operators_1 = __webpack_require__(52);
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
/* 54 */
/***/ ((module) => {

module.exports = require("rxjs");

/***/ })
/******/ 	]);
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

Object.defineProperty(exports, "__esModule", ({ value: true }));
const utils_1 = __webpack_require__(1);
const common_1 = __webpack_require__(5);
const config_1 = __webpack_require__(8);
const core_1 = __webpack_require__(9);
const express_rate_limit_1 = __webpack_require__(10);
const helmet_1 = __webpack_require__(11);
const requestIp = __webpack_require__(12);
const app_module_1 = __webpack_require__(13);
const swagger_1 = __webpack_require__(50);
const user_roles_guard_1 = __webpack_require__(41);
const access_log_interceptor_1 = __webpack_require__(51);
const timeout_interceptor_1 = __webpack_require__(53);
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    const configService = app.get(config_1.ConfigService);
    const PORT = configService.get('SERVER_PORT');
    const HOST = configService.get('SERVER_HOST') || 'localhost';
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
    await app.listen(PORT, () => {
        console.log(`🚀 Server run: http://${HOST}:${PORT}/document`);
    });
}
bootstrap();

})();

/******/ })()
;