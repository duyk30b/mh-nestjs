module.exports = {
	parser: '@typescript-eslint/parser',
	parserOptions: {
		project: 'tsconfig.json',
		tsconfigRootDir: __dirname,
		sourceType: 'module',
	},
	plugins: ['@typescript-eslint/eslint-plugin'],
	extends: ['plugin:@typescript-eslint/recommended'],
	root: true,
	env: {
		node: true,
		jest: true,
	},
	ignorePatterns: ['dist/*'],
	rules: {
		'@typescript-eslint/interface-name-prefix': 'off',
		'@typescript-eslint/explicit-function-return-type': 'off',
		'@typescript-eslint/explicit-module-boundary-types': 'off',
		'@typescript-eslint/no-explicit-any': 'off',
		'no-console': 0,
		'no-tabs': 0,                                            // không cho sử dụng tab
		'no-param-reassign': 0,                                  // sửa params của function sẽ lỗi
		'no-unused-vars': 0,                                     // khai báo biến mà không sử dụng
		'no-multiple-empty-lines': [1, { max: 1, maxEOF: 1 }],   // Số dòng trống tối đa
		'max-len': [1, { code: 120 }],
		'indent': [1, 'tab'],                                    // thụt lề bằng tab
		'semi': [1, 'never'],                                    // dấu ; cuối dòng
		'quotes': [1, 'single', { allowTemplateLiterals: true }],
		'quote-props': [1, 'consistent-as-needed'],              // dấu quote ở key của object -> dùng 1 cách nhất quán
		'arrow-parens': 0,                                       // bắt buộc (a)=>{} thay vì a=>{}
		'@typescript-eslint/no-unused-vars': 0,
		'no-underscore-dangle': 1,                               // dùng dấu gạch dưới _
		'comma-dangle': [1, 'always-multiline'],                 // dấu , tại phần tử cuối cùng trong mảng, object
		'comma-spacing': [1, { before: false, after: true }],    // space trước và sau dấu ,
		'key-spacing': [1, { mode: 'strict' }],                  // space trước và sau dấu : trong object
		'block-spacing': [1, 'always'],                          // space sau {, eg: {return} => { return }
		'computed-property-spacing': [1, 'never'],               // space trong property, eg: abc[ 'x'] => abc['x']
		'spaced-comment': [1, 'always'],                         // space khi comment, eg: //abc => // abc
		'object-curly-spacing': [1, 'always'],                   // space trong object, eg: {a:2} => { a:2 }
		'object-curly-newline': [1, { multiline: true }],        // quy tắc xuống dòng
		'object-property-newline': [1, { allowAllPropertiesOnSameLine: true }],
		'array-bracket-spacing': [1, 'never'],                   // space trong array, eg: [ 1,2, 3 ] => [1,2, 3] 
		'array-bracket-newline': [1, { multiline: true }],       // quy tắc xuống dòng với dấu [ và ] trong mảng
		'array-element-newline': [1, 'consistent'],              // quy tắc xuống dòng với các item trong mảng
		'operator-linebreak': [1, 'before'],                     // dấu ||, ?, +, = ở đầu dòng
		'import/prefer-default-export': 0,                       // nếu export 1 biến thì mặc định phải là default
		'implicit-arrow-linebreak': 0,                           // Bắt phải xuống dòng a.b.c.d
		'function-paren-newline': 0,                             // run() => dấu ) nếu bị xuống dòng sẽ lỗi
		'prefer-template': 0,                                    // Bắt buộc dùng template string khi cộng chuỗi, vcc
	},
}
