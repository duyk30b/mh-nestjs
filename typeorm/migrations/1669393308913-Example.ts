import { MigrationInterface, QueryRunner } from "typeorm";

export class Example1669393308913 implements MigrationInterface {
    name = 'Example1669393308913'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            CREATE TABLE \`clinic\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`level\` tinyint NOT NULL DEFAULT '1',
                \`code\` varchar(255) NULL,
                \`clinicName\` varchar(255) NULL,
                \`address\` varchar(255) NULL,
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_delivery_note\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`customer_id\` int NOT NULL,
                \`employee_id\` int NOT NULL,
                INDEX \`IDX_5ede18bfdfd0ed17f4e175a9b4\` (\`clinic_id\`, \`customer_id\`),
                INDEX \`IDX_b1c1bc16f303f3fa200e35a5c0\` (\`clinic_id\`, \`employee_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_available\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`medicine_id\` int NOT NULL,
                \`quantity\` int NOT NULL DEFAULT '0',
                \`expiry_date\` datetime NOT NULL,
                \`cost_price\` int NOT NULL,
                \`retail_price\` int NOT NULL,
                \`wholesale_price\` int NOT NULL,
                INDEX \`IDX_0209a64334b5e0264836ad3f4b\` (\`clinic_id\`, \`medicine_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_delivery\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`medicine_id\` int NOT NULL,
                \`delivery_note_id\` int NOT NULL,
                \`quantity\` int NOT NULL DEFAULT '0',
                \`expiry_date\` datetime NOT NULL,
                \`cost_price\` int NOT NULL,
                \`expected_price\` int NOT NULL,
                \`actual_price\` int NOT NULL,
                \`discount\` int NOT NULL,
                INDEX \`IDX_3682d1087ab7af8f15fcf82490\` (\`clinic_id\`, \`delivery_note_id\`),
                INDEX \`IDX_244a0b2f5fbe8e4b3d6e14ea1b\` (\`clinic_id\`, \`medicine_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`employee\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`email\` varchar(255) NULL,
                \`phone\` varchar(255) NULL,
                \`username\` varchar(255) NOT NULL,
                \`password\` varchar(255) NOT NULL,
                \`address\` varchar(255) NULL,
                \`role\` enum ('Owner', 'Admin', 'User') NOT NULL DEFAULT 'User',
                INDEX \`IDX_4cd0d85e4f48047027fa2df859\` (\`clinic_id\`, \`username\`),
                INDEX \`IDX_95d9d7d744bb925d7da8ce3c26\` (\`clinic_id\`, \`email\`),
                UNIQUE INDEX \`IDX_817d1d427138772d47eca04885\` (\`email\`),
                UNIQUE INDEX \`IDX_81afb288b526f7e8fed0e4200c\` (\`phone\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_receipt_note\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`provider_id\` int NOT NULL,
                \`employee_id\` int NOT NULL,
                \`buyer_pays_ship\` int NOT NULL,
                \`seller_pays_ship\` int NOT NULL,
                \`discount\` int NOT NULL,
                \`debt\` int NOT NULL,
                \`total_money\` int NOT NULL,
                INDEX \`IDX_cb226e71abe1074969ded4a6b4\` (\`clinic_id\`, \`provider_id\`),
                INDEX \`IDX_964c3888b652abffc09ca97772\` (\`clinic_id\`, \`employee_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_receipt\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`medicine_id\` int NOT NULL,
                \`receipt_note_id\` int NOT NULL,
                \`quantity\` int NOT NULL DEFAULT '0',
                \`expiry_date\` datetime NOT NULL,
                \`cost_price\` int NOT NULL,
                INDEX \`IDX_3eb2f0a6f379037ad2fdeccfe0\` (\`clinic_id\`, \`receipt_note_id\`),
                INDEX \`IDX_598a8e7af31ca9e2f8a8c16f88\` (\`clinic_id\`, \`medicine_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`customer\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`name\` varchar(255) NOT NULL,
                \`phone\` varchar(255) NOT NULL,
                \`address\` varchar(255) NOT NULL,
                INDEX \`IDX_05709b4e05aa8395f1116961de\` (\`clinic_id\`, \`name\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`clinic_id\` int NOT NULL,
                \`brand_name\` varchar(255) NULL,
                \`chemical_name\` varchar(255) NULL,
                \`calculation_unit\` varchar(255) NULL,
                \`image\` varchar(255) NULL,
                UNIQUE INDEX \`IDX_4c4d408de2803dbd81b39bbb3c\` (\`clinic_id\`, \`id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`provider\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_by\` int NULL,
                \`updated_by\` int NULL,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`version\` int NOT NULL,
                \`organize_id\` int NOT NULL,
                \`provider_name\` varchar(255) NOT NULL,
                \`phone\` varchar(255) NOT NULL,
                \`address\` varchar(255) NOT NULL,
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            DROP TABLE \`provider\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_4c4d408de2803dbd81b39bbb3c\` ON \`medicine\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_05709b4e05aa8395f1116961de\` ON \`customer\`
        `);
        await queryRunner.query(`
            DROP TABLE \`customer\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_598a8e7af31ca9e2f8a8c16f88\` ON \`medicine_receipt\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_3eb2f0a6f379037ad2fdeccfe0\` ON \`medicine_receipt\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_receipt\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_964c3888b652abffc09ca97772\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_cb226e71abe1074969ded4a6b4\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_81afb288b526f7e8fed0e4200c\` ON \`employee\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_817d1d427138772d47eca04885\` ON \`employee\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_95d9d7d744bb925d7da8ce3c26\` ON \`employee\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_4cd0d85e4f48047027fa2df859\` ON \`employee\`
        `);
        await queryRunner.query(`
            DROP TABLE \`employee\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_244a0b2f5fbe8e4b3d6e14ea1b\` ON \`medicine_delivery\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_3682d1087ab7af8f15fcf82490\` ON \`medicine_delivery\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_delivery\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_0209a64334b5e0264836ad3f4b\` ON \`medicine_available\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_available\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_b1c1bc16f303f3fa200e35a5c0\` ON \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_5ede18bfdfd0ed17f4e175a9b4\` ON \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            DROP TABLE \`clinic\`
        `);
    }

}
