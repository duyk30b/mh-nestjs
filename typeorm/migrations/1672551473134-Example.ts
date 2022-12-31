import { MigrationInterface, QueryRunner } from "typeorm";

export class Example1672551473134 implements MigrationInterface {
    name = 'Example1672551473134'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            CREATE TABLE \`clinic\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`phone\` varchar(10) NOT NULL,
                \`email\` varchar(255) NOT NULL,
                \`level\` tinyint NOT NULL DEFAULT '1',
                \`name\` varchar(255) NULL,
                \`address\` varchar(255) NULL,
                UNIQUE INDEX \`IDX_b3df084998059e1f2f31bfd1e8\` (\`phone\`),
                UNIQUE INDEX \`IDX_050033b437380ba808c041fe73\` (\`email\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`employee\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`clinic_id\` int NOT NULL,
                \`phone\` varchar(10) NULL,
                \`username\` varchar(255) NOT NULL,
                \`password\` varchar(255) NOT NULL,
                \`role\` enum ('Owner', 'Admin', 'User') NOT NULL DEFAULT 'User',
                \`full_name\` varchar(255) NULL,
                \`birthday\` datetime NULL,
                \`gender\` enum ('Male', 'Female') NULL,
                UNIQUE INDEX \`IDX_4cd0d85e4f48047027fa2df859\` (\`clinic_id\`, \`username\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_delivery\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
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
            CREATE TABLE \`medicine_receipt_note\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`clinic_id\` int NOT NULL,
                \`provider_id\` int NOT NULL,
                \`user_id\` int NOT NULL,
                \`buyer_pays_ship\` int NOT NULL,
                \`seller_pays_ship\` int NOT NULL,
                \`discount\` int NOT NULL,
                \`debt\` int NOT NULL,
                \`total_money\` int NOT NULL,
                INDEX \`IDX_cb226e71abe1074969ded4a6b4\` (\`clinic_id\`, \`provider_id\`),
                INDEX \`IDX_d0056581598a39f1e72b3cf502\` (\`clinic_id\`, \`user_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_receipt\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
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
            CREATE TABLE \`medicine_available\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
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
            CREATE TABLE \`medicine\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
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
            CREATE TABLE \`customer\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`clinic_id\` int NOT NULL,
                \`name\` varchar(255) NOT NULL,
                \`phone\` varchar(255) NOT NULL,
                \`address\` varchar(255) NOT NULL,
                INDEX \`IDX_05709b4e05aa8395f1116961de\` (\`clinic_id\`, \`name\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`patient\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`clinic_id\` int NOT NULL,
                \`full_name\` varchar(255) NOT NULL,
                \`phone\` varchar(10) NULL,
                \`birthday\` datetime NULL,
                \`gender\` enum ('Male', 'Female') NULL,
                \`address\` varchar(255) NULL,
                INDEX \`IDX_650a7eb23f7775614dfaad7102\` (\`clinic_id\`, \`phone\`),
                INDEX \`IDX_291d909c28ed3ed41abed390e8\` (\`clinic_id\`, \`full_name\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`provider\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`clinic_id\` int NOT NULL,
                \`provider_name\` varchar(255) NOT NULL,
                \`phone\` varchar(255) NOT NULL,
                \`address\` varchar(255) NOT NULL,
                UNIQUE INDEX \`IDX_ccb4d0155cb6fdd114ff1e9342\` (\`clinic_id\`, \`id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            ALTER TABLE \`employee\`
            ADD CONSTRAINT \`FK_e7db3d1367ea79e7ad88f22d42d\` FOREIGN KEY (\`clinic_id\`) REFERENCES \`clinic\`(\`id\`) ON DELETE NO ACTION ON UPDATE NO ACTION
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            ALTER TABLE \`employee\` DROP FOREIGN KEY \`FK_e7db3d1367ea79e7ad88f22d42d\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_ccb4d0155cb6fdd114ff1e9342\` ON \`provider\`
        `);
        await queryRunner.query(`
            DROP TABLE \`provider\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_291d909c28ed3ed41abed390e8\` ON \`patient\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_650a7eb23f7775614dfaad7102\` ON \`patient\`
        `);
        await queryRunner.query(`
            DROP TABLE \`patient\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_05709b4e05aa8395f1116961de\` ON \`customer\`
        `);
        await queryRunner.query(`
            DROP TABLE \`customer\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_4c4d408de2803dbd81b39bbb3c\` ON \`medicine\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_0209a64334b5e0264836ad3f4b\` ON \`medicine_available\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_available\`
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
            DROP INDEX \`IDX_d0056581598a39f1e72b3cf502\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_cb226e71abe1074969ded4a6b4\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_receipt_note\`
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
            DROP INDEX \`IDX_4cd0d85e4f48047027fa2df859\` ON \`employee\`
        `);
        await queryRunner.query(`
            DROP TABLE \`employee\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_050033b437380ba808c041fe73\` ON \`clinic\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_b3df084998059e1f2f31bfd1e8\` ON \`clinic\`
        `);
        await queryRunner.query(`
            DROP TABLE \`clinic\`
        `);
    }

}
