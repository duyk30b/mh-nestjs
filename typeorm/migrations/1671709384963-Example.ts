import { MigrationInterface, QueryRunner } from "typeorm";

export class Example1671709384963 implements MigrationInterface {
    name = 'Example1671709384963'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            CREATE TABLE \`medicine_available\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`medicine_id\` int NOT NULL,
                \`quantity\` int NOT NULL DEFAULT '0',
                \`expiry_date\` datetime NOT NULL,
                \`cost_price\` int NOT NULL,
                \`retail_price\` int NOT NULL,
                \`wholesale_price\` int NOT NULL,
                INDEX \`IDX_4510559b597f175115aa24088f\` (\`c_phone\`, \`medicine_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
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
                INDEX \`clinic_phone\` (\`phone\`),
                UNIQUE INDEX \`IDX_b3df084998059e1f2f31bfd1e8\` (\`phone\`),
                UNIQUE INDEX \`IDX_050033b437380ba808c041fe73\` (\`email\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_delivery\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`medicine_id\` int NOT NULL,
                \`delivery_note_id\` int NOT NULL,
                \`quantity\` int NOT NULL DEFAULT '0',
                \`expiry_date\` datetime NOT NULL,
                \`cost_price\` int NOT NULL,
                \`expected_price\` int NOT NULL,
                \`actual_price\` int NOT NULL,
                \`discount\` int NOT NULL,
                INDEX \`IDX_15d12e4715c86978620a769ab1\` (\`c_phone\`, \`delivery_note_id\`),
                INDEX \`IDX_4baa032ec8da4fb50331430258\` (\`c_phone\`, \`medicine_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_receipt_note\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`provider_id\` int NOT NULL,
                \`user_id\` int NOT NULL,
                \`buyer_pays_ship\` int NOT NULL,
                \`seller_pays_ship\` int NOT NULL,
                \`discount\` int NOT NULL,
                \`debt\` int NOT NULL,
                \`total_money\` int NOT NULL,
                INDEX \`IDX_aa6639026a7527775e4ed2652a\` (\`c_phone\`, \`provider_id\`),
                INDEX \`IDX_be9340e301ec0b6cc2e1174d8a\` (\`c_phone\`, \`user_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_receipt\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`medicine_id\` int NOT NULL,
                \`receipt_note_id\` int NOT NULL,
                \`quantity\` int NOT NULL DEFAULT '0',
                \`expiry_date\` datetime NOT NULL,
                \`cost_price\` int NOT NULL,
                INDEX \`IDX_2d3d9d32545f74cffefb0a48e1\` (\`c_phone\`, \`receipt_note_id\`),
                INDEX \`IDX_834a0a72a5c9aa9b1cee5f7539\` (\`c_phone\`, \`medicine_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`employee\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`phone\` varchar(10) NULL,
                \`username\` varchar(255) NOT NULL,
                \`password\` varchar(255) NOT NULL,
                \`role\` enum ('Owner', 'Admin', 'User') NOT NULL DEFAULT 'User',
                INDEX \`IDX_6d4dfc8c7c708a429b4d2a1f4e\` (\`c_phone\`, \`username\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`customer\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`name\` varchar(255) NOT NULL,
                \`phone\` varchar(255) NOT NULL,
                \`address\` varchar(255) NOT NULL,
                INDEX \`IDX_04d58ce9ff74a3eefc90940924\` (\`c_phone\`, \`name\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine_delivery_note\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`customer_id\` int NOT NULL,
                \`user_id\` int NOT NULL,
                INDEX \`IDX_5068133bf34db57cadaab79f50\` (\`c_phone\`, \`customer_id\`),
                INDEX \`IDX_7800a03eadd8ec1caffd141833\` (\`c_phone\`, \`user_id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`provider\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`provider_name\` varchar(255) NOT NULL,
                \`phone\` varchar(255) NOT NULL,
                \`address\` varchar(255) NOT NULL,
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE TABLE \`medicine\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`created_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                \`updated_at\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                \`deleted_at\` datetime(6) NULL,
                \`c_phone\` varchar(10) NOT NULL,
                \`brand_name\` varchar(255) NULL,
                \`chemical_name\` varchar(255) NULL,
                \`calculation_unit\` varchar(255) NULL,
                \`image\` varchar(255) NULL,
                UNIQUE INDEX \`IDX_e4b4d0a2c7a363fc58723256f0\` (\`c_phone\`, \`id\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            DROP INDEX \`IDX_e4b4d0a2c7a363fc58723256f0\` ON \`medicine\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine\`
        `);
        await queryRunner.query(`
            DROP TABLE \`provider\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_7800a03eadd8ec1caffd141833\` ON \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_5068133bf34db57cadaab79f50\` ON \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_04d58ce9ff74a3eefc90940924\` ON \`customer\`
        `);
        await queryRunner.query(`
            DROP TABLE \`customer\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_6d4dfc8c7c708a429b4d2a1f4e\` ON \`employee\`
        `);
        await queryRunner.query(`
            DROP TABLE \`employee\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_834a0a72a5c9aa9b1cee5f7539\` ON \`medicine_receipt\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_2d3d9d32545f74cffefb0a48e1\` ON \`medicine_receipt\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_receipt\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_be9340e301ec0b6cc2e1174d8a\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_aa6639026a7527775e4ed2652a\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_4baa032ec8da4fb50331430258\` ON \`medicine_delivery\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_15d12e4715c86978620a769ab1\` ON \`medicine_delivery\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_delivery\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_050033b437380ba808c041fe73\` ON \`clinic\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_b3df084998059e1f2f31bfd1e8\` ON \`clinic\`
        `);
        await queryRunner.query(`
            DROP INDEX \`clinic_phone\` ON \`clinic\`
        `);
        await queryRunner.query(`
            DROP TABLE \`clinic\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_4510559b597f175115aa24088f\` ON \`medicine_available\`
        `);
        await queryRunner.query(`
            DROP TABLE \`medicine_available\`
        `);
    }

}
