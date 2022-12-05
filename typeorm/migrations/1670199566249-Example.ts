import { MigrationInterface, QueryRunner } from "typeorm";

export class Example1670199566249 implements MigrationInterface {
    name = 'Example1670199566249'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            DROP INDEX \`IDX_964c3888b652abffc09ca97772\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_b1c1bc16f303f3fa200e35a5c0\` ON \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            ALTER TABLE \`medicine_receipt_note\` CHANGE \`employee_id\` \`user_id\` int NOT NULL
        `);
        await queryRunner.query(`
            ALTER TABLE \`medicine_delivery_note\` CHANGE \`employee_id\` \`user_id\` int NOT NULL
        `);
        await queryRunner.query(`
            CREATE TABLE \`user\` (
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
                INDEX \`IDX_bf0a54443b3c5b3f8a787cab4f\` (\`clinic_id\`, \`username\`),
                INDEX \`IDX_1e6b7c613210e2b9c4b5372385\` (\`clinic_id\`, \`email\`),
                UNIQUE INDEX \`IDX_e12875dfb3b1d92d7d7c5377e2\` (\`email\`),
                UNIQUE INDEX \`IDX_8e1f623798118e629b46a9e629\` (\`phone\`),
                PRIMARY KEY (\`id\`)
            ) ENGINE = InnoDB
        `);
        await queryRunner.query(`
            CREATE INDEX \`IDX_d0056581598a39f1e72b3cf502\` ON \`medicine_receipt_note\` (\`clinic_id\`, \`user_id\`)
        `);
        await queryRunner.query(`
            CREATE INDEX \`IDX_d0c2c4349a6f8d89b56c9702fd\` ON \`medicine_delivery_note\` (\`clinic_id\`, \`user_id\`)
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            DROP INDEX \`IDX_d0c2c4349a6f8d89b56c9702fd\` ON \`medicine_delivery_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_d0056581598a39f1e72b3cf502\` ON \`medicine_receipt_note\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_8e1f623798118e629b46a9e629\` ON \`user\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_e12875dfb3b1d92d7d7c5377e2\` ON \`user\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_1e6b7c613210e2b9c4b5372385\` ON \`user\`
        `);
        await queryRunner.query(`
            DROP INDEX \`IDX_bf0a54443b3c5b3f8a787cab4f\` ON \`user\`
        `);
        await queryRunner.query(`
            DROP TABLE \`user\`
        `);
        await queryRunner.query(`
            ALTER TABLE \`medicine_delivery_note\` CHANGE \`user_id\` \`employee_id\` int NOT NULL
        `);
        await queryRunner.query(`
            ALTER TABLE \`medicine_receipt_note\` CHANGE \`user_id\` \`employee_id\` int NOT NULL
        `);
        await queryRunner.query(`
            CREATE INDEX \`IDX_b1c1bc16f303f3fa200e35a5c0\` ON \`medicine_delivery_note\` (\`clinic_id\`, \`employee_id\`)
        `);
        await queryRunner.query(`
            CREATE INDEX \`IDX_964c3888b652abffc09ca97772\` ON \`medicine_receipt_note\` (\`clinic_id\`, \`employee_id\`)
        `);
    }

}
