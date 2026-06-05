-- =========================================================================
-- PRAVAAH ERP - USER MANAGEMENT & RBAC SCHEMA
-- =========================================================================

-- 1. Create permissions table
CREATE TABLE `permissions` (
    `permission_id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `permission_name` VARCHAR(100) UNIQUE NOT NULL,
    `description` TEXT NULL
);

-- 2. Create roles table
CREATE TABLE `roles` (
    `role_id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `role_name` VARCHAR(100) UNIQUE NOT NULL,
    `description` TEXT NULL,
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE
);

-- 3. Create users table
CREATE TABLE `users` (
    `user_id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `role_id` INT NULL,
    `username` VARCHAR(100) UNIQUE NOT NULL,
    `email` VARCHAR(150) UNIQUE NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `first_name` VARCHAR(100) NOT NULL,
    `last_name` VARCHAR(100) NOT NULL,
    `mobile` VARCHAR(20) NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'Active',
    `is_superuser` BOOLEAN NOT NULL DEFAULT FALSE,
    `is_staff` BOOLEAN NOT NULL DEFAULT FALSE,
    `is_email_verified` BOOLEAN NOT NULL DEFAULT FALSE,
    `email_verification_token` VARCHAR(100) NULL,
    `token_created_at` DATETIME(6) NULL,
    `last_login` DATETIME(6) NULL,
    `created_at` DATETIME(6) NOT NULL,
    `updated_at` DATETIME(6) NOT NULL,
    CONSTRAINT `fk_users_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`role_id`) ON DELETE SET NULL
);

-- 4. Create role_permissions join table
CREATE TABLE `role_permissions` (
    `id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `role_id` INT NOT NULL,
    `permission_id` INT NOT NULL,
    CONSTRAINT `fk_role_permissions_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`role_id`) ON DELETE CASCADE,
    CONSTRAINT `fk_role_permissions_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`permission_id`) ON DELETE CASCADE,
    UNIQUE KEY `uniq_role_permission` (`role_id`, `permission_id`)
);

-- 5. Create user_roles join table
CREATE TABLE `user_roles` (
    `id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `user_id` INT NOT NULL,
    `role_id` INT NOT NULL,
    CONSTRAINT `fk_user_roles_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE,
    CONSTRAINT `fk_user_roles_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`role_id`) ON DELETE CASCADE,
    UNIQUE KEY `uniq_user_role` (`user_id`, `role_id`)
);

-- 6. Create audit_logs table
CREATE TABLE `audit_logs` (
    `id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `action` VARCHAR(255) NOT NULL,
    `module` VARCHAR(50) NOT NULL DEFAULT 'usermgmt',
    `ip_address` CHAR(39) NULL,
    `browser_agent` LONGTEXT NULL,
    `timestamp` DATETIME(6) NOT NULL,
    `user_id` INT NULL,
    CONSTRAINT `fk_audit_logs_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON DELETE SET NULL
);
