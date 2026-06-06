-- =========================================================================
-- 1. SCHEMA CREATION QUERIES
-- =========================================================================

-- Create model User
CREATE TABLE `users` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY, 
    `password` varchar(128) NOT NULL, 
    `last_login` datetime(6) NULL, 
    `is_superuser` bool NOT NULL, 
    `username` varchar(150) NOT NULL UNIQUE, 
    `first_name` varchar(150) NOT NULL, 
    `last_name` varchar(150) NOT NULL, 
    `is_staff` bool NOT NULL, 
    `is_active` bool NOT NULL, 
    `date_joined` datetime(6) NOT NULL, 
    `email` varchar(254) NOT NULL UNIQUE, 
    `mobile` varchar(15) NULL, 
    `is_email_verified` bool NOT NULL, 
    `email_verification_token` varchar(100) NULL, 
    `token_created_at` datetime(6) NULL, 
    `created_at` datetime(6) NOT NULL, 
    `updated_at` datetime(6) NOT NULL
);

-- Create model users_groups M2M join table
CREATE TABLE `users_groups` (
    `id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, 
    `user_id` bigint NOT NULL, 
    `group_id` integer NOT NULL
);

-- Create model users_user_permissions M2M join table
CREATE TABLE `users_user_permissions` (
    `id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, 
    `user_id` bigint NOT NULL, 
    `permission_id` integer NOT NULL
);

-- Create model AuditLog
CREATE TABLE `audit_logs` (
    `id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY, 
    `action` varchar(255) NOT NULL, 
    `module` varchar(50) NOT NULL, 
    `ip_address` char(39) NULL, 
    `browser_agent` longtext NULL, 
    `timestamp` datetime(6) NOT NULL, 
    `user_id` bigint NULL
);

-- Add constraints
ALTER TABLE `users_groups` ADD CONSTRAINT `users_groups_user_id_group_id_fc7788e8_uniq` UNIQUE (`user_id`, `group_id`);
ALTER TABLE `users_groups` ADD CONSTRAINT `users_groups_user_id_f500bee5_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);
ALTER TABLE `users_groups` ADD CONSTRAINT `users_groups_group_id_2f3517aa_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`);
ALTER TABLE `users_user_permissions` ADD CONSTRAINT `users_user_permissions_user_id_permission_id_3b86cbdf_uniq` UNIQUE (`user_id`, `permission_id`);
ALTER TABLE `users_user_permissions` ADD CONSTRAINT `users_user_permissions_user_id_92473840_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);
ALTER TABLE `users_user_permissions` ADD CONSTRAINT `users_user_permissio_permission_id_6d08dcd2_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`);
ALTER TABLE `audit_logs` ADD CONSTRAINT `audit_logs_user_id_752b0e2b_fk_users_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);


-- =========================================================================
-- 2. ENTERPRISE ROLE SEEDING QUERIES
-- =========================================================================

-- Purge obsolete groups not in the 7 roles scope
DELETE FROM auth_group 
WHERE name NOT IN ('Super Admin', 'Training Manager', 'Master Trainer', 'Hostel Admin', 'Participant', 'Accounts Admin', 'Staff');

-- Insert the exact 7 enterprise roles
INSERT IGNORE INTO auth_group (name) VALUES 
('Super Admin'),
('Training Manager'),
('Master Trainer'),
('Hostel Admin'),
('Participant'),
('Accounts Admin'),
('Staff');


-- =========================================================================
-- 3. ROLE PERMISSIONS MATRIX MAPPING QUERIES
-- =========================================================================

-- Clear existing permission links for the 7 roles
DELETE FROM auth_group_permissions 
WHERE group_id IN (
    SELECT id FROM auth_group 
    WHERE name IN ('Super Admin', 'Training Manager', 'Master Trainer', 'Hostel Admin', 'Participant', 'Accounts Admin', 'Staff')
);

-- Map all permissions to 'Super Admin'
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT 
    (SELECT id FROM auth_group WHERE name = 'Super Admin'), 
    id 
FROM auth_permission 
WHERE content_type_id = (SELECT id FROM django_content_type WHERE app_label = 'usermgmt' AND model = 'rbacpermissionproxy');

-- Map permissions to 'Training Manager'
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT 
    (SELECT id FROM auth_group WHERE name = 'Training Manager'), 
    id 
FROM auth_permission 
WHERE codename IN ('can_view_student_profiles', 'can_view_trainer_profiles', 'can_view_course_details', 'can_view_hostel_status', 'can_view_management_reports');

-- Map permissions to 'Master Trainer'
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT 
    (SELECT id FROM auth_group WHERE name = 'Master Trainer'), 
    id 
FROM auth_permission 
WHERE codename IN ('can_view_student_profiles', 'can_view_trainer_profiles', 'can_view_management_reports');

-- Map permissions to 'Hostel Admin'
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT 
    (SELECT id FROM auth_group WHERE name = 'Hostel Admin'), 
    id 
FROM auth_permission 
WHERE codename IN ('can_view_hostel_status', 'can_view_management_reports');

-- Map permissions to 'Accounts Admin'
INSERT INTO auth_group_permissions (group_id, permission_id)
SELECT 
    (SELECT id FROM auth_group WHERE name = 'Accounts Admin'), 
    id 
FROM auth_permission 
WHERE codename IN ('can_view_trainer_profiles', 'can_view_management_reports');


-- =========================================================================
-- 4. TEST USER ACCOUNTS GENERATION
-- =========================================================================

-- Purge existing test accounts
DELETE FROM users 
WHERE username IN ('superadmin', 'trainingmanager', 'mastertrainer', 'hosteladmin', 'participant', 'accountsadmin', 'staff');

-- Insert new user profiles (password hash evaluates to 'Password123!')
INSERT INTO users (username, email, password, is_active, is_email_verified, is_staff, is_superuser, date_joined, created_at, updated_at) VALUES
('superadmin', 'superadmin@example.com', 'pbkdf2_sha256$870000$mBywc7FVrv8ZtBRok5LQ0E$H+SlpIs+sYta9atWaadZLZgXSo68QbQzaQoQxAYmlig=', 1, 1, 0, 0, NOW(), NOW(), NOW()),
('trainingmanager', 'trainingmanager@example.com', 'pbkdf2_sha256$870000$mBywc7FVrv8ZtBRok5LQ0E$H+SlpIs+sYta9atWaadZLZgXSo68QbQzaQoQxAYmlig=', 1, 1, 0, 0, NOW(), NOW(), NOW()),
('mastertrainer', 'mastertrainer@example.com', 'pbkdf2_sha256$870000$mBywc7FVrv8ZtBRok5LQ0E$H+SlpIs+sYta9atWaadZLZgXSo68QbQzaQoQxAYmlig=', 1, 1, 0, 0, NOW(), NOW(), NOW()),
('hosteladmin', 'hosteladmin@example.com', 'pbkdf2_sha256$870000$mBywc7FVrv8ZtBRok5LQ0E$H+SlpIs+sYta9atWaadZLZgXSo68QbQzaQoQxAYmlig=', 1, 1, 0, 0, NOW(), NOW(), NOW()),
('participant', 'participant@example.com', 'pbkdf2_sha256$870000$mBywc7FVrv8ZtBRok5LQ0E$H+SlpIs+sYta9atWaadZLZgXSo68QbQzaQoQxAYmlig=', 1, 1, 0, 0, NOW(), NOW(), NOW()),
('accountsadmin', 'accountsadmin@example.com', 'pbkdf2_sha256$870000$mBywc7FVrv8ZtBRok5LQ0E$H+SlpIs+sYta9atWaadZLZgXSo68QbQzaQoQxAYmlig=', 1, 1, 0, 0, NOW(), NOW(), NOW()),
('staff', 'staff@example.com', 'pbkdf2_sha256$870000$mBywc7FVrv8ZtBRok5LQ0E$H+SlpIs+sYta9atWaadZLZgXSo68QbQzaQoQxAYmlig=', 1, 1, 0, 0, NOW(), NOW(), NOW());

-- Map users to their respective roles/groups
INSERT INTO users_groups (user_id, group_id) VALUES
((SELECT id FROM users WHERE username = 'superadmin'), (SELECT id FROM auth_group WHERE name = 'Super Admin')),
((SELECT id FROM users WHERE username = 'trainingmanager'), (SELECT id FROM auth_group WHERE name = 'Training Manager')),
((SELECT id FROM users WHERE username = 'mastertrainer'), (SELECT id FROM auth_group WHERE name = 'Master Trainer')),
((SELECT id FROM users WHERE username = 'hosteladmin'), (SELECT id FROM auth_group WHERE name = 'Hostel Admin')),
((SELECT id FROM users WHERE username = 'participant'), (SELECT id FROM auth_group WHERE name = 'Participant')),
((SELECT id FROM users WHERE username = 'accountsadmin'), (SELECT id FROM auth_group WHERE name = 'Accounts Admin')),
((SELECT id FROM users WHERE username = 'staff'), (SELECT id FROM auth_group WHERE name = 'Staff'));
