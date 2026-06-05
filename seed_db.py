import os
import django
from django.db import transaction

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pravaah.settings')
django.setup()

from usermgmt.models import User, Role, CustomPermission

def seed_database():
    print("Starting database seeding of custom roles, permissions, and users...")
    with transaction.atomic():
        # 1. Sync Custom Permissions
        permissions_data = [
            ('MANAGE_USERS', 'Manage Users'),
            ('ASSIGN_ROLES', 'Assign Roles'),
            ('CREATE_PROGRAMME', 'Create Programme'),
            ('EDIT_PROGRAMME', 'Edit Programme'),
            ('APPROVE_PROGRAMME', 'Approve Programme'),
            ('MANAGE_PARTICIPANTS', 'Manage Participants'),
            ('MARK_ATTENDANCE', 'Mark Attendance'),
            ('UPLOAD_MATERIALS', 'Upload Materials'),
            ('CONDUCT_ASSESSMENTS', 'Conduct Assessments'),
            ('HOSTEL_ALLOCATION', 'Hostel Allocation'),
            ('ROOM_MANAGEMENT', 'Room Management'),
            ('FEE_MANAGEMENT', 'Fee Management'),
            ('PAYMENT_VERIFICATION', 'Payment Verification'),
            ('GENERATE_REPORTS', 'Generate Reports'),
            ('VIEW_AUDIT_LOGS', 'View Audit Logs'),
            ('SEND_NOTIFICATIONS', 'Send Notifications')
        ]
        
        # Purge obsolete permissions
        expected_perms = [p[0] for p in permissions_data]
        CustomPermission.objects.exclude(permission_name__in=expected_perms).delete()
        
        perms = {}
        for name, desc in permissions_data:
            perm, _ = CustomPermission.objects.get_or_create(
                permission_name=name,
                defaults={'description': desc}
            )
            perms[name] = perm
        print("Permissions synchronized.")

        # 2. Sync Roles (expected 8 enterprise roles)
        expected_roles = [
            'Super Admin',
            'Training Manager',
            'Master Trainer',
            'Hostel Admin',
            'Participant',
            'Accounts Admin',
            'Staff',
            'QA'
        ]
        Role.objects.exclude(role_name__in=expected_roles).delete()
        
        roles = {}
        for name in expected_roles:
            role, _ = Role.objects.get_or_create(role_name=name)
            roles[name] = role
        print("Roles synchronized.")

        # 3. Map permissions to roles
        # Clear existing role permissions mapping
        for r in roles.values():
            r.permissions.clear()

        # Helper to assign permissions to role
        def assign_perms(role_name, perm_names):
            role = roles[role_name]
            role_perms = [perms[name] for name in perm_names if name in perms]
            role.permissions.add(*role_perms)

        # Super Admin gets all permissions
        assign_perms('Super Admin', [p[0] for p in permissions_data])
        assign_perms('Training Manager', [
            'CREATE_PROGRAMME', 'EDIT_PROGRAMME', 'APPROVE_PROGRAMME', 
            'MANAGE_PARTICIPANTS', 'MARK_ATTENDANCE', 'GENERATE_REPORTS', 'SEND_NOTIFICATIONS'
        ])
        assign_perms('Master Trainer', [
            'MARK_ATTENDANCE', 'UPLOAD_MATERIALS', 'CONDUCT_ASSESSMENTS', 'MANAGE_PARTICIPANTS'
        ])
        assign_perms('Hostel Admin', [
            'HOSTEL_ALLOCATION', 'ROOM_MANAGEMENT', 'MANAGE_PARTICIPANTS'
        ])
        assign_perms('Accounts Admin', [
            'FEE_MANAGEMENT', 'PAYMENT_VERIFICATION', 'GENERATE_REPORTS'
        ])
        assign_perms('Staff', [
            'MANAGE_PARTICIPANTS', 'MARK_ATTENDANCE', 'SEND_NOTIFICATIONS'
        ])
        assign_perms('QA', [
            'VIEW_AUDIT_LOGS', 'GENERATE_REPORTS', 'MANAGE_USERS', 'ASSIGN_ROLES', 
            'CREATE_PROGRAMME', 'EDIT_PROGRAMME', 'APPROVE_PROGRAMME', 
            'MANAGE_PARTICIPANTS', 'MARK_ATTENDANCE', 'UPLOAD_MATERIALS', 
            'CONDUCT_ASSESSMENTS', 'HOSTEL_ALLOCATION', 'ROOM_MANAGEMENT', 
            'FEE_MANAGEMENT', 'PAYMENT_VERIFICATION', 'SEND_NOTIFICATIONS'
        ])
        assign_perms('Participant', [
            'MANAGE_PARTICIPANTS', 'MARK_ATTENDANCE', 'UPLOAD_MATERIALS', 'CONDUCT_ASSESSMENTS'
        ])

        print("Permissions mapped to roles successfully.")

        # 4. Sync/Create test user accounts (all with Password123!)
        test_users = [
            ('superadmin', 'superadmin@example.com', 'Super', 'Admin', 'Super Admin'),
            ('trainingmanager', 'trainingmanager@example.com', 'Training', 'Manager', 'Training Manager'),
            ('mastertrainer', 'mastertrainer@example.com', 'Master', 'Trainer', 'Master Trainer'),
            ('hosteladmin', 'hosteladmin@example.com', 'Hostel', 'Admin', 'Hostel Admin'),
            ('participant', 'participant@example.com', 'Participant', 'User', 'Participant'),
            ('accountsadmin', 'accountsadmin@example.com', 'Accounts', 'Admin', 'Accounts Admin'),
            ('staff', 'staff@example.com', 'Staff', 'User', 'Staff'),
            ('qa', 'qa@example.com', 'QA', 'User', 'QA'),
        ]

        usernames = [u[0] for u in test_users]
        User.objects.filter(username__in=usernames).delete()

        for username, email, first_name, last_name, role_name in test_users:
            user = User.objects.create_user(
                username=username,
                email=email,
                password='Password123!',
                first_name=first_name,
                last_name=last_name,
                status='Active'
            )
            user.is_email_verified = True
            if role_name == 'Super Admin':
                user.is_superuser = True
                user.is_staff = True
            user.save()

            # Assign role
            role = roles[role_name]
            user.role = role
            user.roles.add(role)
            user.save()

        print("Test users created and assigned to roles successfully.")
        print("Database schema creation and seeding completed successfully.")

if __name__ == '__main__':
    seed_database()
