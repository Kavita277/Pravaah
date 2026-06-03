from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from usermgmt.models import RBACPermissionProxy

class Command(BaseCommand):
    help = 'Populates the database with extended roles and granular permission sets'

    def handle(self, *args, **kwargs):
        self.stdout.write('Executing extended RBAC installation data seeding...')

        # Complete List of Roles Including New Requested Divisions
        roles_to_create = [
            'Super Admin',
            'System Admin',
            'Management',
            'Accounts',
            'QA',
            'Training Manager',
            'Trainer',
            'Hostel Admin',
            'Participant'
        ]

        # Sync roles into Group model records
        groups_dict = {}
        for role_name in roles_to_create:
            group, created = Group.objects.get_or_create(name=role_name)
            groups_dict[role_name] = group
            if created:
                self.stdout.write(f"Generated target role: {role_name}")

        # Fetch custom proxy capability configurations
        content_type = ContentType.objects.get_for_model(RBACPermissionProxy, for_concrete_model=False)
        
        # Safe Mapping Logic to Distribute Permissions Across Roles Automatically
        def assign_perms(group_name, codenames_list):
            if group_name in groups_dict:
                group_obj = groups_dict[group_name]
                perms = Permission.objects.filter(content_type=content_type, codename__in=codenames_list)
                group_obj.permissions.set(perms)
                self.stdout.write(f"Mapped {perms.count()} policy tokens to group '{group_name}'")

        # 1. System Admin Roles get absolute access
        all_perms = Permission.objects.filter(content_type=content_type)
        if 'System Admin' in groups_dict:
            groups_dict['System Admin'].permissions.set(all_perms)

        # 2. Management Core Mapping
        assign_perms('Management', [
            'can_view_admin_dashboard', 'can_view_permission_matrix',
            'can_view_management_reports', 'can_approve_requests',
            'can_view_student_profiles', 'can_view_trainer_profiles',
            'can_view_course_details', 'can_view_hostel_status'
        ])

        # 3. Accounts Division Core Mapping
        assign_perms('Accounts', [
            'can_view_finance_dashboard', 'can_manage_finance',
            'can_view_management_reports'
        ])

        # 4. QA Division Core Mapping
        assign_perms('QA', [
            'can_view_qa_logs', 'can_manage_qa_tickets',
            'can_view_course_details'
        ])

        # 5. Lower-Level User Profiles Safe Mapping (Read-Only)
        assign_perms('Participant', [
            'can_view_course_details', 'can_view_hostel_status'
        ])
        
        assign_perms('Trainer', [
            'can_view_student_profiles', 'can_view_trainer_profiles', 'can_view_course_details'
        ])

        self.stdout.write(self.style.SUCCESS('Successfully seeded all new roles and safe view permission tokens!'))
