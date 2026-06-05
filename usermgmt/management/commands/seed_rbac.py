from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from usermgmt.models import RBACPermissionProxy, Role

class Command(BaseCommand):
    help = 'Populates the database with the exact 7 enterprise roles and permission sets'

    def handle(self, *args, **kwargs):
        self.stdout.write('Executing RBAC database data seeding...')

        # Exact 7 Roles required by current scope
        roles_to_create = [
            'Super Admin',
            'Training Manager',
            'Master Trainer',
            'Hostel Admin',
            'Participant',
            'Accounts Admin',
            'Staff'
        ]

        # Purge obsolete roles
        for group in list(Role.objects.all()):
            if group.role_name not in roles_to_create:
                self.stdout.write(f"Purging obsolete role: {group.role_name}")
                group.delete()

        # Sync/create the 7 roles
        groups_dict = {}
        for role_name in roles_to_create:
            group, created = Role.objects.get_or_create(role_name=role_name)
            groups_dict[role_name] = group
            if created:
                self.stdout.write(f"Generated role: {role_name}")

        # Fetch custom proxy capability configurations
        content_type = ContentType.objects.get_for_model(RBACPermissionProxy, for_concrete_model=False)
        all_perms = Permission.objects.filter(content_type=content_type)
        
        # Helper to assign permissions to a group
        def assign_perms(group_name, codenames_list):
            if group_name in groups_dict:
                group_obj = groups_dict[group_name]
                perms = Permission.objects.filter(content_type=content_type, codename__in=codenames_list)
                group_obj.permissions.set(perms)
                self.stdout.write(f"Mapped {perms.count()} permissions to group '{group_name}'")

        # 1. Super Admin: Full access to all permissions
        if 'Super Admin' in groups_dict:
            groups_dict['Super Admin'].permissions.set(all_perms)
            self.stdout.write("Mapped all permissions to 'Super Admin'")

        # 2. Training Manager: Participant, Master Trainer, Course, Hostel Management, Reports
        assign_perms('Training Manager', [
            'can_view_student_profiles',
            'can_view_trainer_profiles',
            'can_view_course_details',
            'can_view_hostel_status',
            'can_view_management_reports'
        ])

        # 3. Master Trainer: View Participant and Trainer records, Reports
        assign_perms('Master Trainer', [
            'can_view_student_profiles',
            'can_view_trainer_profiles',
            'can_view_management_reports'
        ])

        # 4. Hostel Admin: Hostel Management, Reports
        assign_perms('Hostel Admin', [
            'can_view_hostel_status',
            'can_view_management_reports'
        ])

        # 5. Accounts Admin: Master Trainer Management, Reports
        assign_perms('Accounts Admin', [
            'can_view_trainer_profiles',
            'can_view_management_reports'
        ])

        # 6. Participant: Own profile only (no global proxy permissions)
        assign_perms('Participant', [])

        # 7. Staff: Temporary permissions (none seeded by default)
        assign_perms('Staff', [])

        self.stdout.write(self.style.SUCCESS('Successfully seeded all 7 roles and permission tokens!'))


