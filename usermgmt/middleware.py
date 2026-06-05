from django.shortcuts import redirect
from django.contrib import messages
from django.urls import resolve

class RoleBasedAccessControlMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Resolve the current URL route name to check what view they are trying to load
        try:
            current_route = resolve(request.path_info).url_name
        except Exception:
            current_route = None

        # Whitelist of public routes accessible without login
        PUBLIC_ROUTES = {
            'login',
            'home',
            'forgot_password',
            'reset_password',
            'reset_password_confirm',
            'verify_email',
            'verify_email_confirm',
            'session_expired',
        }

        # 1. Enforce login requirements centrally for all private routes
        if not request.user.is_authenticated:
            if current_route not in PUBLIC_ROUTES:
               return redirect('usermgmt:login')
            return self.get_response(request)

        # 2. Rule: Superadmins / Superusers bypass all restrictions instantly
        # Also checks if they belong to an explicit 'Super Admin' role
        is_superadmin = request.user.is_superuser or (
            request.user.role and request.user.role.role_name == 'Super Admin'
        ) or request.user.roles.filter(role_name='Super Admin').exists()
        if is_superadmin:
            return self.get_response(request)


        # 3. Define your Route-to-Permission Mapping Dictionary
        # Maps the URL 'name' from urls.py to the permission codename from models.py
        PERMISSION_GATEWAY = {
            'register': 'MANAGE_USERS',
            'users_list': 'MANAGE_USERS',
            'rbac_users_list': 'MANAGE_USERS',
            
            'admin_dashboard': 'ASSIGN_ROLES',
            'roles_list': 'ASSIGN_ROLES',
            'role_add': 'ASSIGN_ROLES',
            'permissions_list': 'ASSIGN_ROLES',
            'assign_role': 'ASSIGN_ROLES',
            'assign_permissions': 'ASSIGN_ROLES',
            'permission_matrix': 'ASSIGN_ROLES',

            'activity_dashboard': 'VIEW_AUDIT_LOGS',
            'audit_logs': 'VIEW_AUDIT_LOGS',
            
            # Person 2 Analytics / Report Modules Maps
            'reports': 'GENERATE_REPORTS',
            'report_result': 'GENERATE_REPORTS',
            
            # Business Module Placeholders
            'participant_management_placeholder': 'MANAGE_PARTICIPANTS',
            'master_trainer_management_placeholder': 'MARK_ATTENDANCE',
            'course_management_placeholder': 'CREATE_PROGRAMME',
            'hostel_management_placeholder': 'HOSTEL_ALLOCATION',
        }

        # 4. Enforce Restrictions
        if current_route in PERMISSION_GATEWAY:
            required_permission = PERMISSION_GATEWAY[current_route]
            
            # Check if the user's assigned role (Group) has this permission set via the Matrix
            # Standard Django syntax format: 'app_label.codename'
            permission_string = f'usermgmt.{required_permission}'
            
            if not request.user.has_perm(permission_string):
                messages.error(request, "You do not have access. Please request the Admin to give you access.")
                
                # Redirect restricted users back to their basic personal profile dashboard safely
                return redirect('usermgmt:user_home')

        return self.get_response(request)