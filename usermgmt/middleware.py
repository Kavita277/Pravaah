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
        # Also checks if they belong to an explicit 'Super Admin' group name
        is_superadmin = request.user.is_superuser or request.user.groups.filter(name='Super Admin').exists()
        if is_superadmin:
            return self.get_response(request)

        # 4. Define your Route-to-Permission Mapping Dictionary
        # Maps the URL 'name' from urls.py to the permission codename from models.py
        PERMISSION_GATEWAY = {
            'register': 'can_assign_roles',
            'admin_dashboard': 'can_view_admin_dashboard',
            'activity_dashboard': 'can_view_qa_logs',
            'roles_list': 'can_manage_roles',
            'role_add': 'can_manage_roles',
            'permissions_list': 'can_modify_permissions',
            'assign_role': 'can_assign_roles',
            'assign_permissions': 'can_modify_permissions',
            'permission_matrix': 'can_view_permission_matrix',
            'rbac_users_list': 'can_view_admin_dashboard',
            'users_list': 'can_view_admin_dashboard',
            'audit_logs': 'can_view_qa_logs',
            
            # Person 2 Analytics / Report Modules Maps
            'reports': 'can_view_management_reports',
            'report_result': 'can_view_management_reports',
        }

        # 5. Enforce Restrictions
        if current_route in PERMISSION_GATEWAY:
            required_permission = PERMISSION_GATEWAY[current_route]
            
            # Check if the user's assigned role (Group) has this permission set via the Matrix
            # Standard Django syntax format: 'app_label.codename'
            permission_string = f'usermgmt.{required_permission}'
            
            if not request.user.has_perm(permission_string):
                messages.error(request, "Access Denied: You do not have the required permissions for this action.")
                
                # Redirect restricted users back to their basic personal profile dashboard safely
                return redirect('usermgmt:user_home')

        return self.get_response(request)