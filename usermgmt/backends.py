from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class CustomRoleBackend(ModelBackend):
    """
    Custom authentication backend that maps standard Django permission checking
    to the custom 'roles', 'permissions', and 'user_roles' schema.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            UserModel().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def get_user_permissions(self, user_obj, obj=None):
        return set()

    def get_group_permissions(self, user_obj, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous:
            return set()
        
        perms = set()
        # Direct role relation permissions (one-to-many)
        if user_obj.role and user_obj.role.is_active:
            for p in user_obj.role.permissions.all():
                perms.add(f"usermgmt.{p.permission_name}")
            
        # Many-to-many roles relations permissions (user_roles join table)
        for r in user_obj.roles.filter(is_active=True):
            for p in r.permissions.all():
                perms.add(f"usermgmt.{p.permission_name}")
            
        return perms

    def get_all_permissions(self, user_obj, obj=None):
        return self.get_group_permissions(user_obj, obj)

    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active:
            return False
        if user_obj.is_superuser:
            return True
        return perm in self.get_all_permissions(user_obj, obj)
