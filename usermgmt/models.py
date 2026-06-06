from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class CustomPermission(models.Model):
    """
    Custom Permission model mapping to 'permissions' table.
    """
    permission_id = models.AutoField(primary_key=True)
    permission_name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)

    class Meta:
        managed = False  # This model is managed manually, not by Django's migrations
        db_table = 'permissions'

    @property
    def id(self):
        return self.permission_id

    def __str__(self):
        return self.permission_name


class Role(models.Model):
    """
    Custom Role model mapping to 'roles' table.
    """
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    permissions = models.ManyToManyField(
        CustomPermission,
        through='RolePermission',
        related_name='roles',
        blank=True
    )

    class Meta:
        db_table = 'roles'

    @property
    def id(self):
        return self.role_id

    def __str__(self):
        return self.role_name


class RolePermission(models.Model):
    """
    Join table mapping to 'role_permissions' table.
    """
    role = models.ForeignKey(Role, on_delete=models.CASCADE, db_column='role_id')
    permission = models.ForeignKey(CustomPermission, on_delete=models.CASCADE, db_column='permission_id')

    class Meta:
        db_table = 'role_permissions'
        unique_together = ('role', 'permission')


class CustomUserManager(BaseUserManager):
    """
    Custom manager for custom User model.
    """
    def create_user(self, username, email, password=None, **extra_fields):
        if not username:
            raise ValueError('The Username field must be set')
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('status', 'Active')
        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser):
    """
    Custom User model mapping to 'users' table.
    """
    user_id = models.AutoField(primary_key=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True, db_column='role_id')
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(max_length=150, unique=True)
    password = models.CharField(max_length=255, db_column='password_hash')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    mobile = models.CharField(max_length=20, blank=True, null=True)
    status = models.CharField(max_length=20, default='Active')

    # Django admin/system metadata fields
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    # Verification lifecycle fields
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    token_created_at = models.DateTimeField(blank=True, null=True)

    # Chronological timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    roles = models.ManyToManyField(
        Role,
        through='UserRole',
        related_name='users_set',
        blank=True
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']

    class Meta:
        db_table = 'users'

    @property
    def is_active(self):
        return self.status == 'Active'

    @is_active.setter
    def is_active(self, value):
        self.status = 'Active' if value else 'Inactive'

    @property
    def id(self):
        return self.user_id

    def has_perm(self, perm, obj=None):
        if self.is_superuser:
            return True
        from django.contrib.auth import get_backends
        for backend in get_backends():
            if hasattr(backend, 'has_perm'):
                if backend.has_perm(self, perm, obj):
                    return True
        return False

    def has_perms(self, perm_list, obj=None):
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, app_label):
        if self.is_superuser:
            return True
        from django.contrib.auth import get_backends
        for backend in get_backends():
            if hasattr(backend, 'has_module_perms'):
                if backend.has_module_perms(self, app_label):
                    return True
        return False

    def __str__(self):
        return f"{self.username} ({self.email})"


class UserRole(models.Model):
    """
    Join table mapping to 'user_roles' table.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, db_column='user_id')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, db_column='role_id')

    class Meta:
        db_table = 'user_roles'
        unique_together = ('user', 'role')




class AuditLog(models.Model):
    """
    Custom AuditLog model mapping to 'audit_logs' table.
    """
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='audit_logs',
        db_column='user_id'
    )
    action = models.CharField(max_length=255)
    module = models.CharField(max_length=50, default='usermgmt')
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    browser_agent = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']

    def __str__(self):
        user_str = self.user.username if self.user else "Anonymous"
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {user_str} - {self.action}"
