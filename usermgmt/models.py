from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission

class User(AbstractUser):
    """
    TABLE 1: users (Extends Django's AbstractUser)
    Contains all foundational credentials, personal details, contact info, 
    and verification statuses for any user accessing PRAVAAH.
    
    Inherited Fields from AbstractUser:
        - id (INT, Primary Key, Auto-increment) -> Acts as user_id
        - username (VARCHAR, Unique)
        - password (VARCHAR) -> Acts as password_hash
        - first_name (VARCHAR)
        - last_name (VARCHAR)
        - is_staff (BOOLEAN)
        - is_active (BOOLEAN) -> Tracks account activation/status (Active/Inactive)
        - is_superuser (BOOLEAN)
        - date_joined (DATETIME)
    """
    # Custom attributes from registration requirements
    email = models.EmailField(unique=True, max_length=254)  # Overriding to ensure strict uniqueness
    mobile = models.CharField(max_length=15, blank=True, null=True)
    
    # Email Verification lifecycle tracking attributes
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    token_created_at = models.DateTimeField(blank=True, null=True)
    
    # Chronological timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Overriding groups and permissions relationships to avoid shared database clashes
    groups = models.ManyToManyField(
        Group,
        related_name='usermgmt_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='usermgmt_user_permissions_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user_permissions',
    )

    class Meta:
        db_table = 'users'  # Forces the database to name the table exactly 'gaurav_user'

    def __str__(self):
        return f"{self.username} ({self.email})"


class RBACPermissionProxy(Permission):
    """
    TABLE 2 & 3: roles & permissions Configuration
    Proxy model registers system scopes into core permissions engine.
    """
    class Meta:
        proxy = True
        permissions = (
            # --- Higher-Level / Administrative Capabilities ---
            ('can_view_admin_dashboard', 'Can view central security dashboard layout'),
            ('can_view_permission_matrix', 'Can view global cross-reference matrix grid'),
            ('can_modify_permissions', 'Can alter granular privileges or override tokens'),
            ('can_manage_roles', 'Can create, update, or delete system groups'),
            ('can_assign_roles', 'Can map user accounts to defined groups'),
            
            # --- Management Division Tokens ---
            ('can_view_management_reports', 'Can read high-level analytical business summaries'),
            ('can_approve_requests', 'Can authorize institutional operational overrides'),
            
            # --- Accounts / Finance Division Tokens ---
            ('can_view_finance_dashboard', 'Can read accounting ledgers and payment histories'),
            ('can_manage_finance', 'Can process invoices and update payment parameters'),
            
            # --- Quality Assurance (QA) Division Tokens ---
            ('can_view_qa_logs', 'Can read automated testing output metrics and system reports'),
            ('can_manage_qa_tickets', 'Can log, modify, or track software verification modules'),
            
            # --- Core Lower-Level Operational Read Permissions ---
            ('can_view_student_profiles', 'Can read student records and profiles (Lower Level Access)'),
            ('can_view_trainer_profiles', 'Can read trainer contact parameters (Lower Level Access)'),
            ('can_view_course_details', 'Can read syllabus blueprints and batch timings (Lower Level Access)'),
            ('can_view_hostel_status', 'Can read room vacancy layouts and allocation maps (Lower Level Access)'),
        )


class AuditLog(models.Model):
    """
    TABLE 4: audit_logs
    Tracks every structural database write, verification event, and authentication 
    state action chronologically for compliance tracking.
    """
    id = models.AutoField(primary_key=True)  # Explicit unique log entry identifier
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='audit_logs'
    )
    action = models.CharField(max_length=255)  # e.g., "User Registered", "Role Updated", "Logged Out"
    module = models.CharField(max_length=50, default='usermgmt')  # Tracks source module workspace context
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    browser_agent = models.TextField(blank=True, null=True)  # Captures client browser properties for audit logs
    timestamp = models.DateTimeField(auto_now_add=True)  # Equivalent to created_at for chronological sorting

    class Meta:
        db_table = 'audit_logs'  # Forces the database to name the table exactly 'audit_logs'
        ordering = ['-timestamp']  # Pulls latest transactional updates first by default

    def __str__(self):
        user_str = self.user.username if self.user else "Anonymous"
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {user_str} - {self.action}"