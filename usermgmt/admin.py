from django.contrib import admin
from .models import User, AuditLog, Role

# =========================================================================
# 1. CUSTOM USER MODEL REGISTRATION
# =========================================================================
@admin.register(User)
class CustomUserAdmin(admin.ModelAdmin):
    model = User
    
    # Display these primary columns explicitly in the admin data row list view
    list_display = ['username', 'email', 'is_staff', 'is_superuser', 'status', 'is_email_verified']
    
    # Add filters to the sidebar to make user administration faster
    list_filter = ['is_staff', 'is_superuser', 'status', 'is_email_verified']
    
    # Enable search for key user identification fields
    search_fields = ['username', 'email', 'first_name', 'last_name', 'mobile']

    # Configure the form sections when expanding/editing an individual user profile
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'mobile')}),
        ('Role & Status', {'fields': ('role', 'status', 'is_staff', 'is_superuser')}),
        ('Verification Flags', {'fields': ('is_email_verified', 'email_verification_token', 'token_created_at')}),
    )


# =========================================================================
# 2. CUSTOM ROLE MODEL REGISTRATION
# =========================================================================
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['role_id', 'role_name', 'is_active']
    list_filter = ['is_active']
    search_fields = ['role_name', 'description']


# =========================================================================
# 3. CENTRAL SYSTEM AUDIT LOG REGISTRATION
# =========================================================================
@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    # Columns shown on the global operational data table layout grid
    list_display = ['id', 'user', 'action', 'module', 'ip_address', 'timestamp']
    
    # Sidebar quick filters to isolate specific security logs
    list_filter = ['module', 'timestamp', 'action']
    
    # Global search query text targets (looks up related user accounts dynamically)
    search_fields = ['user__username', 'action', 'ip_address', 'module']
    
    # Ensure logs display chronologically with the latest records up top
    ordering = ['-timestamp']
    
    # Make log items read-only to prevent tampering with historical audit data
    readonly_fields = ['id', 'user', 'action', 'module', 'ip_address', 'browser_agent', 'timestamp']

