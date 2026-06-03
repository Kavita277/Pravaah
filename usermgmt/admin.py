from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, AuditLog

# =========================================================================
# 1. CUSTOM USER MODEL REGISTRATION
# =========================================================================
@admin.register(User)
class CustomUserAdmin(UserAdmin):
    model = User
    
    # Display these primary columns explicitly in the admin data row list view
    list_display = ['username', 'email', 'is_staff', 'is_superuser', 'is_active', 'is_email_verified']
    
    # Add filters to the sidebar to make user administration faster
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'is_email_verified']
    
    # Configure the form sections when expanding/editing an individual user profile
    fieldsets = UserAdmin.fieldsets + (
        ('Custom Profile Flags', {
            'fields': (
                ['mobile', 'is_email_verified', 'email_verification_token', 'token_created_at']
            )
        }),
    )


# =========================================================================
# 2. CENTRAL SYSTEM AUDIT LOG REGISTRATION
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
