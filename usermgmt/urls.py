from django.urls import path
from . import views  # Local views folder containing all combined views

app_name = 'usermgmt'

urlpatterns = [
    # --- Authentication & Registration Routes (Person 1) ---
    path('', views.public_landing_view, name='public_home'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('session-expired/', views.session_expired_view, name='session_expired'),
    path('verify-email/', views.verify_email_view, name='verify_email'),
    path('verify-email/<str:uidb64>/<str:token>/', views.verify_email_view, name='verify_email_confirm'),
    
    # --- Password Recovery lifecycle (Person 1) ---
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('reset-password/', views.reset_password_view, name='reset_password'),
    path('reset-password/<str:uidb64>/<str:token>/', views.reset_password_confirm, name='reset_password_confirm'),
    path('change-password/', views.change_password_view, name='change_password'),

    # --- Profile & Personal Dashboard Management (Person 2) ---
    path('dashboard/', views.home, name='user_home'),  # Remapped from '' to avoid blocking login page
    path('profile/', views.profile, name='profile'),
    path('profile/edit/', views.profile_edit, name='profile_edit'),
    path('profile/change-password/', views.change_password, name='profile_change_password'),  # Namespaced distinct form view

    # --- Auditing & Operational Logging Metrics (Person 2) ---
    path('audit-logs/', views.audit_logs, name='audit_logs'),
    path('activity-dashboard/', views.activity_dashboard, name='activity_dashboard'),

    # --- Analytical Reports Module Data (Person 2) ---
    path('reports/', views.reports, name='reports'),
    path('report-result/', views.report_result, name='report_result'),

    # --- Role Based Access Control (RBAC) Admin Framework (Person 1 & 3) ---
    path('rbac/dashboard/', views.admin_dashboard_view, name='admin_dashboard'),
    path('rbac/roles/', views.roles_list_view, name='roles_list'),
    path('rbac/roles/add/', views.role_form_view, name='role_add'),
    path('rbac/permissions/', views.permissions_list_view, name='permissions_list'),
    path('rbac/assign-role/', views.assign_role_view, name='assign_role'),
    path('rbac/assign-permissions/', views.assign_permissions_view, name='assign_permissions'),
    path('rbac/matrix/', views.permission_matrix_view, name='permission_matrix'),
    
    # --- Unified User Administration Lists (Person 2 & 3) ---
    path('users-list/', views.users_list, name='users_list'),          # Person 2 view endpoint
    path('rbac/users/', views.users_list_view, name='rbac_users_list'),
    path('test/', views.test_page, name='test'),# Person 3 admin-level list endpoint
]
