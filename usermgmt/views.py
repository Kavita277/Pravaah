from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.db import transaction, IntegrityError, models
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator

from .models import User, AuditLog, Role, CustomPermission, RolePermission
from .forms import ProfileEditForm  # Ensure ProfileEditForm is defined in forms.py
from commonservices.utils import send_email, get_client_ip

# --- Internal Session Helper ---
def _redirect_if_session_expired(request):
    if not request.user.is_authenticated:
        return redirect('usermgmt:session_expired')
    return None

def _enforce_super_admin(user, permission_name=None):
    is_superadmin = user.is_superuser or (
        user.role and user.role.role_name == 'Super Admin'
    ) or user.roles.filter(role_name='Super Admin').exists()
    if is_superadmin:
        return
        
    if permission_name and user.has_perm(f"usermgmt.{permission_name}"):
        return

    from django.core.exceptions import PermissionDenied
    raise PermissionDenied("Access Denied: Super Admin or required permission required.")


def public_landing_view(request):
    # If the user is already authenticated, redirect them to their dashboard
    if request.user.is_authenticated:
        return redirect('usermgmt:user_home')
    return render(request, 'public_landing.html')


# =========================================================================
# 1. AUTHENTICATION & ACCESSIBILITY WORKFLOWS (Person 1)
# =========================================================================

def login_view(request):
    # Handle login form POST and render login template
    if request.method == 'POST':
        username_input = (request.POST.get('username') or request.POST.get('email', '')).strip()
        password = request.POST.get('password', '')
        remember = request.POST.get('remember')

       # # Simple brute-force protection per-session
       # failures = request.session.get('login_failures', {})
       # entry = failures.get(username_input, {'count': 0, 'first': None})
       # first_ts = entry.get('first')
       # if first_ts and entry.get('count', 0) >= 5 and (timezone.now().timestamp() - first_ts) < 15 * 60:
      #      messages.error(request, 'Too many failed login attempts. Try again later.')
       #     return render(request, 'auth/login.html')

        # Allow login by email: lookup username if input looks like email
        username = username_input
        if '@' in username_input:
            try:
                u = User.objects.get(email__iexact=username_input)
                username = u.username
            except User.DoesNotExist:
                username = username_input

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if not user.is_active:
                messages.error(request, 'Account inactive. Please verify your email or contact support.')
                return render(request, 'auth/login.html')
            if not user.is_superuser and not user.is_staff and not user.is_email_verified:
                messages.error(request, 'Email not verified. Please check your inbox or resend verification.')
                return render(request, 'auth/login.html')

            login(request, user)
            
            # Session expiry handling
            if remember:
                request.session.set_expiry(1209600)  # 2 weeks
            else:
                request.session.set_expiry(86400)    # 1 day (instead of browser close which drops easily)

            # Audit log
            AuditLog.objects.create(
                user=user, 
                action='Login Success', 
                ip_address=get_client_ip(request), 
                browser_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            # Reset failures
          # if username_input in failures:
          #      failures.pop(username_input)
           #     request.session['login_failures'] = failures

            # Dynamic Role-Based Redirect Gateways
            groups = list(user.roles.values_list('role_name', flat=True))
            if user.role:
                groups.append(user.role.role_name)
            if user.is_superuser or 'Super Admin' in groups or 'System Admin' in groups:
                return redirect('usermgmt:admin_dashboard')
                
            # Normal users drop cleanly onto their standard home view to prevent hitting RBAC blocks
            return redirect('usermgmt:user_home')
        else:
            # Increment failure count
            #entry['count'] = entry.get('count', 0) + 1
           # if not entry.get('first'):
           #     entry['first'] = timezone.now().timestamp()
           # failures[username_input] = entry
           # request.session['login_failures'] = failures
            
            # Audit
            AuditLog.objects.create(
                user=None, 
                action=f'Login Failed for {username_input}', 
                ip_address=get_client_ip(request), 
                browser_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            messages.error(request, 'Invalid username or password')

    return render(request, 'auth/login.html')
def register_view(request):
    if not request.user.is_authenticated:
        return redirect('usermgmt:login')
    _enforce_super_admin(request.user, 'MANAGE_USERS')

    roles = Role.objects.all()

    if request.method == 'POST':
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        mobile = request.POST.get('mobile', '').strip() or request.POST.get('mobile_number', '').strip()
        role = request.POST.get('role', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if not all([first_name, last_name, username, email, password, confirm_password]):
            messages.error(request, 'Please fill in all required fields.')
            return render(request, 'auth/register.html', {'roles': roles})

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'auth/register.html', {'roles': roles})

        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, ' '.join(e.messages))
            return render(request, 'auth/register.html', {'roles': roles})

        try:
            with transaction.atomic():
                if User.objects.filter(username=username).exists():
                    messages.error(request, 'Username already exists.')
                    return render(request, 'auth/register.html', {'roles': roles})
                if User.objects.filter(email=email).exists():
                    messages.error(request, 'Email already exists.')
                    return render(request, 'auth/register.html', {'roles': roles})

                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                )
                user.mobile = mobile
                user.is_active = True
                user.is_email_verified = True
                user.save()

                if role:
                    try:
                        grp = Role.objects.get(role_name=role)
                        user.role = grp
                        user.roles.add(grp)
                        user.save()
                    except Role.DoesNotExist:
                        pass

                AuditLog.objects.create(user=user, action='User Registered by Admin', ip_address=get_client_ip(request), browser_agent=request.META.get('HTTP_USER_AGENT', ''))
                
                messages.success(request, f"User account '{username}' successfully registered and activated!")
                return redirect('usermgmt:rbac_users_list')

        except IntegrityError:
            messages.error(request, 'A user with that username or email already exists.')
            return render(request, 'auth/register.html', {'roles': roles})

    return render(request, 'auth/register.html', {'roles': roles})


def logout_view(request):
    user = request.user if request.user.is_authenticated else None
    logout(request)
    if user:
        AuditLog.objects.create(user=user, action='Logout', ip_address=get_client_ip(request))
    messages.success(request, 'You have been logged out.')
    return redirect('usermgmt:login')


def session_expired_view(request):
    return render(request, 'auth/session_expired.html')


# =========================================================================
# 2. ACCOUNT RECOVERY LIFECYCLE MANAGEMENT (Person 1)
# =========================================================================

def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        messages.success(request, 'If an account with that email exists, a password reset link has been sent.')
        if not email:
            return render(request, 'auth/forgot_password.html')

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return render(request, 'auth/forgot_password.html')

        last = user.token_created_at
        if last and (timezone.now() - last).total_seconds() < 60:
            return render(request, 'auth/forgot_password.html')

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        user.email_verification_token = token
        user.token_created_at = timezone.now()
        user.save(update_fields=['email_verification_token', 'token_created_at'])

        reset_link = request.build_absolute_uri(reverse('usermgmt:reset_password_confirm', args=[uid, token]))
        try:
            send_email(to=user.email, subject='Reset your password', template='password_reset_link', context={'reset_link': reset_link})
            AuditLog.objects.create(user=user, action='Password Reset Requested', ip_address=get_client_ip(request))
        except Exception:
            AuditLog.objects.create(user=user, action='Password Reset Enqueue Failed', ip_address=get_client_ip(request))

        return render(request, 'auth/forgot_password.html')
    return render(request, 'auth/forgot_password.html')


def reset_password_view(request):
    messages.info(request, 'Password reset now uses a secure email link. Request a new reset link below.')
    return redirect('usermgmt:forgot_password')


def reset_password_confirm(request, uidb64=None, token=None):
    if not uidb64 or not token:
        messages.error(request, 'Invalid password reset link.')
        return redirect('usermgmt:forgot_password')
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, 'Invalid password reset link.')
        return redirect('usermgmt:forgot_password')

    if not default_token_generator.check_token(user, token):
        messages.error(request, 'Password reset link is invalid or expired. Please request a new one.')
        return redirect('usermgmt:forgot_password')

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        if not new_password or new_password != confirm_password:
            messages.error(request, 'Please provide matching passwords.')
            return render(request, 'auth/reset_password_confirm.html')
        try:
            validate_password(new_password)
        except ValidationError as e:
            messages.error(request, ' '.join(e.messages))
            return render(request, 'auth/reset_password_confirm.html')

        user.set_password(new_password)
        user.email_verification_token = ''
        user.token_created_at = None
        user.save(update_fields=['password', 'email_verification_token', 'token_created_at'])
        AuditLog.objects.create(user=user, action='Password Reset Completed', ip_address=get_client_ip(request))
        messages.success(request, 'Password reset successfully. You can now login.')
        return redirect('usermgmt:login')

    return render(request, 'auth/reset_password_confirm.html')


def change_password_view(request):
    @login_required
    def _inner(request):
        if request.method == 'POST':
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            if not request.user.check_password(current_password):
                messages.error(request, 'Current password is incorrect.')
                return render(request, 'auth/change_password.html')
            if not new_password or new_password != confirm_password:
                messages.error(request, 'Please provide matching new passwords.')
                return render(request, 'auth/change_password.html')
            try:
                validate_password(new_password, user=request.user)
            except ValidationError as e:
                messages.error(request, ' '.join(e.messages))
                return render(request, 'auth/change_password.html')

            request.user.set_password(new_password)
            request.user.save()
            AuditLog.objects.create(user=request.user, action='Password Changed', ip_address=get_client_ip(request))
            messages.success(request, 'Password changed successfully. Please login again.')
            return redirect('usermgmt:login')
        return render(request, 'auth/change_password.html')

    return _inner(request)


def verify_email_view(request, uidb64=None, token=None):
    if uidb64 and token:
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            messages.error(request, 'Invalid verification link.')
            return redirect('usermgmt:verify_email')

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.is_email_verified = True
            user.email_verification_token = ''
            user.token_created_at = None
            user.save(update_fields=['is_active', 'is_email_verified', 'email_verification_token', 'token_created_at'])
            AuditLog.objects.create(user=user, action='Email Verified', ip_address=get_client_ip(request))
            messages.success(request, 'Email verified successfully. You can now login.')
            return redirect('usermgmt:login')

        messages.error(request, 'Verification link is invalid or expired.')
        return redirect('usermgmt:verify_email')

    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            messages.error(request, 'Please provide your email to resend verification.')
            return render(request, 'auth/verify_email.html')
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            messages.error(request, 'No account found for that email.')
            return render(request, 'auth/verify_email.html')

        last = user.token_created_at
        if last and (timezone.now() - last).total_seconds() < 60:
            messages.error(request, 'Please wait before requesting another verification email.')
            return render(request, 'auth/verify_email.html')

        token = default_token_generator.make_token(user)
        user.email_verification_token = token
        user.token_created_at = timezone.now()
        user.save(update_fields=['email_verification_token', 'token_created_at'])
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verify_link = request.build_absolute_uri(reverse('usermgmt:verify_email_confirm', args=[uid, token]))
        try:
            send_email(to=user.email, subject='Verify your account', template='verify_email', context={'first_name': user.first_name, 'username': user.username, 'verify_link': verify_link})
            AuditLog.objects.create(user=user, action='Verification Email Sent (resend)', ip_address=get_client_ip(request))
            messages.success(request, 'Verification email resent. Check your inbox.')
        except Exception:
            AuditLog.objects.create(user=user, action='Verification Email Enqueue Failed (resend)', ip_address=get_client_ip(request))
            messages.error(request, 'Unable to send verification email right now.')

    return render(request, 'auth/verify_email.html')


# =========================================================================
# 3. PROFILE & PERSONAL PORTAL DASHBOARD (Person 2)
# =========================================================================

@login_required
def home(request):
    total_users = User.objects.count()
    active_users = User.objects.filter(status='Active').count()
    total_roles = Role.objects.count()
    total_audit_logs = AuditLog.objects.count()
    
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'total_roles': total_roles,
        'total_audit_logs': total_audit_logs,
    }
    return render(request, 'profile/user_dashboard.html', context)


@login_required
def profile(request):
    context = {
        'user_data': request.user
    }
    return render(request, 'profile/profile.html', context)


@login_required
def profile_edit(request):
    user = request.user
    if request.method == 'POST':
        form = ProfileEditForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            AuditLog.objects.create(
                user=user,
                action='Profile Updated',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, 'Profile updated successfully.')
            return redirect('usermgmt:profile')
    else:
        form = ProfileEditForm(instance=user)
    
    return render(request, 'profile/profile_edit.html', {'form': form})


@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            AuditLog.objects.create(
                user=request.user,
                action='Password Changed',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, 'Password changed successfully.')
            return redirect('usermgmt:profile')
    else:
        form = PasswordChangeForm(request.user)
    
    return render(request, 'profile/change_password.html', {'form': form})


# =========================================================================
# 4. AUDITING & METRIC REPORTING ENGINE (Person 2)
# =========================================================================

@login_required
def audit_logs(request):
    search = request.GET.get('search')
    logs = AuditLog.objects.all().order_by('-timestamp')  # Standardized chronological lookup key

    if search:
        logs = logs.filter(
            models.Q(action__icontains=search) |
            models.Q(user__username__icontains=search)
        )

    paginator = Paginator(logs, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'logs': page_obj,
        'page_obj': page_obj,
        'search': search
    }
    return render(request, 'audit/audit_logs.html', context)


@login_required
def reports(request):
    return render(request, 'reports/reports.html')


@login_required
def report_result(request):
    report_type = request.GET.get('report_type')
    role = request.GET.get('role')
    status = request.GET.get('status')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    login_start = request.GET.get('login_start')
    login_end = request.GET.get('login_end')
    joined_within = request.GET.get('joined_within')
    search = request.GET.get('search')

    users = User.objects.all()

    if role:
        users = users.filter(models.Q(role__role_name=role) | models.Q(roles__role_name=role)).distinct()
    
    if status == 'Active':
        users = users.filter(status='Active')
    elif status == 'Inactive':
        users = users.filter(status='Inactive')

    if start_date:
        users = users.filter(created_at__date__gte=start_date)
    if end_date:
        users = users.filter(created_at__date__lte=end_date)

    if login_start:
        users = users.filter(last_login__date__gte=login_start)
    if login_end:
        users = users.filter(last_login__date__lte=login_end)

    if joined_within and joined_within.isdigit():
        from django.utils import timezone
        import datetime
        cutoff = timezone.now() - datetime.timedelta(days=int(joined_within))
        users = users.filter(created_at__gte=cutoff)

    if search:
        users = users.filter(
            models.Q(username__icontains=search) |
            models.Q(first_name__icontains=search) |
            models.Q(last_name__icontains=search) |
            models.Q(email__icontains=search)
        )

    users_list = users.order_by('-created_at')

    counts = {
        'total': users_list.count(),
        'active': users_list.filter(status='Active').count(),
        'inactive': users_list.filter(status='Inactive').count(),
        'new': users_list.count()
    }

    context = {
        'report_type': report_type,
        'users': users_list,
        'counts': counts,
        'search': search
    }
    return render(request, 'reports/report_result.html', context)


@login_required
def users_list(request):
    _enforce_super_admin(request.user, 'MANAGE_USERS')
    users = User.objects.all().order_by('-created_at')
    search = request.GET.get('search')
    
    if search:
        users = users.filter(username__icontains=search)

    paginator = Paginator(users, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'users': page_obj,
        'page_obj': page_obj,
        'search': search
    }
    return render(request, 'rbac/users_list.html', context)


@login_required
def activity_dashboard(request):
    total_users = User.objects.count()
    total_logs = AuditLog.objects.count()
    total_roles = Role.objects.count()
    login_count = AuditLog.objects.filter(action='Login Success').count()
    recent_logs = AuditLog.objects.all().order_by('-timestamp')[:5]

    # Cleaned role mapping references
    admin_count = User.objects.filter(models.Q(role__role_name='Admin') | models.Q(roles__role_name='Admin')).distinct().count()
    manager_count = User.objects.filter(models.Q(role__role_name='Manager') | models.Q(roles__role_name='Manager')).distinct().count()
    qa_count = User.objects.filter(models.Q(role__role_name='QA') | models.Q(roles__role_name='QA')).distinct().count()

    # Active flags map natively to status conditions
    active_users = User.objects.filter(status='Active').count()
    inactive_users = User.objects.filter(status='Inactive').count()

    login_actions = AuditLog.objects.filter(action='Login Success').count()
    logout_actions = AuditLog.objects.filter(action='Logout').count()
    update_actions = AuditLog.objects.filter(action='Profile Updated').count()

    recent_registrations = User.objects.order_by('-created_at')[:5]
    failed_logins = AuditLog.objects.filter(action__icontains='Failed').count()
    
    top_role = Role.objects.annotate(total_users=models.Count('users_set') + models.Count('user_set')).order_by('-total_users').first()

    context = {
        'total_users': total_users,
        'total_logs': total_logs,
        'total_roles': total_roles,
        'login_count': login_count,
        'recent_logs': recent_logs,
        'admin_count': admin_count,
        'manager_count': manager_count,
        'qa_count': qa_count,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'login_actions': login_actions,
        'logout_actions': logout_actions,
        'update_actions': update_actions,
        'active_users_count': active_users,
        'recent_registrations': recent_registrations,
        'failed_logins': failed_logins,
        'top_role': top_role
    }
    return render(request, 'audit/activity_dashboard.html', context)


# =========================================================================
# 5. ROLE-BASED ACCESS CONTROL (RBAC) ADMIN WORKFLOWS (Person 1 & 3)
# =========================================================================

@login_required
def admin_dashboard_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'ASSIGN_ROLES')
        
    context = {
        'total_users': User.objects.count(),
        'total_roles': Role.objects.count(),
        'total_permissions': CustomPermission.objects.count(),
        'recent_logs': AuditLog.objects.all()[:5]
    }
    return render(request, 'rbac/admin_dashboard.html', context)


@login_required
def roles_list_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'ASSIGN_ROLES')
        
    roles = Role.objects.all()
    return render(request, 'rbac/roles_list.html', {'roles': roles})


@login_required
def role_form_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'ASSIGN_ROLES')
        
    if request.method == 'POST':
        role_name = request.POST.get('role_name')
        if role_name:
            Role.objects.get_or_create(role_name=role_name)
            messages.success(request, f"Role '{role_name}' successfully created!")
            return redirect('usermgmt:roles_list')
    return render(request, 'rbac/role_form.html')


@login_required
def permissions_list_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'ASSIGN_ROLES')
        
    permissions = CustomPermission.objects.all()
    return render(request, 'rbac/permissions_list.html', {'permissions': permissions})


@login_required
def assign_role_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'ASSIGN_ROLES')
        
    users = User.objects.all()
    roles = Role.objects.all()
    
    total_users = User.objects.count()
    active_users = User.objects.filter(status='Active').count()
    unassigned_users = User.objects.filter(role__isnull=True).count()
    
    role_counts = []
    for role in roles:
        count = User.objects.filter(models.Q(role=role) | models.Q(roles=role)).distinct().count()
        role_counts.append({
            'role_name': role.role_name,
            'count': count
        })
    
    selected_user_id = request.GET.get('user_id') or request.POST.get('user_id')
    selected_user = None
    user_role_name = None
    if selected_user_id:
        try:
            selected_user = User.objects.get(user_id=selected_user_id)
            user_role_name = selected_user.role.role_name if selected_user.role else (selected_user.roles.first().role_name if selected_user.roles.exists() else None)
        except User.DoesNotExist:
            pass

    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        selected_role_name = request.POST.get('role_name')
        
        if user_id and selected_role_name:
            target_user = get_object_or_404(User, user_id=user_id)
            target_user.roles.clear() 
            assigned_group = Role.objects.get(role_name=selected_role_name)
            target_user.role = assigned_group
            target_user.roles.add(assigned_group)
            target_user.save()
            
            messages.success(request, f"Successfully assigned role '{selected_role_name}' to {target_user.username}!")
            return redirect(reverse('usermgmt:assign_role') + f'?user_id={user_id}')
        
    context = {
        'users': users,
        'roles': roles,
        'selected_user': selected_user,
        'user_role_name': user_role_name,
        'total_users': total_users,
        'active_users': active_users,
        'unassigned_users': unassigned_users,
        'role_counts': role_counts,
    }
    return render(request, 'rbac/assign_role.html', context)


@login_required
def assign_permissions_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'ASSIGN_ROLES')
        
    roles = Role.objects.all()
    permissions = CustomPermission.objects.all()
    
    selected_role_id = request.GET.get('role_id') or request.POST.get('role_id')
    selected_role = None
    if selected_role_id:
        try:
            selected_role = Role.objects.get(role_id=selected_role_id)
        except Role.DoesNotExist:
            pass

    if request.method == 'POST':
        role_id = request.POST.get('role_id')
        selected_permissions = request.POST.getlist('permissions')
        if role_id:
            try:
                role = Role.objects.get(role_id=role_id)
                perms = CustomPermission.objects.filter(permission_id__in=selected_permissions)
                role.permissions.set(perms)
                messages.success(request, f"Permissions updated successfully for role '{role.role_name}'!")
            except Role.DoesNotExist:
                messages.error(request, "Selected role does not exist.")
            return redirect(reverse('usermgmt:assign_permissions') + f'?role_id={role_id}')

    context = {
        'roles': roles,
        'permissions': permissions,
        'selected_role': selected_role,
    }
    return render(request, 'rbac/assign_permissions.html', context)


@login_required
def permission_matrix_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'ASSIGN_ROLES')
        
    roles = Role.objects.all()
    permissions = CustomPermission.objects.all()
    
    if request.method == 'POST':
        selected_pairings = request.POST.getlist('matrix_relations')
        matrix_map = {role.role_id: [] for role in roles}
        
        for pairing in selected_pairings:
            if "_" in pairing:
                role_id_str, perm_id_str = pairing.split("_")
                r_id = int(role_id_str)
                p_id = int(perm_id_str)
                if r_id in matrix_map:
                    matrix_map[r_id].append(p_id)
        
        for role in roles:
            perms_to_set = CustomPermission.objects.filter(permission_id__in=matrix_map[role.role_id])
            role.permissions.set(perms_to_set)
            
        messages.success(request, "Global Permission Matrix updated successfully!")
        return redirect('usermgmt:permission_matrix')

    total_roles = roles.count()
    total_permissions = permissions.count()
    total_mappings = RolePermission.objects.count()

    context = {
        'roles': roles,
        'permissions': permissions,
        'total_roles': total_roles,
        'total_permissions': total_permissions,
        'total_mappings': total_mappings,
    }
    return render(request, 'rbac/permission_matrix.html', context)


@login_required
def users_list_view(request):
    redirect_response = _redirect_if_session_expired(request)
    if redirect_response:
        return redirect_response
    _enforce_super_admin(request.user, 'MANAGE_USERS')
        
    selected_role_id = request.GET.get('role')
    roles = Role.objects.all()
    users = User.objects.all()
    
    if selected_role_id:
        users = users.filter(models.Q(role__role_id=selected_role_id) | models.Q(roles__role_id=selected_role_id)).distinct()
        
    context = {
        'users': users,
        'roles': roles,
        'selected_role': int(selected_role_id) if selected_role_id and selected_role_id.isdigit() else None
    }
    return render(request, 'rbac/users_list.html', context)
from django.shortcuts import render

@login_required
def participant_management_view(request):
    return render(request, 'module_placeholder.html', {
        'module_name': 'Participant Management',
        'module_icon': 'fa-solid fa-users'
    })

@login_required
def master_trainer_management_view(request):
    return render(request, 'module_placeholder.html', {
        'module_name': 'Master Trainer Management',
        'module_icon': 'fa-solid fa-user-tie'
    })

@login_required
def course_management_view(request):
    return render(request, 'module_placeholder.html', {
        'module_name': 'Course Management',
        'module_icon': 'fa-solid fa-book'
    })

@login_required
def hostel_management_view(request):
    return render(request, 'module_placeholder.html', {
        'module_name': 'Hostel Management',
        'module_icon': 'fa-solid fa-hotel'
    })

@login_required
def gate_approval_view(request):
    return render(request, 'prelaunch/getApproval.html')