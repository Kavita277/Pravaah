# Pravaah ERP - Technical Documentation
## User Management & Role-Based Access Control (RBAC) System

This document outlines the architecture, implementation details, and features of the **Pravaah ERP User Management & RBAC Module**.

---

## 1. System Architecture & Database Schema

The application is built on top of the **Django Web Framework** using a custom schema mapped to a MySQL/SQLite database. Rather than relying solely on default Django Group/User tables, the system uses custom, optimized database tables mapped to Django models using an advanced custom authentication backend and database-level foreign keys.

### Core Database Entities (from [final_schema.sql](file:///c:/Users/Kavita/Desktop/Pravaah_Final/final_schema.sql)):
1. **`permissions` (`CustomPermission` model)**:
   - Manages individual action-based permission nodes (e.g., `MANAGE_USERS`, `ASSIGN_ROLES`, `CREATE_PROGRAMME`).
2. **`roles` (`Role` model)**:
   - Defines system roles (e.g., `Super Admin`, `Training Manager`, `Hostel Admin`, `QA`, etc.).
3. **`users` (`User` model)**:
   - Inherits from `AbstractBaseUser`. Supports email-as-username login, mobile verification status, active status indicators, and email verification workflows.
4. **`role_permissions` & `user_roles` (Join Tables)**:
   - Implements multi-role inheritance, allowing users to inherit permissions from multiple roles simultaneously.
5. **`audit_logs` (`AuditLog` model)**:
   - Records every sensitive transaction, capturing user IDs, descriptive actions, target modules, client IP addresses, browser agents, and timestamps.

---

## 2. Core Features: What Was Achieved & How

### A. User Registration & Onboarding
- **How it works**: Implemented in [views.register_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L132-L202). Restricted to administrators with the `MANAGE_USERS` permission.
- **Safety controls**: Employs Django `transaction.atomic` database transactions to prevent partial/corrupt user creation. Enforces password complexity rules using standard Django `validate_password` rules.

### B. Dynamic Roles & Permissions Administration
- **How it works**: Roles and permission lists are rendered dynamically from the database.
- **Management actions**: Admins can add roles dynamically via [role_form_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L647-L660) and view all permissions via [permissions_list_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L663-L671).

### C. Enterprise Authentication System
- **How it works**: Located in [views.login_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L51-L131) and [views.logout_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L205-L211).
- **Multi-Identifier Login**: Allows users to log in using either their `username` or their `email`. The system dynamically detects `@` signs and queries the user repository accordingly.
- **Auditing**: Captures both successful logins and failed logins in the database audit log.

### D. User Profile & Password Management
- **How it works**: Logged-in users can update their profile information (first name, last name, mobile) via [profile_edit](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L410-L427).
- **Password Updates**: Users can update their password via [change_password](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L431-L448), using standard Django forms which re-hash active session tokens (`update_session_auth_hash`) so that users are not forced to log in again immediately.

### E. Database Auditing & Logging
- **How it works**: Accessible through [views.audit_logs](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L454-L474).
- **Capabilities**: Captures IP address, user-agent signatures, action descriptions, and timestamps. Supports server-side search querying and 10-item pagination for page speed.

### F. Analytical Reports Engine
- **How it works**: Configured in [views.reports](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L478-L480) and [views.report_result](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L483-L543).
- **Capabilities**: Generates tabular datasets filtering by enterprise roles, active status flags, account creation dates, last-login date ranges, search strings, or registration latency (e.g. joined within the last X days). Computes real-time cohort counts (total, active, inactive, new).

---

## 3. New Advanced Features (Beyond Core Requirements)

Beyond basic CRUD and logging, the system includes several enterprise-grade security and usability enhancements:

### 1. Global Permission Matrix Editor
- **Files**: [permission_matrix_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L773-L812) and [permission_matrix.html](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/templates/rbac/permission_matrix.html).
- **Feature**: Provides an advanced, grid-based administrative layout mapping all system roles against all permissions. Admins can update system-wide role permissions in bulk via a single check-grid rather than editing roles one-by-one. It shows key indicators like *Total Roles*, *Total Permissions*, and *Active Permission Mappings*.

### 2. Custom Hybrid Authentication & Inheritance Backend
- **Files**: [CustomRoleBackend](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/backends.py#L4-L50).
- **Feature**: Extends standard Django security check patterns (`request.user.has_perm`) to fit the custom SQL role structure.
- **Inheritance Logic**: Checks direct role relations (one-to-many field `role` on the user) AND handles many-to-many memberships (via the `user_roles` join table). Active permissions are merged dynamically at runtime, allowing users to inherit permissions from multiple roles simultaneously while remaining compatible with built-in Django decorators (e.g., `@permission_required`).

### 3. Automated RBAC Middleware Gatekeeper
- **Files**: [RoleBasedAccessControlMiddleware](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/middleware.py#L5-L86).
- **Feature**: Intercepts requests globally. Handles:
  1. **Public Route Whitelisting**: Automatically bypasses login requirements for public pages (e.g., login, password recovery, email verification, and session timeout notifications).
  2. **URL-to-Permission Mapping**: Automatically maps named routes (e.g., `roles_list` or `reports`) to custom permissions (like `ASSIGN_ROLES` or `GENERATE_REPORTS`).
  3. **Super Admin Bypass**: Instantly permits users marked as superusers or belonging to the `Super Admin` group to skip RBAC checks.
  4. **Access Restraints**: Blocks unauthorized actions, pushes clear error notifications to the user interface, and redirects users to a safe dashboard page.

### 4. Self-Service Email Verification & Password Recovery Lifecycle
- **Files**: [forgot_password_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L222-L252), [reset_password_confirm](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L260-L295), and [verify_email_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L327-L380).
- **Security features**:
  - Uses cryptographic tokens (`default_token_generator`) and base64-encoded user IDs (`uidb64`) in verification/reset URLs.
  - Implements temporal rate-limiting (restricting confirmation requests to one request every 60 seconds using `token_created_at` timestamp).

### 5. Resilient Email Dispatch Adapter
- **Files**: [usermgmt/utils.py](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/utils.py#L16-L52) and [commonservices/utils.py](file:///c:/Users/Kavita/Desktop/Pravaah_Final/commonservices/utils.py#L15-L42).
- **Feature**: Ensures system stability by attempting to dispatch notification emails to an external API (defined by `EMAIL_SERVICE_URL` and `EMAIL_SERVICE_API_KEY`). If the service is unreachable or unconfigured, the system executes an automated fallback: it logs the email payload and posts an `EmailQueued` audit log entry so operations/background workers can process it.

### 6. Interactive Activity Metrics Dashboard
- **Files**: [activity_dashboard](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L568-L612) and [activity_dashboard.html](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/templates/audit/activity_dashboard.html).
- **Feature**: Aggregates usage data into a clean dashboard:
  - System metrics (Total Users, Active/Inactive counts, Total Roles, Audit Logs length).
  - Role demographics (Admin, Manager, QA user distributions).
  - Authentication metrics (Success vs Failed logins).
  - Chronological lists of recent user registrations and recent audit activity.
  - Identifies the most populated system role dynamically (`top_role`) using Django `annotate` aggregation.

### 7. Custom Database Seeding Script
- **Files**: [seed_db.py](file:///c:/Users/Kavita/Desktop/Pravaah_Final/seed_db.py).
- **Feature**: A synchronization utility that initializes:
  - 16 custom system permissions.
  - 8 core enterprise roles.
  - Custom permission-to-role mappings.
  - 8 active test accounts with pre-assigned roles (Super Admin, Hostel Admin, Training Manager, Participant, etc.) and pre-hashed credentials.
  - Ideal for local test setups and clean system deployments.

### 8. Programme Gate Approval Checklist Framework
- **Files**: [gate_approval_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L866-L867) and [getApproval.html](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/templates/prelaunch/getApproval.html).
- **Feature**: Implements a massive checkpoint matrix covering all training milestones:
  - *Need Identification, Technical Proposal, Client Acceptance, Prescreening, Session Plans, Assessments, Invoicing, Professional Fees, challenges & mitigation.*
  - Supports remarks, completion status dropdowns, attendee logs, preparers, approvers, and provisional vs final check flags.

### 9. Graceful Module Placeholders
- **Files**: [participant_management_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L838-L842), [master_trainer_management_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L845-L849), [course_management_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L852-L856), [hostel_management_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L859-L863), [main_dashboard_view](file:///c:/Users/Kavita/Desktop/Pravaah_Final/usermgmt/views.py#L870-L874).
- **Feature**: Maps core operational links to placeholder modules dynamically featuring custom FontAwesome icons (e.g. `fa-hotel`, `fa-users`, `fa-book`), allowing pre-launch testing and demonstration without encountering broken links or 404 page-not-found errors.
