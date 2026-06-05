from django import template

register = template.Library()

@register.filter(name='has_group')
def has_group(user, group_name):
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    if user.role and user.role.role_name == group_name:
        return True
    return user.roles.filter(role_name=group_name).exists()
