import json
import logging
from django.conf import settings
from .models import AuditLog, User

logger = logging.getLogger(__name__)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def send_email(to, subject, template, context):
    """
    Minimal email adapter stub.
    Tries to POST to external service defined by EMAIL_SERVICE_URL in settings.
    If not configured or requests is unavailable, falls back to logging the payload
    and creating an AuditLog entry so the email team can pick it up.
    """
    payload = {
        'to': to,
        'subject': subject,
        'template': template,
        'context': context,
    }

    url = getattr(settings, 'EMAIL_SERVICE_URL', None)
    api_key = getattr(settings, 'EMAIL_SERVICE_API_KEY', None)

    if url:
        try:
            import requests
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            resp = requests.post(url, json=payload, headers=headers, timeout=5)
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.exception('Failed to send email via EMAIL_SERVICE_URL')

    # fallback: log and create an AuditLog record so ops can see pending email
    logger.info('Email payload (fallback): %s', json.dumps(payload))
    try:
        AuditLog.objects.create(user=None, action=f'EmailQueued for {to}', module='usermgmt', browser_agent=json.dumps(payload))
    except Exception:
        logger.exception('Failed to persist EmailQueued audit')
    return False
