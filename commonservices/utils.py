import json
import logging
from django.conf import settings

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
    Centralized email adapter for the platform. Tries external service defined
    by settings.EMAIL_SERVICE_URL. Falls back to logging when not configured.
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
        except Exception:
            logger.exception('Failed to send email via external service')

    # fallback
    logger.info('Email fallback payload: %s', json.dumps(payload))
    return False
