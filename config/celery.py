import os
from django.apps import apps, AppConfig
from django.conf import settings
from celery import Celery

if not settings.configured:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', "config.settings.") 

APP = Celery('celery')


class CeleryConfig(AppConfig):
    name = 'celery'
    verbose_name = 'Celery Config'

    def ready(self):
        APP.config_from_object('django.conf:settings', namespace='CELERY')
        installed_apps = [app_config.name for app_config in apps.get_app_configs()]
        APP.autodiscover_tasks(installed_apps, force=True)

    def tearDown(self):
        pass