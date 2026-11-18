from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        from . import signals  # noqa: F401  (V2 Phase 1: identity audit receivers)
        from . import checks  # noqa: F401  (troubleshooting bindings / observation source deployment checks)
