from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        from . import signals  # pylint: disable=unused-import  # noqa: F401  (imported for its side effect: V2 Phase 1 identity audit receivers)
        from . import checks  # pylint: disable=unused-import  # noqa: F401  (imported for its side effect: troubleshooting bindings / observation source deployment checks)
