"""URL configuration for the clab_dualstack_lab Phase 3 UI foundation."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
]
