from typing import List, Any
from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from accounts.views import HealthCheckView

schema_view = get_schema_view(
    openapi.Info(
        title="Auth Service API",
        default_version='v1',
        description="User Authentication Service with JWT, PostgreSQL, and Redis",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@authservice.local"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns: List[Any] = [
    path('admin/', admin.site.urls),

    path('health/', HealthCheckView.as_view(), name='health_check'),

    path('api/v1/auth/', include('accounts.urls')),

    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]
