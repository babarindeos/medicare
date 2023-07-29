from django.contrib import admin
from .models import HealthProvider, HealthWorker, Role, Patient, SharedAccess, UserKey

# Register your models here.
admin.site.register(HealthProvider)
admin.site.register(HealthWorker)
admin.site.register(Role)
admin.site.register(Patient)
admin.site.register(SharedAccess)
admin.site.register(UserKey)
