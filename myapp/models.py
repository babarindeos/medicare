from datetime import datetime
from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class HealthProvider(models.Model):
    name = models.CharField(max_length=500)
    type = models.CharField(max_length=500)
    address = models.CharField(max_length=1000)
    email = models.CharField(max_length=100)
    username = models.CharField(max_length=50)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user')
    date = models.DateTimeField(default=datetime.now, blank=True)


class HealthWorker(models.Model):
    healthprovider = models.ForeignKey(HealthProvider, on_delete=models.CASCADE, related_name='hcp_worker')
    staffno = models.CharField(max_length=50)
    firstname = models.CharField(max_length=50, blank=True)
    lastname = models.CharField(max_length=50, blank=True)
    role = models.CharField(max_length=200)
    experience = models.CharField(max_length=5)
    phone = models.CharField(max_length=50)
    email = models.CharField(max_length=200)
    picture = models.CharField(max_length=200)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='hw_user')
    date = models.DateTimeField(default=datetime.now, blank=True)


class Role(models.Model):
    name = models.CharField(max_length=100)
    date = models.DateTimeField(default=datetime.now, blank=True)



class Patient(models.Model):
    healthprovider = models.ForeignKey(HealthProvider, on_delete=models.CASCADE, related_name='hcp_patient')
    recordno = models.CharField(max_length=100)
    firstname = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    gender = models.CharField(max_length=20)
    dob = models.CharField(max_length=100, blank= True)
    nhis = models.CharField(max_length=50, blank=True)
    phone = models.CharField(max_length=50)
    email = models.CharField(max_length=100)
    picture = models.CharField(max_length=300)
    address = models.CharField(max_length=300)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='pt_user')
    date = models.DateTimeField(default=datetime.now, blank=True)


class SharedAccess(models.Model):
     identifier = models.CharField(max_length=10)
     healthworker = models.ForeignKey(HealthWorker, on_delete=models.CASCADE, related_name='sa_healthworker')
     patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='sa_patient')
     type = models.CharField(max_length=50)
     owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sa_owner')
     owner_healthprovider = models.ForeignKey(HealthProvider, on_delete=models.CASCADE, related_name='sa_healthprovider')
     owner_publickey = models.CharField(max_length=255)
     owner_privatekey = models.CharField(max_length=255)
     recipient = models.CharField(max_length=255)
     recipient_publickey = models.CharField(max_length=255)
     recipient_privatekey = models.CharField(max_length=255)
     isverified = models.BooleanField()
     date = models.DateTimeField(default=datetime.now, blank=True)


class UserKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='userkey')
    public_key = models.CharField(max_length=1000, blank=True)
    private_key = models.CharField(max_length=2000)


    
