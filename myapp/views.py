from django.db.models import Q
import json
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import HealthProvider, HealthWorker, Patient, Role, SharedAccess, UserKey


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Create your views here.
def index(request):
    return render(request, 'index.html')


def kmc_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            if user.is_staff:
                auth.login(request, user)
                return redirect('kmc_home')
            else:
                messages.info(request, 'Invalid Credentials')
                return redirect('kmc_login')
        else:
            messages.info(request, 'Invalid Credentials')
            return redirect('kmc_login')
    else:       

        return render(request, 'kmc/kmc_login.html')


@login_required
def kmc_home(request):
    healthProviders_count = len(HealthProvider.objects.all())
    healthWorkers_count = len(HealthWorker.objects.all())
    
    context = {
        'healthProviderCount' : healthProviders_count,
        'healthWorkerCount' : healthWorkers_count
    }
    return render(request, 'kmc/kmc_home.html', context)

@login_required
def kmc_healthcare_provider(request):
    healthProviders = HealthProvider.objects.all()

    healthProviders_count = len(healthProviders)
      

    return render(request, 'kmc/kmc_healthcare_provider.html', {'healthProviders': healthProviders, 'count' : healthProviders_count})

@login_required
def kmc_healthcare_provider_create(request):
    if request.method == 'POST':
        name = request.POST['name']
        type = request.POST['type']
        address = request.POST['address']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']

        #check if a username exist
        if User.objects.filter(username=username).exists():
            messages.info(request, "Sorry, an Health Provider already exist with the Administrator's username")
            return redirect('kmc_healthcare_provider_create')
        elif User.objects.filter(email=email).exists():
            messages.info(request, "Sorry, an Health Provider with that email already exist. Duplicate emails are not allowed.")
            return redirect('kmc_healthcare_provider_create')
        else:            
            user = User.objects.create_user(username=username, email=email, first_name=name, last_name=type, password=password)
            user.save()

            healthProvider = HealthProvider.objects.create(name=name, type=type, address=address, email=email, username=username, user=user)
            healthProvider.save()

            return redirect('kmc_healthcare_provider')
        
    else:
        return render(request, 'kmc/kmc_healthcare_provider_create.html')
    
@login_required
def kmc_health_worker(request):
    health_workers = HealthWorker.objects.all();
    health_workers_count = len(health_workers)
    return render(request, 'kmc/kmc_health_worker.html', {'healthWorkers': health_workers, 'count': health_workers_count})

@login_required
def kmc_patient(request):
    return render(request, 'kmc/kmc_patient.html')

@login_required
def kmc_medical_record(request):
    return render(request, 'kmc/kmc_medical_record.html')

@login_required
def kmc_blockchain(request):
    return render(request, 'kmc/kmc_blockchain.html')

@login_required
def kmc_smartcontract(request):
    return render(request, 'kmc/kmc_smartcontract.html')

@login_required
def kmc_myaccount(request):
    return render(request, 'kmc/kmc_myaccount.html')

@login_required
def kmc_healthcare_provider_edit(request, id):

    if HealthProvider.objects.filter(id=id).exists():
        health_provider = HealthProvider.objects.get(id=id)
    else:
        return redirect('kmc_healthcare_provider')
    
    if request.method == "POST":
        name = request.POST['name']
        type = request.POST['type']
        address = request.POST['address']
        email = request.POST['email']

        health_provider.name = name
        health_provider.type = type
        health_provider.address = address
        health_provider.email = email

        health_provider.save() 

        return redirect('kmc_healthcare_provider')       
    else:        
        return render(request, 'kmc/kmc_healthcare_provider_edit.html', {'health_provider': health_provider})


def hcp_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        if HealthProvider.objects.filter(username=username).exists():
             user  = auth.authenticate(username=username, password=password)
             if user is not None:
                health_provider = HealthProvider.objects.get(username=username)
                request.session['health_provider_name'] = health_provider.name
                request.session['loggedin_health_provider_id'] = health_provider.id              

                auth.login(request, user)
                return redirect('hcp_home')
             else:
                messages.info(request, 'Invalid Credentials')
                return redirect('hcp_login')
        else:
                messages.info(request, 'Invalid Credentials')
    else:
        return render(request, 'hcp/hcp_login.html')

@login_required
def hcp_home(request):
    health_provider_id = request.session.get('loggedin_health_provider_id')
    if health_provider_id is not None:
        health_provider = HealthProvider.objects.get(id=health_provider_id)        
        healthWorker = HealthWorker.objects.filter(healthprovider=health_provider)
        healthWorker_count = healthWorker.count()

        context = {
            'healthWorkerCount' : healthWorker_count
        }
        return render(request, 'hcp/hcp_home.html', context)
    else:
        return redirect('hcp_login')
    

@login_required
def hcp_health_worker(request):

    health_provider_id = request.session.get('loggedin_health_provider_id')
    if health_provider_id is not None:
        health_provider = HealthProvider.objects.get(id=health_provider_id)
        health_workers = HealthWorker.objects.filter(healthprovider=health_provider)
        
        health_workers_count = len(health_workers)
        return render(request, 'hcp/hcp_health_worker.html', {'healthWorkers' : health_workers, 'count' : health_workers_count})
    else:
        return redirect('hcp_login')   
    
    

    

@login_required
def hcp_health_worker_create(request):   
    if request.method=='POST':
        staffno = request.POST['staffno']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        role = request.POST['role']
        experience = request.POST['experience']
        phone = request.POST['phone']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']
        
        
        #check if user already exist
        if User.objects.filter(username=username).exists():
            messages.info(request, 'Access username already exist. Duplicate usernames are not allowed')
            return redirect('hcp_health_worker_create')
        elif HealthWorker.objects.filter(staffno=staffno).exists():
            messages.info(request, 'An Staff with that Staff No. already exist. Duplicate Staff No are not allowed')
            return redirect('hcp_health_worker_create')
        else:
            user = User.objects.create_user(username=username, email=email, first_name=firstname, 
                                            last_name=lastname, password=password)
            user.save()

            health_provider = HealthProvider.objects.get(id= request.session.get('loggedin_health_provider_id'))
            health_worker = HealthWorker.objects.create(healthprovider=health_provider, staffno=staffno,firstname=firstname, 
                                                        lastname=lastname, role=role, 
                                                        experience=experience, phone=phone, email=email, user=user)
            health_worker.save()

            return redirect('hcp_health_worker')

    else:
        roles = Role.objects.all()
        return render(request, 'hcp/hcp_health_worker_create.html', {'roles' : roles})


@login_required
def hcp_health_worker_edit(request, id):
    if HealthWorker.objects.filter(id=id).exists():
        health_worker = HealthWorker.objects.get(id=id)
        roles = Role.objects.all()
        context = {
            'healthWorker' : health_worker,
            'roles' : roles
        }
        return render(request, 'hcp/hcp_health_worker_edit.html', context)
    else:
        return redirect('hcp_health_worker')

@login_required
def hcp_health_worker_update(request, id):
    if request.method == 'POST':
        staffno = request.POST['staffno']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        role = request.POST['role']
        experience = request.POST['experience']
        phone = request.POST['phone']
        email = request.POST['email']

        health_worker = HealthWorker.objects.get(id=id)

        health_worker.staffno = staffno
        health_worker.firstname = firstname
        health_worker.lastname = lastname
        health_worker.role = role
        health_worker.experience = experience
        health_worker.phone = phone
        health_worker.email = email

        health_worker.save()
    
    return redirect('hcp_health_worker')


def hcp_health_worker_delete(request, id):
    if HealthWorker.objects.filter(id=id).exists():
        health_worker = HealthWorker.objects.get(id=id)        
        health_worker.delete()

        return redirect('hcp_health_worker')
    else:
        return redirect('hcp_health_worker')


@login_required
def hcp_patient(request):
    return render(request, 'hcp/hcp_patient.html')

@login_required
def hcp_medical_record(request):
    return render(request, 'hcp/hcp_medical_record.html')

@login_required
def hcp_settings(request):
    return render(request, 'hcp/hcp_settings.html')



def hw_login(request):
    if request.method=='POST':
        username = request.POST['username']
        password = request.POST['password']

        if User.objects.filter(username=username).exists():
            user_data = User.objects.get(username=username)
            if HealthWorker.objects.filter(user=user_data):
                 user = auth.authenticate(username=username, password=password)
                 
                 if user is not None:
                        healthworker = HealthWorker.objects.get(user=user_data)
                        request.session['healthprovider_id'] = healthworker.healthprovider.id
                        request.session['healthprovider_name'] = healthworker.healthprovider.name
                        request.session['role'] = healthworker.role
                        auth.login(request, user)
                        return redirect('hw_home')   
                 else:
                     messages.info(request, 'Invalid Credentials')
                     return redirect('hw_login')
                 
            else:
                messages.info(request, 'Invalid Credentials')
                return redirect('hw_login')

        else:
            messages.info(request, 'Invalid Credentials')
            return redirect('hw_login')
            
    else:
        return render(request, 'hw/hw_login.html')
    
@login_required
def hw_home(request):    
    return render(request,'hw/hw_home.html')


@login_required
def hw_healthworker(request):
     health_provider_id = request.session.get('healthprovider_id')
     if health_provider_id is not None:
        health_provider = HealthProvider.objects.get(id=health_provider_id)
        health_workers = HealthWorker.objects.filter(healthprovider=health_provider)
        
        health_workers_count = len(health_workers)
        return render(request, 'hw/hw_healthworker.html', {'healthWorkers' : health_workers, 'count' : health_workers_count})
     else:
        return redirect('hw_healthworker')   
    

@login_required
def hw_healthworker_create(request):    
    if request.method=='POST':
        staffno = request.POST['staffno']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        role = request.POST['role']
        experience = request.POST['experience']
        phone = request.POST['phone']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']        
        
        
        #check if user already exist
        if User.objects.filter(username=username).exists():
            messages.info(request, 'Access username already exist. Duplicate usernames are not allowed')
            return redirect('hw_healthworker_create')
        elif HealthWorker.objects.filter(staffno=staffno).exists():
            messages.info(request, 'An Staff with that Staff No. already exist. Duplicate Staff No are not allowed')
            return redirect('hw_healthworker_create')
        else:
            user = User.objects.create_user(username=username, email=email, first_name=firstname, 
                                            last_name=lastname, password=password)
            user.save()

            health_provider = HealthProvider.objects.get(id= request.session.get('healthprovider_id'))
            health_worker = HealthWorker.objects.create(healthprovider=health_provider, staffno=staffno,firstname=firstname, 
                                                        lastname=lastname, role=role, 
                                                        experience=experience, phone=phone, email=email, user=user)
            health_worker.save()

            return redirect('hw_healthworker')

    else:
        roles = Role.objects.all()
        return render(request, 'hw/hw_healthworker_create.html', {'roles' : roles})



def hw_healthworker_edit(request, id):
    if HealthWorker.objects.filter(id=id).exists():
        health_worker = HealthWorker.objects.get(id=id)
        roles = Role.objects.all()
        context = {
            'healthWorker' : health_worker,
            'roles' : roles
        }
        return render(request, 'hw/hw_healthworker_edit.html', context)
    else:
        return redirect('hw_healthworker')


def hw_healthworker_update(request, id):
    if request.method == 'POST':
        staffno = request.POST['staffno']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        role = request.POST['role']
        experience = request.POST['experience']
        phone = request.POST['phone']
        email = request.POST['email']

        health_worker = HealthWorker.objects.get(id=id)

        health_worker.staffno = staffno
        health_worker.firstname = firstname
        health_worker.lastname = lastname
        health_worker.role = role
        health_worker.experience = experience
        health_worker.phone = phone
        health_worker.email = email

        health_worker.save()
    
    return redirect('hw_healthworker')



def hw_patient(request):
    health_provider_id = request.session.get('healthprovider_id')
    if health_provider_id is not None:
        health_provider = HealthProvider.objects.get(id=health_provider_id)
        patients = Patient.objects.filter(healthprovider=health_provider)
        
        patient_count = len(patients)
        return render(request, 'hw/hw_patient.html', {'patients' : patients, 'count' : patient_count})
    else:
        return redirect('hw/hw_patient.html')


def hw_patient_create(request):
    if request.method == 'POST':
        fileno = request.POST['fileno']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        gender = request.POST['gender']
        dob = request.POST['dob']
        phone = request.POST['phone']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']


        #check if user already exist
        if User.objects.filter(username=username).exists():
            messages.info(request, 'Access username already exist. Duplicate usernames are not allowed')
            return redirect('hw_patient_create')
        elif Patient.objects.filter(recordno=fileno).exists():
            messages.info(request, 'An Patient with that File No. already exist. Duplicate File No are not allowed')
            return redirect('hw_patient_create')
        else:
            user = User.objects.create_user(username=username, email=email, first_name=firstname, 
                                            last_name=lastname, password=password)
            user.save()

            health_provider = HealthProvider.objects.get(id= request.session.get('healthprovider_id'))
            patient = Patient.objects.create(healthprovider=health_provider, recordno=fileno, firstname=firstname, 
                                                        lastname=lastname, gender=gender, dob=dob,
                                                        phone=phone, email=email, user=user)
            patient.save()

            return redirect('hw_patient')

    else:    
        return render(request, 'hw/hw_patient_create.html')


def hw_patient_edit(request, id):
    patient = Patient.objects.get(id=id)
    if patient is not None:
        return render(request, 'hw/hw_patient_edit.html', {'patient':patient})
    else:
        return HttpResponse('Not Found')
    


def hw_patient_update(request, id):
    return HttpResponse(id)

def hw_medical_record(request):
    pass    


def hw_internal_medical_access(request):
    myHealthProvider = HealthProvider.objects.get(id= request.session['healthprovider_id']) 
    

    ##sharedAccess = SharedAccess.objects.all()
    ##sharedAccess_list = []
        
    #for shared in sharedAccess:
        #sharedAccess_list.append(shared)

    sharedaccess = SharedAccess.objects.filter(owner_healthprovider=request.session['healthprovider_id'])
    healthworkers = HealthWorker.objects.filter(Q(role='Doctor') | Q(role='Nurse'), healthprovider=myHealthProvider)
    patients = Patient.objects.filter(healthprovider=myHealthProvider)
    
    context = {
        'sharedaccess' : sharedaccess,
        'healthworkers' : healthworkers,
        'patients' : patients
    }

    return render(request, 'hw/hw_internal_medical.html', context)



def hw_create_internal_shared_access(request):
    
    healthworker_id = request.POST['healthworker']
    patient_id = request.POST['patient']

    healthworker = HealthWorker.objects.get(id=healthworker_id)
    patient = Patient.objects.get(id=patient_id)


    identifier = healthworker_id + patient_id


    if SharedAccess.objects.filter(identifier=identifier).exists():
        messages.info(request, 'That access has already been granted')
        return redirect('hw_internal_medical_access')
    else:
        user = request.user       
        type = 'internal'
        owner_healthprovider = HealthProvider.objects.get(id=request.session['healthprovider_id'])
        shared_access = SharedAccess.objects.create(identifier=identifier, healthworker=healthworker,
                                                    patient=patient, type=type, owner=user,
                                                    owner_healthprovider = owner_healthprovider)
        shared_access.save()
        return redirect('hw_internal_medical_access')
        


def hw_shared_access_revoke(request, id):
    sharedaccess = SharedAccess.objects.get(id=id).delete()
    return redirect('hw_internal_medical_access')


def hw_external_medical_access(request):
    return render(request, 'hw/hw_external_medical.html')



def hw_create_external_shared_access(request):
    pass


def hw_myaccount(request):   
    _healthprovider = HealthProvider.objects.get(id=request.session['healthprovider_id'])
    patients = Patient.objects.filter(healthprovider=_healthprovider)

    user = request.user;
    
    if UserKey.objects.filter(user=user).exists():
        _userkey = UserKey.objects.get(user=user)
    else:
        _userkey = None    

    context = {
        'user': user,
        'userkey' : _userkey,
        'patients' : patients
    }
    return render(request, 'hw/hw_myaccount.html', context)


def hw_userkey(request):
    return HttpResponse("Am here")


def hw_generate_userkey(request):
    if request.method == 'POST':
        #public_key = request.POST['public_key']

        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate the corresponding public key
        public_key = private_key.public_key()

        # Get the PEM-encoded private key
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Use NoEncryption for no encryption
        )

         # Get the PEM-encoded public key
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if UserKey.objects.filter(user=request.user).exists():
            userkey = UserKey.objects.get(user=request.user)
            userkey.public_key = public_key_pem.decode()
            userkey.private_key = private_key_pem.decode()
            userkey.save()
            
        else:
            userkey = UserKey.objects.create(user=request.user, public_key=public_key_pem.decode(), 
                                             private_key=private_key_pem.decode())
            userkey.save()
            

        return redirect(request.META.get('HTTP_REFERER'))

        

        

@login_required
def logout(request):
    auth.logout(request)
    return redirect('index')



