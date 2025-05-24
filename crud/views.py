from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from .models import Genders, Users
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import check_password
from functools import wraps

def login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            return redirect('/login/')
        return view_func(request, *args, **kwargs)
    return wrapper

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        try:
            user = Users.objects.get(username=username)
            if check_password(password, user.password):
                request.session['user_id'] = user.user_id
                request.session['username'] = user.username
                return redirect('/user/list')
            else:
                messages.error(request, 'Invalid username or password.')
        except Users.DoesNotExist:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'registration/login.html')

def logout_view(request):
    request.session.flush()
    messages.success(request, "You have been logged out.")
    return redirect('/login/')

@login_required
def gender_list(request):
    try:
        genders = Genders.objects.all()
        data = {'genders':genders}
        return render(request, 'gender/GendersList.html', data)
    except Exception as e:
        return HttpResponse(f'Error occured during load gender list: {e}')

@login_required
def add_gender(request):
    try:
        if request.method == 'POST':
            gender = request.POST.get('gender')
            Genders.objects.create(gender=gender).save()
            messages.success(request, 'Gender added successfully!')
            return redirect('/gender/list')
        else:
            return render(request, 'gender/AddGender.html')
    except Exception as e:
        return HttpResponse(f'Error occured during add gender: {e}')
    
@login_required
def edit_gender(request, genderId):
    try:
        if request.method == 'POST':
            genderObj = Genders.objects.get(pk=genderId)
            gender = request.POST.get('gender')
            genderObj.gender = gender
            genderObj.save()
            messages.success(request, 'Gender updated successfully!')
            data = {'gender': genderObj}
            return render(request, 'gender/EditGender.html', data)
        else:
            genderObj = Genders.objects.get(pk=genderId)
            data = {'gender': genderObj}
        return render(request, 'gender/EditGender.html', data)
    except Exception as e:
        return HttpResponse(f'Error occured during edit gender: {e}')

@login_required
def delete_gender(request, genderId):
    try:
        genderObj = Genders.objects.get(pk=genderId)

        data = {
            'gender': genderObj
        }
        
        return render(request, 'gender/DeleteGender.html', data)
    except Exception as e:
        return HttpResponse(f'Error occurred during delete gender: {e}')

@login_required
def user_list(request):
    try:
        userObj = Users.objects.select_related('gender')
        data = {'users': userObj}
        return render(request, 'user/UsersList.html',data)
    except Exception as e:
        return HttpResponse(f'Error occured during load users: {e}')

@login_required
def add_user(request):
    try:
       if request.method == 'POST':
           fullName = request.POST.get('full_name')
           gender = request.POST.get('gender')
           birthDate = request.POST.get('birth_date')
           address = request.POST.get('address')
           contactNumber = request.POST.get('contact_number')
           email = request.POST.get('email')
           username = request.POST.get('username')
           password = request.POST.get('password')
           confirmPassword = request.POST.get('confirm_password')

        #    if password != confirmPassword:
        #        return

           Users.objects.create(
               full_name=fullName,
               gender=Genders.objects.get(pk=gender),
               birth_date=birthDate,
               address=address,
               contact_number=contactNumber,
               email=email,
               username=username,
               password=make_password(password)
           ).save()
           
           messages.success(request, 'User added successfully!')
           return redirect('/user/add')
       else:
            genderObj = Genders.objects.all()

            data = {
                'genders': genderObj
            }

       return render(request, 'user/AddUser.html', data)
    except Exception as e:
        return HttpResponse(f'Error occured during add user: {e}')