from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from .models import Genders, Users
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from django.utils import timezone
from django.shortcuts import get_object_or_404

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # First try authenticating with Django's auth system (for superusers)
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            request.session['user_id'] = user.id
            request.session['username'] = user.username
            request.session['is_superuser'] = True
            messages.success(request, "You have been logged in successfully.")
            return redirect('/user/list')
        
        # If not a superuser, check the custom Users table
        try:
            custom_user = Users.objects.get(username=username)
            if check_password(password, custom_user.password):
                # For custom users, create a Django user session to make them behave like admin users
                django_user, created = User.objects.get_or_create(
                    username=custom_user.username,
                    defaults={
                        'password': make_password(password),
                        'is_staff': False,
                        'is_superuser': False
                    }
                )
                
                # Authenticate and login the user with Django's auth system
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    auth_login(request, user)
                    request.session['user_id'] = custom_user.user_id
                    request.session['username'] = custom_user.username
                    request.session['is_custom_user'] = True
                    messages.success(request, "You have been logged in successfully.")
                    return redirect('/user/list')
                else:
                    messages.error(request, 'Authentication failed.')
            else:
                messages.error(request, 'Invalid username or password.')
        except Users.DoesNotExist:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'registration/login.html')

def logout_view(request):
    # Logout from Django's auth system
    if hasattr(request, 'user') and request.user.is_authenticated:
        auth_logout(request)
    
    # Clear session data
    request.session.flush()
    
    messages.success(request, "You have been logged out successfully.")
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
        genderObj = get_object_or_404(Genders, pk=genderId)
        
        if request.method == 'POST':
            genderObj.delete()
            messages.success(request, 'Gender deleted successfully!')
            return redirect('/gender/list')
            
        # GET request handling
        data = {'gender': genderObj}
        return render(request, 'gender/DeleteGender.html', data)
        
    except Exception as e:
        return HttpResponse(f'Error occurred during delete gender: {e}')
    
@login_required
def user_list(request):
    try:
        # Get search query from request
        search_query = request.GET.get('q', '').strip()
        
        # Start with base queryset
        queryset = Users.objects.select_related('gender').order_by('user_id')
        
        # Apply search filter if query exists
        if search_query:
            queryset = queryset.filter(
                Q(full_name__icontains=search_query) |
                Q(email__icontains=search_query) |
                Q(username__icontains=search_query) |
                Q(contact_number__icontains=search_query)
            )
        # Pagination
        paginator = Paginator(queryset, 10)  # 10 users per page
        page_number = request.GET.get('page')
        
        try:
            users = paginator.page(page_number)
        except PageNotAnInteger:
            # If page is not an integer, deliver first page
            users = paginator.page(1)
        except EmptyPage:
            # If page is out of range, deliver last page
            users = paginator.page(paginator.num_pages)
        
        # Calculate range for pagination display
        page_range = paginator.get_elided_page_range(
            number=users.number,
            on_each_side=1,
            on_ends=1
        )
        
        context = {
            'users': users,
            'search_query': search_query,
            'page_range': page_range,
        }
        
        return render(request, 'user/UsersList.html', context)
        
    except Exception as e:
        return HttpResponse(
            f'Error occurred while loading users: {str(e)}',
            status=500
        )
    
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

           if password != confirmPassword:
               messages.error(request, "Passwords don't match!")
               return redirect('/user/add')

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
    
from django.http import JsonResponse

@login_required
def check_username(request):
    username = request.GET.get('username', '')
    # Check both Django auth users and custom Users table
    exists = (
        User.objects.filter(username=username).exists() or 
        Users.objects.filter(username=username).exists()
    )
    return JsonResponse({'exists': exists})

@login_required
def edit_user(request, user_id):
    try:
        user = get_object_or_404(Users, pk=user_id)
        genders = Genders.objects.all()
        
        if request.method == 'POST':
            # Get form data
            full_name = request.POST.get('full_name')
            gender_id = request.POST.get('gender')
            birth_date = request.POST.get('birth_date')
            address = request.POST.get('address')
            contact_number = request.POST.get('contact_number')
            email = request.POST.get('email')
            username = request.POST.get('username')
            
            # Check if username has changed and if new username exists
            if username != user.username:
                if Users.objects.filter(username=username).exists():
                    messages.error(request, 'Username already exists!')
                    return redirect(f'/user/edit/{user_id}/')
            
            # Update user data
            user.full_name = full_name
            user.gender = Genders.objects.get(pk=gender_id)
            user.birth_date = birth_date
            user.address = address
            user.contact_number = contact_number
            user.email = email
            user.username = username
            user.save()
            
            messages.success(request, 'User updated successfully!')
            return redirect('/user/list/')
        
        # For GET request, render the edit form
        context = {
            'user': user,
            'genders': genders,
            'today': timezone.now().date()  # For date validation
        }
        return render(request, 'user/EditUser.html', context)
        
    except Exception as e:
        messages.error(request, f'Error occurred: {str(e)}')
        return redirect('/user/list/')
    
@login_required
def change_password(request, user_id):
    try:
        user = get_object_or_404(Users, pk=user_id)
        
        if request.method == 'POST':
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            # Verify current password
            if not check_password(current_password, user.password):
                messages.error(request, 'Current password is incorrect')
                return redirect(f'/registration/change_password/{user_id}/')
                
            # Check new passwords match
            if new_password != confirm_password:
                messages.error(request, 'New passwords do not match')
                return redirect(f'/registration/change_password/{user_id}/')
                
            # Update password
            user.password = make_password(new_password)
            user.save()
            
            messages.success(request, 'Password updated successfully!')
            return redirect(f'/user/edit/{user_id}/')
            
        return render(request, 'registration/ChangePassword.html', {'user': user})
        
    except Exception as e:
        messages.error(request, f'Error changing password: {str(e)}')
        return redirect(f'/user/edit/{user_id}/')

@login_required
def delete_user(request, user_id):
    try:
        user = get_object_or_404(Users, pk=user_id)
        
        if request.method == 'POST':
            user.delete()
            messages.success(request, 'User deleted successfully!')
            return redirect('/user/list')
            
        # GET request handling
        context = {'user': user}
        return render(request, 'user/DeleteUser.html', context)
        
    except Exception as e:
        messages.error(request, f'Error occurred while deleting user: {str(e)}')
        return redirect('/user/list')