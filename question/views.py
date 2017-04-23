from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# Create your views here.
@login_required
def index(request):
	user = request.user
	context = {
		'user': user,
	}
	return render(request, 'question/main.html', context=context)

def profile(request, userid):
	return render(request, 'question/profile.html')

def settings(request):
	return render(request, 'question/settings.html')
