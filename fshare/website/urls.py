from django.conf.urls import include, url
from django.contrib.auth.views import login as django_login
from django.contrib.auth.views import logout as django_logout

urlpatterns = [
    url(r'^$', 'website.views.index', name="index"),
    url(r'^myfiles$', 'website.views.myfiles', name="myfiles"),

    # Authentication views
    url(r'^register$', 'website.views.register', name="register"),
    url(r'^login$', django_login, name="login"),
    url(r'^logout$', django_logout, {'template_name': "registration/logout.html"}, name="logout"),
]
