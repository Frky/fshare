import django.views.defaults
from django.conf.urls import include, url
from django.contrib.auth.views import login as django_login
from django.contrib.auth.views import logout as django_logout
from website import views

urlpatterns = [
    url(r'^$', views.index, name="index"),
    url(r'^myfiles$', views.myfiles, name="myfiles"),
    url(r'^cockpit$', views.cockpit, name="cockpit"),
    url(r'^upload', views.upload, name="upload"),
    url(r'^about', views.about, name="about"),

    # Ajax views
    url(r'^generate_registration_key$', views.generate_registration_key, name="generate_registration_key"),
    url(r'^mark_key_distributed$', views.mark_key_distributed, name="mark_key_distributed"),
    url(r'^revoke_key$', views.revoke_key, name="revoke_key"),
    url(r'^size_available$', views.size_available, name="size_available"),

    # Authentication views
    url(r'^register$', views.register, name="register"),
    url(r'^login$', django_login, name="login"),
    url(r'^logout$', django_logout, {'template_name': "registration/logout.html"}, name="logout"),

    # File downloading view
    url(r'^dl/(?P<fid>[-A-Za-z0-9_]+)$', views.download, name="download"),
    url(r'^get/(?P<fid>[-A-Za-z0-9_]+)$', views.get, name="get"),
    # File deleting view
    url(r'^rm/(?P<fid>[-A-Za-z0-9_]+)$', views.delete, name="delete"),
    # File updating view
    url(r'^update/(?P<fid>[-A-Za-z0-9_]+)$', views.update, name="update"),
    # Get file name
    url(r'^get_name/(?P<fid>[-A-Za-z0-9_]+)$', views.get_name, name="get_name"),

    # 404 page
    url(r'^404$', django.views.defaults.page_not_found)
]
