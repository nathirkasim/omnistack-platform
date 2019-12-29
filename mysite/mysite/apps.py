from django.contrib.admin.apps import AdminConfig


class MySiteAdminConfig(AdminConfig):
    default_site = 'mysite.admin.TutorialAdminSite'
