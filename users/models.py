from __future__ import unicode_literals
from django.db import models, transaction
from django.utils import timezone
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager)
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import re


def validate_even(value):
    if re.match(r"^\+?7?\d{9,15}$", value) is None and \
            re.match(r"^\w[A-Za-z0-9\.\+_-]*@[A-Za-z0-9]+\.[a-z]+$", value) is None:
        raise ValidationError(
            _(f'{value} is not an even number or email'),
            params={'value': value},
        )


class UserManager(BaseUserManager):

    def _create_user(self, login, password, **extra_fields):
        """
        Creates and saves a User with the given login,and password.
        """
        if not login:
            raise ValueError('The given login must be set')
        try:
            with transaction.atomic():
                user = self.model(login=login, **extra_fields)
                user.set_password(password)
                user.save(using=self._db)
                return user
        except Exception:
            raise

    def create_user(self, login, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(login, password, **extra_fields)

    def create_superuser(self, login, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)

        return self._create_user(login, password=password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    """
    login = models.CharField(validators=[validate_even], max_length=40, unique=True, default='')
    type_of_login = models.CharField(max_length=20, default='', blank=True)
    name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'login'
    REQUIRED_FIELDS = ['name']

    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)
        return self


class Token(models.Model):
    token = models.CharField(max_length=500)
    user = models.ForeignKey(User, related_name="token_user", on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("token", "user")
