from django.contrib.auth.models import AbstractUser
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db import models
from django.utils import timezone
from model_utils import Choices
from django.utils.translation import gettext_lazy as _
from phonenumber_field.modelfields import PhoneNumberField

from custom_auth.managers import CustomUserManager


class Application_User(AbstractUser):
    USER_TYPES = Choices(
        ("users", "Users"),
        ("seller", "Seller"),
    )
    GENDER_TYPES = Choices(
        ("male", "Male"),
        ("female", "Female"),
    )
    username_validator = UnicodeUsernameValidator()
    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        blank=True,
        null=True,
        help_text=('Required. 150 characters or fewer. Lettres , digits and @/./+/-/ only .'),
        validators=[username_validator],
        error_messages={
            'unique': _('A user with that username already exists.'),
        }
    )
    email = models.EmailField(_("email address"), error_messages={
        'unique': _('A user with that email address  already exists.'),
    }, unique=True)

    name = models.CharField(
        _('name'),
        max_length=300,
        blank=True,
        help_text=_('name as it was returned by social media provider.'),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    phone = PhoneNumberField(_('phone'), null=True, blank=True, unique=True, )
    gender = models.CharField(max_length=10, choices=GENDER_TYPES)
    address = models.TextField(
        _('address'),
        max_length=1000,
        blank=True,
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPES, default=USER_TYPES.users)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = CustomUserManager()

    def __str__(self):
        return self.email or self.name
