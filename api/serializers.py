from django.contrib.auth.models import Group
from rest_framework import serializers
from django.contrib.auth import get_user_model


User = get_user_model()


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ("id", "name")
        read_only_fields = fields


class UserSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", "groups")
        read_only_fields = fields
