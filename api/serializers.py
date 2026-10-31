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
    services = serializers.SerializerMethodField()

    def get_services(self, user):
        from sso.access import services_for

        return {
            slug: service["enabled"] for slug, service in services_for(user).items()
        }

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "groups",
            "services",
        )
        read_only_fields = fields
