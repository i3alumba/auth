from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .sessions import consume_login_attempt


class LimitedTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        username = attrs[self.username_field]
        if (
            len(username) > 150
            or len(attrs["password"]) > 4096
            or not consume_login_attempt(self.context["request"], username)
        ):
            raise AuthenticationFailed(
                self.error_messages["no_active_account"], "no_active_account"
            )
        return super().validate(attrs)


class LimitedTokenObtainPairView(TokenObtainPairView):
    serializer_class = LimitedTokenObtainPairSerializer
