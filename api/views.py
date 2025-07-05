from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated

from api.serializers import GroupSerializer, User, UserSerializer


class UserViewSet(ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return User.objects.filter(id=self.request.user.id)


class GroupViewSet(ModelViewSet):
    serializer_class = GroupSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return self.request.user.groups
