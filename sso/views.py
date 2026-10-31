from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .access import services_for


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def access(request):
    return Response({"services": services_for(request.user)})
