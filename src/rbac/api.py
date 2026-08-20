from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response

from rbac import resolver
from rbac.serializers import CheckSerializer


@api_view(["POST"])
def check_view(request: Request) -> Response:
    serializer = CheckSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data
    allowed = resolver.check(
        data["principal_id"],
        data["permission_id"],
        data["scope_type"],
        data["scope_id"],
    )
    return Response({"allowed": allowed})
