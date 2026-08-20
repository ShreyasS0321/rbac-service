from rest_framework import serializers


class CheckSerializer(serializers.Serializer):
    principal_id = serializers.IntegerField()
    permission_id = serializers.IntegerField()
    scope_type = serializers.CharField(required=False, allow_null=True, default=None)
    scope_id = serializers.CharField(required=False, allow_null=True, default=None)
