from rest_framework import serializers

from rbac.models import Role


class CheckSerializer(serializers.Serializer):
    principal_id = serializers.IntegerField()
    permission_id = serializers.IntegerField()
    scope_type = serializers.CharField(required=False, allow_null=True, default=None)
    scope_id = serializers.CharField(required=False, allow_null=True, default=None)


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "key", "name", "description", "is_system"]
        read_only_fields = ["id", "is_system"]


class EdgeSerializer(serializers.Serializer):
    child = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    parent = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
