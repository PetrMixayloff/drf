import re

import chardet
import jwt
import subprocess
from django.contrib.auth import user_logged_in
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.serializers import jwt_payload_handler

from users.models import User
from drf import settings
from .serializers import UserSerializer


class CreateUserAPIView(APIView):
    # Allow any user (authenticated or not) to access this url
    permission_classes = (AllowAny,)

    def post(self, request):
        user = request.data
        login = user["login"]
        password = user["password"]
        user["type_of_login"] = self.check_login_type(login)
        serializer = UserSerializer(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user = User.objects.get(login=login, password=password)
        payload = jwt_payload_handler(user)
        token = jwt.encode(payload, settings.SECRET_KEY)
        return Response(token, status=status.HTTP_201_CREATED)

    def check_login_type(self, login):
        if re.match(r"^\+?1?\d{9,15}$", login):
            return 'phone'
        else:
            return 'email'


class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    # Allow only authenticated users to access this url
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        # serializer to handle turning our `User` object into something that
        # can be JSONified and sent to the client.
        serializer = self.serializer_class(request.user)

        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated, ])
def get_latency(request):
    p = subprocess.Popen(["ping", "www.google.com"], stdout=subprocess.PIPE)
    latency = ''
    for line in p.stdout:
        char = chardet.detect(line)
        charenc = char['encoding']
        line = line.decode(charenc).encode('utf-8')
        if 'мсек' in line.decode('utf-8'):
            latency = line.decode('utf-8')
    latency = 'Время задержки до www.google.com: ' + latency
    response = {'latency': latency}
    return Response(response, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny, ])
def authenticate_user(request):
    try:
        login = request.data['login']
        password = request.data['password']

        user = User.objects.get(login=login, password=password)
        if user:
            try:
                payload = jwt_payload_handler(user)
                token = jwt.encode(payload, settings.SECRET_KEY)
                user_details = {'name': user.name,
                                'token': token}
                user_logged_in.send(sender=user.__class__,
                                    request=request,
                                    user=user)
                return Response(user_details, status=status.HTTP_200_OK)

            except Exception as e:
                raise e
        else:
            res = {
                'error': 'can not authenticate with the given credentials or the account has been deactivated'}
            return Response(res, status=status.HTTP_403_FORBIDDEN)
    except KeyError:
        res = {'error': 'please provide a email and a password'}
        return Response(res)
