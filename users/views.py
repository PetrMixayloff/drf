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
from django.conf import settings
from users.models import User, Token
from drf import settings
from .serializers import UserSerializer
from django.core.exceptions import ObjectDoesNotExist


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
        token_model = Token(token=token, user=user)
        token_model.save()
        return Response(token, status=status.HTTP_201_CREATED)

    def check_login_type(self, login):
        if re.match(r"^\+?1?\d{9,15}$", login):
            return 'phone'
        else:
            return 'email'


@api_view(['GET'])
@permission_classes([IsAuthenticated, ])
def get_info(request):
    # serializer to handle turning our `User` object into something that
    # can be JSONified and sent to the client.
    token = request.auth
    print(token)
    try:
        token_model = Token.objects.get(token=token)
    except ObjectDoesNotExist:
        return Response(status=status.HTTP_401_UNAUTHORIZED)
    serializer = UserSerializer(request.user)
    token_model.save()
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated, ])
def get_latency(request):
    token = request.auth.decode('utf-8')
    try:
        token_model = Token.objects.get(token=token)
    except ObjectDoesNotExist:
        return Response(status=status.HTTP_401_UNAUTHORIZED)
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
    token_model.save()
    return Response(response, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated, ])
def logout(request):
    all = request.GET.get('all', '')
    token_models = Token.objects.filter(user_id=request.user.id).order_by('-timestamp')
    if all:
        for item in token_models:
            item.delete()
    else:
        token_models[0].delete()
    return Response(status=status.HTTP_200_OK)


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
                token_model = Token(token=token, user=user)
                token_model.save()
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
