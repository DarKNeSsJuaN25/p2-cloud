import json
import boto3
import os
import jwt
import datetime
import hashlib
from utils import hash_password, verify_password

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['TABLE_NAME'])
JWT_SECRET = os.environ['JWT_SECRET']

def crear_usuario(event, context):
    body = event['body']

    tenant_id = body['tenant_id']
    username = body['username']
    password = body['password']

    hashed_password = hash_password(password)

    table.put_item(
        Item={
            'tenant_id': tenant_id,
            'username': username,
            'password': hashed_password
        }
    )

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Usuario creado'})
    }

def login(event, context):
    body = event['body']

    tenant_id = body['tenant_id']
    username = body['username']
    password = body['password']

    response = table.get_item(Key={'tenant_id': tenant_id, 'username': username})

    if 'Item' not in response:
        return {'statusCode': 401, 'body': json.dumps({'message': 'Credenciales inválidas'})}

    user = response['Item']

    if not verify_password(password, user['password']):
        return {'statusCode': 401, 'body': json.dumps({'message': 'Credenciales inválidas'})}

    payload = {
        'tenant_id': tenant_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')

    return {
        'statusCode': 200,
        'body': json.dumps({'token': token})
    }

def validar_token(event, context):
    token = event['headers'].get('Authorization')

    if not token:
        return {'statusCode': 401, 'body': json.dumps({'message': 'Token requerido'})}

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return {'statusCode': 401, 'body': json.dumps({'message': 'Token expirado'})}
    except jwt.InvalidTokenError:
        return {'statusCode': 401, 'body': json.dumps({'message': 'Token inválido'})}

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Token válido', 'payload': payload})
    }
