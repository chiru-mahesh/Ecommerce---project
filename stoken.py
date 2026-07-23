from itsdangerous import URLSafeTimedSerializer
secret_key='Code567'
salt='otpverify'
def endata(data):
    serializer=URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data,salt=salt)
def dndata(data):
    serializer=URLSafeTimedSerializer(secret_key)
    return serializer.loads(data,salt=salt,max_age=3600)