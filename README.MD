# 认证授权服务
## 自定义授权方式
password_like方式     
curl调用:
curl -v -X POST   http://192.168.31.102:8901/oauth2/token   -H "Content-Type: application/x-www-form-urlencoded"   -u "password-client-id:secret"   -d "grant_type=password_like"   -d "username=user1"   -d "password=123456"