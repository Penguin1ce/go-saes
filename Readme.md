# S-AES 接口说明

## 基础信息
- 服务地址：`http://localhost:8080`
- 统一请求头：`Content-Type: application/json`

## 1. 加密接口
- **URL**：`/encrypt`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "plaintext": "明文（16 位二进制字符串）",
    "key": "密钥（16 位二进制字符串）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "密文（16 位二进制字符串）"
    }
  }
  ```
- **示例**
  ```http
  POST /encrypt HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "plaintext": "0110010101110100",
    "key": "0001000000010000"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "1111001010110011"
    }
  }
  ```
- **错误响应**
  ```json
  {
    "code": 1,
    "message": "错误信息"
  }
  ```

## 2. 解密接口
- **URL**：`/decrypt`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "ciphertext": "密文（16 位二进制字符串）",
    "key": "密钥（16 位二进制字符串）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "plaintext": "明文（16 位二进制字符串）"
    }
  }
  ```
- **示例**
  ```http
  POST /decrypt HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "ciphertext": "1111001010110011",
    "key": "0001000000010000"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "plaintext": "0110010101110100"
    }
  }
  ```
- **错误响应**
  ```json
  {
    "code": 1,
    "message": "错误信息"
  }
  ```

## 错误码说明
- `200`：请求成功。
- `400`：请求参数错误，可能是字段缺失或二进制格式不正确。
- `500`：服务内部错误。
