# S-AES 接口说明

## 基础信息
- 服务地址：`http://localhost:8080`
- 统一请求头：`Content-Type: application/json`
- 密钥说明：支持 16 位或 32 位二进制 / 十六进制密钥（十六进制可带 `0x` 前缀）。16 位密钥执行标准 S-AES 单轮加/解密；32 位密钥将拆分为 K1、K2 顺序执行双重 S-AES。
- 十六进制示例：`0x6574`（16 位数据块）、`0x1010`（16 位密钥）、`0x1010F0F0`（32 位密钥，表示 K1=0x1010、K2=0xF0F0）。

## 1. 加密接口
- **URL**：`/encrypt`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "plaintext": "明文（16 位二进制或十六进制字符串，例如 0110... 或 0x6574）",
    "key": "密钥（16 位或 32 位二进制 / 十六进制字符串）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "密文（16 位二进制字符串，可按需转换为十六进制）"
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
    "ciphertext": "密文（16 位二进制或十六进制字符串）",
    "key": "密钥（16 位或 32 位二进制 / 十六进制字符串）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "plaintext": "明文（16 位二进制字符串，可按需转换为十六进制）"
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

## 3. Base64 加密接口
- **URL**：`/encrypt/base64`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "plaintext": "明文（ASCII 字符串，自动按 16 bit 分组加密）",
    "key": "密钥（16 位或 32 位二进制 / 十六进制字符串）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "密文（Base64 编码字符串）"
    }
  }
  ```
- **示例**
  ```http
  POST /encrypt/base64 HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "plaintext": "et",
    "key": "0001000000010000"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "BPo="
    }
  }
  ```
- **注意事项**
  - 仅支持 ASCII 字符；若明文长度为奇数，会在尾部自动补齐一个空字节以满足 16 bit 分组。

## 4. Base64 解密接口
- **URL**：`/decrypt/base64`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "ciphertext": "密文（Base64 编码字符串）",
    "key": "密钥（16 位或 32 位二进制 / 十六进制字符串）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "plaintext": "明文（ASCII 字符串）"
    }
  }
  ```
- **示例**
  ```http
  POST /decrypt/base64 HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "ciphertext": "BPo=",
    "key": "0001000000010000"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "plaintext": "et"
    }
  }
  ```
- **注意事项**
  - Base64 解码后的字节长度必须为 2 的倍数，否则将返回错误。

## 5. 中间相遇攻击接口
- **URL**：`/attack/meet-in-the-middle`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "pairs": [
      {
        "plaintext": "0x6574",
        "ciphertext": "0x9920"
      }
    ]
  }
  ```
  - `pairs` 至少包含一组 16 bit 明文与密文，可同时提供多组以减少伪碰撞。
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "count": 1,
      "keys": [
        {
          "k1_hex": "0x1010",
          "k1_bin": "0001000000010000",
          "k2_hex": "0xF0F0",
          "k2_bin": "1111000011110000",
          "combined_hex": "0x1010F0F0",
          "combined_bin": "00010000000100001111000011110000"
        }
      ]
    }
  }
  ```
  - `count` 表示匹配到的密钥数量，可能大于 1。
  - `keys` 返回所有候选 `(K1, K2)`，同时提供二进制与十六进制形式。
- **示例**
  ```http
  POST /attack/meet-in-the-middle HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "pairs": [
      {
        "plaintext": "0x6574",
        "ciphertext": "0x9920"
      }
    ]
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "count": 1,
      "keys": [
        {
          "k1_hex": "0x1010",
          "k1_bin": "0001000000010000",
          "k2_hex": "0xF0F0",
          "k2_bin": "1111000011110000",
          "combined_hex": "0x1010F0F0",
          "combined_bin": "00010000000100001111000011110000"
        }
      ]
    }
  }
  ```
- **注意事项**
  - 如果只提供一组明密文，可能存在多个候选密钥，请结合额外数据进行筛选。
  - 接口默认针对 32 bit 密钥的双重加密场景（K1 → K2）。

## 附：32 位密钥双重加解密示例
- **加密示例**
  ```http
  POST /encrypt HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "plaintext": "0110010101110100",
    "key": "00010000000100001111000011110000"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "1001100100100000"
    }
  }
  ```
  > 返回值为 16 位二进制，可在前端十六进制模式查看为 `0x9920`。
- **Base64 加密示例**
  ```http
  POST /encrypt/base64 HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "plaintext": "et",
    "key": "00010000000100001111000011110000"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "mSA="
    }
  }
  ```
- **十六进制输入示例**
  ```http
  POST /encrypt HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "plaintext": "0x6574",
    "key": "0x1010F0F0"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "1001100100100000"
    }
  }
  ```

## 错误码说明
- `200`：请求成功。
- `400`：请求参数错误，可能是字段缺失或二进制格式不正确。
- `500`：服务内部错误。
