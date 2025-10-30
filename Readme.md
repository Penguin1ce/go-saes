# S-AES 实验2

## 基本信息

![image-20251031001712216](doc/assets/image-20251031001712216.png)

![image-20251031001744015](doc/assets/image-20251031001744015.png)

![image-20251031001757484](doc/assets/image-20251031001757484.png)

![image-20251031001808865](doc/assets/image-20251031001808865.png)



## 关卡1 基本测试

输入明文1234和密钥4567，得到密文

![image-20251031001926440](doc/assets/image-20251031001926440.png)

解密得到

![image-20251031002018130](doc/assets/image-20251031002018130.png)



## 关卡2 交叉测试

根据和别人相同的明文以及密钥输入https://gitee.com/H0OD/s-aes

可以发现得到了相同的密文，通过了关卡2的测试

我们约定使用列序列作为标准计算，保持和教材一致

## 关卡3 扩展功能

考虑到向实用性扩展，加密算法的数据输入可以是ASII编码字符串(分组为2 Bytes)，对应地输出也可以是ACII字符串。

使用Base64返回字符串，防止出现乱码

输入明文：`I love CQU`，密钥：`0x1234`，获得密文：`Qph0n+Gy9SmV/Q==`

![image-20251031002227675](doc/assets/image-20251031002227675.png)

解密得到

![image-20251031002408228](doc/assets/image-20251031002408228.png)







## 关卡4 多重加密

### 4.1双重加密

将S-AES算法通过双重加密进行扩展，分组长度仍然是16 bits，但密钥长度为32 bits。

加密：

![image-20251031002603309](doc/assets/image-20251031002603309.png)

解密：

![image-20251031002636013](doc/assets/image-20251031002636013.png)

### 4.2 中间相遇攻击

输入两个已知的明密文对，已知密钥为`0x12345678`

`0x1234` --> `0x1EC9` 

`0x4321` --> `0x9D66`

![image-20251031002804430](doc/assets/image-20251031002804430.png)

可以得到2个32位的密钥

![image-20251031002822729](doc/assets/image-20251031002822729.png)

### 4.3 三重加密

使用 `48bits (K1+K2+K3)` 的模式进行三重加解密。

加密：

![image-20251031003107338](doc/assets/image-20251031003107338.png)

解密：

![image-20251031003130068](doc/assets/image-20251031003130068.png)

可以看到通过测试

## 关卡 5 工作模式

基于S-AES算法，使用密码分组链(CBC)模式对较长的明文消息进行加密。

我们使用后端自动生成初始向量，返回给前端。

输入明文

`Cache penetration happens when many requests ask for data that does not exist in the database. Because the data is not in the cache, every request goes directly to the database. The cache cannot help, and the database becomes overloaded.`

密钥`0x1234`，后端自动生成初始向量`0x681A`，得到密文

`A0whBMT8vaRUX8EFJDwwdynqnBHElGehvkHCka6ZQRc0P7FOjHrFWpECzgQNW3fb2fEg/XnM9KQBUozI+Bgg4cvM5capBh4p/r6XOBkRBD02PwnkZo6+kGRsVOMe4P522Pnmho0UE8eZBIzsHIH27pfolXqouDGIX4x2ob2xugUM7sgp/Ehqipre5xZVMXihJH5/3ACQdkupqkWGveLEAnEtj8NJBHjhUwmaRtNSfX67J+GQw71TavJGWkcCn4lGhp695tg6twb6Q/TzPkR3Qyu6gd+gnB9UbKmj/VnNolJpfLwAa2zEht0foO4QJQ==`

![image-20251031003431552](doc/assets/image-20251031003431552.png)

解密成功

![image-20251031003630750](doc/assets/image-20251031003630750.png)

在CBC模式下进行加密，并尝试对密文分组进行替换或修改，然后进行解密，请对比篡改密文前后的解密结果。

如果篡改了密文，可以发现：大部分的原本并没有发生改变。

![image-20251031003706774](doc/assets/image-20251031003706774.png)




# S-AES 接口说明

## 基础信息
- 服务地址：`http://localhost:8080`
- 统一请求头：`Content-Type: application/json`
- 密钥说明：支持 16 / 32 / 48 位二进制或十六进制密钥（十六进制可带 `0x` 前缀）。
  - 16 位密钥执行标准 S-AES；
  - 32 位密钥拆分为 K1、K2 顺序执行双重加解密；
  - 48 位密钥拆分为 K1、K2、K3 顺序执行三重加解密（加密方向为 K1→K2→K3，解密方向为 K3→K2→K1）。

- 十六进制示例：`0x6574`（16 位数据块）、`0x1010`（16 位密钥）、`0x1010F0F0`（32 位密钥，表示 K1=0x1010、K2=0xF0F0）、`0x1010F0F00F0F`（48 位密钥，表示 K1=0x1010、K2=0xF0F0、K3=0x0F0F）。

## 1. 加密接口
- **URL**：`/encrypt`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "plaintext": "明文（16 位二进制或十六进制字符串，例如 0110... 或 0x6574）",
    "key": "密钥（16 / 32 / 48 位二进制或十六进制字符串）"
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
    "key": "密钥（16 / 32 / 48 位二进制或十六进制字符串）"
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
    "key": "密钥（16 / 32 / 48 位二进制或十六进制字符串）"
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
    "key": "密钥（16 / 32 / 48 位二进制或十六进制字符串）"
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

## 5. CBC 十六进制加密接口
- **URL**：`/encrypt/cbc`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "plaintext": "明文（ASCII 字符串，自动按 16 bit 分组加密）",
    "key": "密钥（16 / 32 / 48 位二进制或十六进制字符串）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "密文（按 16 bit 分组的十六进制字符串，示例：0x1234 0xABCD ...）",
      "iv": "初始向量（0x 前缀的 16 bit 十六进制字符串）"
    }
  }
  ```
- **示例**
  ```http
  POST /encrypt/cbc HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json
  
  {
    "plaintext": "Mini S-AES CBC",
    "key": "0001000000010000"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "0x130B 0x6E3A 0xCC91 0xF1C1 0x1A47 0xD56E 0xD399",
      "iv": "0x7D1C"
    }
  }
  ```
- **注意事项**
  - 服务会为每次加密自动生成随机 16 bit 初始向量 (IV)，需要与密文一并传输给解密方。
  - 明文若为奇数字节，将在末尾自动补 `0x00` 以满足 16 bit 分组，解密时会自动移除这类补位。

## 6. CBC 十六进制解密接口
- **URL**：`/decrypt/cbc`
- **Method**：`POST`
- **请求体**
  ```json
  {
    "ciphertext": "密文（按 16 bit 分组的十六进制字符串，可使用空格/逗号分隔或连续书写）",
    "key": "密钥（16 / 32 / 48 位二进制或十六进制字符串）",
    "iv": "初始向量（0x 前缀的 16 bit 十六进制字符串，可写成 16 位二进制）"
  }
  ```
- **响应体**
  ```json
  {
    "code": 0,
    "message": "success",
    "data": {
      "plaintext": "解密后的 ASCII 明文"
    }
  }
  ```
- **示例**
  ```http
  POST /decrypt/cbc HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json
  
  {
    "ciphertext": "0x130B 0x6E3A 0xCC91 0xF1C1 0x1A47 0xD56E 0xD399",
    "key": "0001000000010000",
    "iv": "0x7D1C"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "plaintext": "Mini S-AES CBC"
    }
  }
  ```
- **注意事项**
  - 解密方必须使用加密时提供的 IV；IV 不正确会导致解密失败或得到错误结果。
  - IV 字符串支持 `0x` 前缀十六进制或 16 位二进制表示。

## 7. 中间相遇攻击接口
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

## 附：多轮密钥加解密示例
- **32 位双重加密示例**
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
- **32 位双重 Base64 加密示例**
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
- **48 位三重加密示例**
  ```http
  POST /encrypt HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json
  
  {
    "plaintext": "0x6574",
    "key": "0x1010F0F00F0F"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "0100100000000001"
    }
  }
  ```
  > 二进制密文 `0100100000000001` 对应十六进制 `0x4801`。
- **48 位三重 Base64 加密示例**
  ```http
  POST /encrypt/base64 HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json
  
  {
    "plaintext": "et",
    "key": "0x1010F0F00F0F"
  }
  ```
  ```json
  HTTP/1.1 200 OK
  {
    "code": 0,
    "message": "success",
    "data": {
      "ciphertext": "SAE="
    }
  }
  ```

## 错误码说明
- `200`：请求成功。
- `400`：请求参数错误，可能是字段缺失或二进制格式不正确。
- `500`：服务内部错误。
