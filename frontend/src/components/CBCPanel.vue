<template>
  <el-card shadow="never" class="panel-card" :body-style="{ padding: '24px' }">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <span>CBC 模式（Base64）</span>
          <el-tag size="small" type="info" effect="light">随机 16 bit IV</el-tag>
        </div>
        <p class="card-subtitle">
          对 ASCII 明文执行 CBC 加密，返回 Base64 编码的密文与初始向量；同样支持 Base64 密文的解密。
        </p>
      </div>
    </template>

    <el-tabs v-model="activeTab">
      <el-tab-pane label="加密" name="encrypt">
        <p class="tab-intro">
          输入 ASCII 明文以及 16 / 32 / 48 位密钥（可为二进制或十六进制表示），即可获得 Base64 密文与随机生成的十六进制初始向量。
        </p>
        <el-form
          ref="encryptFormRef"
          :model="encryptForm"
          :rules="encryptRules"
          label-position="top"
          @submit.prevent
        >
          <el-form-item label="明文（ASCII）" prop="plaintext">
            <el-input
              v-model="encryptForm.plaintext"
              type="textarea"
              :rows="5"
              maxlength="256"
              show-word-limit
            />
          </el-form-item>
          <el-form-item label="密钥（16 位二进制或十六进制）" prop="key">
            <el-input
              v-model="encryptForm.key"
              maxlength="50"
              show-word-limit
            />
          </el-form-item>
          <el-form-item class="form-actions">
            <el-button type="primary" :loading="loading.encrypt" @click="handleEncrypt">
              立即加密
            </el-button>
            <el-button @click="resetEncrypt">清空</el-button>
          </el-form-item>
        </el-form>
        <el-result
          v-if="encryptResult"
          icon="success"
          title="CBC 加密成功"
          :sub-title="`密文（Base64）：${encryptResult.ciphertext}`"
          class="result-block"
        >
          <template #extra>
            <span class="iv-display">初始向量（十六进制）：{{ encryptResult.iv }}</span>
          </template>
        </el-result>
      </el-tab-pane>

      <el-tab-pane label="解密" name="decrypt">
        <p class="tab-intro">
          提供 Base64 编码的密文、十六进制初始向量与共享密钥，即可恢复原始 ASCII 明文。
        </p>
        <el-form
          ref="decryptFormRef"
          :model="decryptForm"
          :rules="decryptRules"
          label-position="top"
          @submit.prevent
        >
          <el-form-item label="密文（Base64）" prop="ciphertext">
            <el-input
              v-model="decryptForm.ciphertext"
              type="textarea"
              :rows="5"
            />
          </el-form-item>
          <el-form-item label="密钥（16 位二进制或十六进制）" prop="key">
            <el-input
              v-model="decryptForm.key"
              maxlength="50"
              show-word-limit
            />
          </el-form-item>
          <el-form-item label="初始向量（十六进制或 16 位二进制）" prop="iv">
            <el-input
              v-model="decryptForm.iv"
              maxlength="20"
              show-word-limit
            />
          </el-form-item>
          <el-form-item class="form-actions">
            <el-button type="primary" :loading="loading.decrypt" @click="handleDecrypt">
              立即解密
            </el-button>
            <el-button @click="resetDecrypt">清空</el-button>
          </el-form-item>
        </el-form>
        <el-result
          v-if="decryptResult"
          icon="success"
          title="CBC 解密成功"
          :sub-title="`明文（ASCII）：${decryptResult}`"
          class="result-block"
        />
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import httpClient from '../api/httpClient';

const activeTab = ref('encrypt');
const encryptFormRef = ref();
const decryptFormRef = ref();

const encryptForm = reactive({
  plaintext: '',
  key: ''
});

const decryptForm = reactive({
  ciphertext: '',
  key: '',
  iv: ''
});

const loading = reactive({
  encrypt: false,
  decrypt: false
});

const encryptResult = ref(null);
const decryptResult = ref('');

const sanitizeBinary = (value) => value.replace(/\s+/g, '').trim();
const sanitizeAscii = (value) => value.replace(/\r/g, '');
const sanitizeBase64 = (value) => value.replace(/\s+/g, '').trim();

const normalizeHex = (value, hexDigits) => {
  const sanitized = value.replace(/\s+/g, '').trim();
  if (!sanitized) {
    throw new Error('请输入十六进制字符串');
  }
  let hex = sanitized;
  if (hex.startsWith('0x') || hex.startsWith('0X')) {
    hex = hex.slice(2);
  }
  if (hex.length !== hexDigits) {
    throw new Error(`十六进制字符串须为 ${hexDigits} 个字符`);
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('仅支持十六进制字符（0-9、A-F）');
  }
  return `0x${hex.toUpperCase()}`;
};

const createBinaryOrHexValidator = (bits) => (_rule, value, callback) => {
  if (!value) {
    callback(new Error(`请输入 ${bits} 位二进制或十六进制字符串`));
    return;
  }
  const sanitized = sanitizeBinary(value);
  if (new RegExp(`^[01]{${bits}}$`).test(sanitized)) {
    callback();
    return;
  }
  try {
    normalizeHex(value, bits / 4);
    callback();
  } catch (error) {
    callback(error instanceof Error ? error : new Error('格式不正确'));
  }
};

const decodeBase64 = (value) => {
  if (typeof atob === 'function') {
    return atob(value);
  }
  if (typeof globalThis !== 'undefined' && globalThis.Buffer) {
    return globalThis.Buffer.from(value, 'base64').toString('binary');
  }
  throw new Error('当前环境不支持 Base64 解码');
};

const base64Validator = (_rule, value, callback) => {
  const sanitized = sanitizeBase64(value);
  if (!sanitized) {
    callback(new Error('请输入 Base64 字符串'));
    return;
  }
  if (sanitized.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(sanitized)) {
    callback(new Error('Base64 编码格式不正确'));
    return;
  }
  try {
    decodeBase64(sanitized);
    callback();
  } catch (_e) {
    callback(new Error('Base64 编码格式不正确'));
  }
};

const asciiValidator = (_rule, value, callback) => {
  const sanitized = sanitizeAscii(value);
  if (!sanitized) {
    callback(new Error('请输入 ASCII 明文'));
    return;
  }
  if (!/^[\x00-\x7F]+$/.test(sanitized)) {
    callback(new Error('仅支持 ASCII 字符'));
    return;
  }
  callback();
};

const binaryOrHex16Validator = createBinaryOrHexValidator(16);

const encryptRules = {
  plaintext: [{ validator: asciiValidator, trigger: 'blur' }],
  key: [{ validator: binaryOrHex16Validator, trigger: 'blur' }]
};

const decryptRules = {
  ciphertext: [{ validator: base64Validator, trigger: 'blur' }],
  key: [{ validator: binaryOrHex16Validator, trigger: 'blur' }],
  iv: [{ validator: binaryOrHex16Validator, trigger: 'blur' }]
};

const prepareBinaryOrHexValue = (value, bits) => {
  const sanitized = sanitizeBinary(value);
  if (new RegExp(`^[01]{${bits}}$`).test(sanitized)) {
    return sanitized;
  }
  return normalizeHex(value, bits / 4);
};

const handleEncrypt = async () => {
  if (!encryptFormRef.value) return;
  encryptResult.value = null;
  const isValid = await encryptFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.encrypt = true;
  try {
    const payload = {
      plaintext: sanitizeAscii(encryptForm.plaintext),
      key: prepareBinaryOrHexValue(encryptForm.key, 16)
    };
    encryptForm.key = payload.key;
    const response = await httpClient.post('/encrypt/cbc', payload);
    const { code, message, data } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = data || {};
    if (!result.ciphertext || !result.iv) {
      throw new Error('服务未返回完整的密文或初始向量');
    }
    encryptResult.value = {
      ciphertext: sanitizeBase64(result.ciphertext),
      iv: sanitizeBinary(result.iv || '')
    };
  } catch (error) {
    const message =
      error.response?.data?.message ||
      error.message ||
      '请求失败，请稍后重试';
    ElMessage.error(message);
  } finally {
    loading.encrypt = false;
  }
};

const handleDecrypt = async () => {
  if (!decryptFormRef.value) return;
  decryptResult.value = '';
  const isValid = await decryptFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.decrypt = true;
  try {
    const payload = {
      ciphertext: sanitizeBase64(decryptForm.ciphertext),
      key: prepareBinaryOrHexValue(decryptForm.key, 16),
      iv: prepareBinaryOrHexValue(decryptForm.iv, 16)
    };
    decryptForm.ciphertext = payload.ciphertext;
    decryptForm.key = payload.key;
    decryptForm.iv = payload.iv;

    const response = await httpClient.post('/decrypt/cbc', payload);
    const { code, message, data } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = data || {};
    decryptResult.value = result.plaintext || '';
    if (!decryptResult.value) {
      ElMessage.warning('解密成功但未返回明文字段');
    }
  } catch (error) {
    const message =
      error.response?.data?.message ||
      error.message ||
      '请求失败，请稍后重试';
    ElMessage.error(message);
  } finally {
    loading.decrypt = false;
  }
};

const resetEncrypt = () => {
  encryptForm.plaintext = '';
  encryptForm.key = '';
  encryptResult.value = null;
  encryptFormRef.value?.clearValidate();
};

const resetDecrypt = () => {
  decryptForm.ciphertext = '';
  decryptForm.key = '';
  decryptForm.iv = '';
  decryptResult.value = '';
  decryptFormRef.value?.clearValidate();
};
</script>

<style scoped>
.panel-card {
  width: 100%;
  border-radius: 16px;
  border: none;
  box-shadow: 0 20px 45px rgba(31, 45, 61, 0.1);
  background: #ffffff;
}

.card-header {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 1.2rem;
  font-weight: 600;
  color: #303133;
}

.card-subtitle {
  margin: 0;
  font-size: 0.95rem;
  color: #606266;
  line-height: 1.6;
}

.tab-intro {
  margin: 0 0 16px;
  font-size: 0.9rem;
  color: #606266;
  line-height: 1.6;
}

.form-actions :deep(.el-form-item__content) {
  display: flex;
  gap: 12px;
}

.result-block {
  margin-top: 16px;
  background: #f5f7fa;
  border-radius: 12px;
  padding: 12px 16px;
}

.result-block :deep(.el-result__title) {
  font-size: 1rem;
}

.result-block :deep(.el-result__subtitle) {
  font-size: 0.95rem;
  word-break: break-all;
  line-height: 1.6;
}

.result-block :deep(.el-result__extra) {
  margin-top: 8px;
}

.iv-display {
  font-size: 0.95rem;
  color: #303133;
  word-break: break-all;
}
</style>
