<template>
  <el-card shadow="never" class="panel-card" :body-style="{ padding: '24px' }">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <span>多重加解密面板</span>
          <el-tag size="small" type="warning" effect="light">16 位分组 / 32 位密钥</el-tag>
        </div>
        <p class="card-subtitle">
          使用 32 位密钥（K1 + K2）执行顺序多重 S-AES 加解密操作
        </p>
      </div>
    </template>
    <el-tabs v-model="activeTab">
      <el-tab-pane label="加密" name="encrypt">
        <div class="mode-switch">
          <el-radio-group v-model="encryptMode" size="small">
            <el-radio-button label="binary">16 位二进制</el-radio-button>
            <el-radio-button label="hex">16 位十六进制</el-radio-button>
            <el-radio-button label="base64">Base64</el-radio-button>
          </el-radio-group>
        </div>

        <template v-if="encryptMode === 'binary'">
          <el-form ref="encryptBinaryFormRef" :model="encryptBinaryForm" :rules="binaryFormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="明文（16 位二进制）" prop="plaintext">
                <el-input v-model="encryptBinaryForm.plaintext" placeholder="示例：0110010101110100" maxlength="16"
                  show-word-limit />
              </el-form-item>
              <el-form-item label="密钥（32 位二进制或十六进制）" prop="key">
                <el-input v-model="encryptBinaryForm.key" placeholder="示例：00010000000100001111000011110000 或 0x1010F0F0"
                  maxlength="34" show-word-limit />
              </el-form-item>
            </div>
            <el-form-item>
              <el-button type="primary" :loading="loading.encryptBinary" @click="handleEncryptBinary">
                立即加密
              </el-button>
              <el-button @click="resetEncryptBinary">清空</el-button>
            </el-form-item>
          </el-form>
        </template>

        <template v-else-if="encryptMode === 'hex'">
          <el-form ref="encryptHexFormRef" :model="encryptHexForm" :rules="hexFormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="明文（16 位十六进制）" prop="plaintext">
                <el-input v-model="encryptHexForm.plaintext" placeholder="示例：0x6574 或 6574" maxlength="6"
                  show-word-limit />
              </el-form-item>
              <el-form-item label="密钥（32 位十六进制）" prop="key">
                <el-input v-model="encryptHexForm.key" placeholder="示例：0x1010F0F0 或 1010F0F0" maxlength="10"
                  show-word-limit />
              </el-form-item>
            </div>
            <el-form-item>
              <el-button type="primary" :loading="loading.encryptHex" @click="handleEncryptHex">
                立即加密
              </el-button>
              <el-button @click="resetEncryptHex">清空</el-button>
            </el-form-item>
          </el-form>
        </template>

        <template v-else>
          <el-form ref="encryptBase64FormRef" :model="encryptBase64Form" :rules="asciiFormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="明文（ASCII，自动按 16 bit 补齐）" prop="plaintext">
                <el-input v-model="encryptBase64Form.plaintext" placeholder="示例：et 或 ete" />
              </el-form-item>
              <el-form-item label="密钥（32 位二进制或十六进制）" prop="key">
                <el-input v-model="encryptBase64Form.key" placeholder="示例：00010000000100001111000011110000 或 0x1010F0F0"
                  maxlength="34" show-word-limit />
              </el-form-item>
            </div>
            <el-form-item>
              <el-button type="primary" :loading="loading.encryptBase64" @click="handleEncryptBase64">
                立即加密
              </el-button>
              <el-button @click="resetEncryptBase64">清空</el-button>
            </el-form-item>
          </el-form>
        </template>

        <el-result v-if="encryptResult" icon="success" :title="encryptResultMode === 'base64' ? 'Base64 加密成功' : '加密成功'"
          :sub-title="encryptResultMode === 'base64'
            ? `密文（Base64）：${encryptResult}`
            : encryptResultMode === 'hex'
              ? `密文（十六进制）：${binaryToHex(encryptResult)}（二进制：${encryptResult}）`
              : `密文（二进制）：${encryptResult}`" class="result-block" />
      </el-tab-pane>
      <el-tab-pane label="解密" name="decrypt">
        <div class="mode-switch">
          <el-radio-group v-model="decryptMode" size="small">
            <el-radio-button label="binary">16 位二进制</el-radio-button>
            <el-radio-button label="hex">16 位十六进制</el-radio-button>
            <el-radio-button label="base64">Base64</el-radio-button>
          </el-radio-group>
        </div>

        <template v-if="decryptMode === 'binary'">
          <el-form ref="decryptBinaryFormRef" :model="decryptBinaryForm" :rules="binaryFormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="密文（16 位二进制）" prop="ciphertext">
                <el-input v-model="decryptBinaryForm.ciphertext" placeholder="示例：1001100100100000" maxlength="16"
                  show-word-limit />
              </el-form-item>
              <el-form-item label="密钥（32 位二进制或十六进制）" prop="key">
                <el-input v-model="decryptBinaryForm.key" placeholder="示例：00010000000100001111000011110000 或 0x1010F0F0"
                  maxlength="34" show-word-limit />
              </el-form-item>
            </div>
            <el-form-item>
              <el-button type="primary" :loading="loading.decryptBinary" @click="handleDecryptBinary">
                立即解密
              </el-button>
              <el-button @click="resetDecryptBinary">清空</el-button>
            </el-form-item>
          </el-form>
        </template>

        <template v-else-if="decryptMode === 'hex'">
          <el-form ref="decryptHexFormRef" :model="decryptHexForm" :rules="cipherHexFormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="密文（16 位十六进制）" prop="ciphertext">
                <el-input v-model="decryptHexForm.ciphertext" placeholder="示例：0x3B97 或 3B97" maxlength="6"
                  show-word-limit />
              </el-form-item>
              <el-form-item label="密钥（32 位十六进制）" prop="key">
                <el-input v-model="decryptHexForm.key" placeholder="示例：0x1010F0F0 或 1010F0F0" maxlength="10"
                  show-word-limit />
              </el-form-item>
            </div>
            <el-form-item>
              <el-button type="primary" :loading="loading.decryptHex" @click="handleDecryptHex">
                立即解密
              </el-button>
              <el-button @click="resetDecryptHex">清空</el-button>
            </el-form-item>
          </el-form>
        </template>

        <template v-else>
          <el-form ref="decryptBase64FormRef" :model="decryptBase64Form" :rules="base64FormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="密文（Base64）" prop="ciphertext">
                <el-input v-model="decryptBase64Form.ciphertext" placeholder="示例：mSA=" />
              </el-form-item>
              <el-form-item label="密钥（32 位二进制或十六进制）" prop="key">
                <el-input v-model="decryptBase64Form.key" placeholder="示例：00010000000100001111000011110000 或 0x1010F0F0"
                  maxlength="34" show-word-limit />
              </el-form-item>
            </div>
            <el-form-item>
              <el-button type="primary" :loading="loading.decryptBase64" @click="handleDecryptBase64">
                立即解密
              </el-button>
              <el-button @click="resetDecryptBase64">清空</el-button>
            </el-form-item>
          </el-form>
        </template>

        <el-result v-if="decryptResult" icon="success" :title="decryptResultMode === 'base64' ? 'Base64 解密成功' : '解密成功'"
          :sub-title="decryptResultMode === 'base64'
            ? `明文（ASCII）：${decryptResult}`
            : decryptResultMode === 'hex'
              ? `明文（十六进制）：${binaryToHex(decryptResult)}（二进制：${decryptResult}）`
              : `明文（二进制）：${decryptResult}`" class="result-block" />
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { reactive, ref, watch } from 'vue';
import { ElMessage } from 'element-plus';
import httpClient from '../api/httpClient';

const BLOCK_BITS = 16;
const BLOCK_HEX_DIGITS = 4;
const KEY_BITS = 32;
const KEY_HEX_DIGITS = 8;

const activeTab = ref('encrypt');
const encryptMode = ref('binary');
const decryptMode = ref('binary');

const encryptBinaryFormRef = ref();
const encryptHexFormRef = ref();
const encryptBase64FormRef = ref();
const decryptBinaryFormRef = ref();
const decryptHexFormRef = ref();
const decryptBase64FormRef = ref();

const encryptBinaryForm = reactive({ plaintext: '', key: '' });
const encryptHexForm = reactive({ plaintext: '', key: '' });
const encryptBase64Form = reactive({ plaintext: '', key: '' });
const decryptBinaryForm = reactive({ ciphertext: '', key: '' });
const decryptHexForm = reactive({ ciphertext: '', key: '' });
const decryptBase64Form = reactive({ ciphertext: '', key: '' });

const loading = reactive({
  encryptBinary: false,
  encryptHex: false,
  encryptBase64: false,
  decryptBinary: false,
  decryptHex: false,
  decryptBase64: false
});

const encryptResult = ref('');
const encryptResultMode = ref('binary');
const decryptResult = ref('');
const decryptResultMode = ref('binary');

const sanitizeBinary = (value) => value.replace(/\s+/g, '').trim();
const sanitizeHex = (value) => value.replace(/\s+/g, '').trim();
const sanitizeBase64 = (value) => value.replace(/\s+/g, '');

const createBinaryValidator = (bits) => (_rule, value, callback) => {
  if (!value) {
    callback(new Error(`请输入 ${bits} 位二进制字符串`));
    return;
  }
  const sanitized = sanitizeBinary(value);
  if (!new RegExp(`^[01]{${bits}}$`).test(sanitized)) {
    callback(new Error(`仅支持 ${bits} 位二进制字符（0 或 1）`));
    return;
  }
  callback();
};

const normalizeHex = (value, hexDigits) => {
  const sanitized = sanitizeHex(value);
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

const createHexValidator = (hexDigits) => (_rule, value, callback) => {
  try {
    normalizeHex(value, hexDigits);
    callback();
  } catch (error) {
    callback(error instanceof Error ? error : new Error('十六进制格式不正确'));
  }
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

const base64Validator = (_rule, value, callback) => {
  if (!value) {
    callback(new Error('请输入 Base64 密文'));
    return;
  }
  const sanitized = sanitizeBase64(value);
  if (sanitized.length === 0 || sanitized.length % 4 !== 0) {
    callback(new Error('请输入合法的 Base64 字符串'));
    return;
  }
  const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  if (!base64Pattern.test(sanitized)) {
    callback(new Error('请输入合法的 Base64 字符串'));
    return;
  }
  callback();
};

const asciiValidator = (_rule, value, callback) => {
  if (!value) {
    callback(new Error('请输入 ASCII 明文'));
    return;
  }
  if (!/^[\x00-\x7F]+$/.test(value)) {
    callback(new Error('仅支持 ASCII 字符'));
    return;
  }
  callback();
};

const binaryBlockValidator = createBinaryValidator(BLOCK_BITS);
const binaryOrHexKeyValidator = createBinaryOrHexValidator(KEY_BITS);
const hexBlockValidator = createHexValidator(BLOCK_HEX_DIGITS);
const hexKeyValidator = createHexValidator(KEY_HEX_DIGITS);

const binaryFormRules = {
  plaintext: [{ validator: binaryBlockValidator, trigger: 'blur' }],
  ciphertext: [{ validator: binaryBlockValidator, trigger: 'blur' }],
  key: [{ validator: binaryOrHexKeyValidator, trigger: 'blur' }]
};

const hexFormRules = {
  plaintext: [{ validator: hexBlockValidator, trigger: 'blur' }],
  key: [{ validator: hexKeyValidator, trigger: 'blur' }]
};

const cipherHexFormRules = {
  ciphertext: [{ validator: hexBlockValidator, trigger: 'blur' }],
  key: [{ validator: hexKeyValidator, trigger: 'blur' }]
};

const base64FormRules = {
  ciphertext: [{ validator: base64Validator, trigger: 'blur' }],
  key: [{ validator: binaryOrHexKeyValidator, trigger: 'blur' }]
};

const asciiFormRules = {
  plaintext: [{ validator: asciiValidator, trigger: 'blur' }],
  key: [{ validator: binaryOrHexKeyValidator, trigger: 'blur' }]
};

const setEncryptResultMode = (mode) => {
  encryptResultMode.value = mode === 'base64' ? 'base64' : mode === 'hex' ? 'hex' : 'binary';
};

const setDecryptResultMode = (mode) => {
  decryptResultMode.value = mode === 'base64' ? 'base64' : mode === 'hex' ? 'hex' : 'binary';
};

watch(encryptMode, (mode) => {
  encryptResult.value = '';
  setEncryptResultMode(mode);
  if (mode === 'binary') {
    encryptHexFormRef.value?.clearValidate();
    encryptBase64FormRef.value?.clearValidate();
  } else if (mode === 'hex') {
    encryptBinaryFormRef.value?.clearValidate();
    encryptBase64FormRef.value?.clearValidate();
  } else {
    encryptBinaryFormRef.value?.clearValidate();
    encryptHexFormRef.value?.clearValidate();
  }
});

watch(decryptMode, (mode) => {
  decryptResult.value = '';
  setDecryptResultMode(mode);
  if (mode === 'binary') {
    decryptHexFormRef.value?.clearValidate();
    decryptBase64FormRef.value?.clearValidate();
  } else if (mode === 'hex') {
    decryptBinaryFormRef.value?.clearValidate();
    decryptBase64FormRef.value?.clearValidate();
  } else {
    decryptBinaryFormRef.value?.clearValidate();
    decryptHexFormRef.value?.clearValidate();
  }
});

const prepareBinaryOrHexValue = (value, bits) => {
  const sanitized = sanitizeBinary(value);
  if (new RegExp(`^[01]{${bits}}$`).test(sanitized)) {
    return sanitized;
  }
  return normalizeHex(value, bits / 4);
};

const binaryToHex = (binary) => {
  if (!binary || !/^[01]+$/.test(binary)) return '';
  const paddedLength = Math.ceil(binary.length / 4) * 4;
  const parsed = parseInt(binary.padStart(paddedLength, '0'), 2);
  if (Number.isNaN(parsed)) return '';
  return `0x${parsed.toString(16).toUpperCase().padStart(paddedLength / 4, '0')}`;
};

const handleEncryptBinary = async () => {
  if (!encryptBinaryFormRef.value) return;
  encryptResult.value = '';
  const isValid = await encryptBinaryFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.encryptBinary = true;
  try {
    const payload = {
      plaintext: sanitizeBinary(encryptBinaryForm.plaintext),
      key: prepareBinaryOrHexValue(encryptBinaryForm.key, KEY_BITS)
    };
    encryptBinaryForm.plaintext = payload.plaintext;
    encryptBinaryForm.key = payload.key;

    const response = await httpClient.post('/encrypt', payload);
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    encryptResult.value = result.ciphertext || '';
    setEncryptResultMode('binary');
    if (!encryptResult.value) {
      ElMessage.warning('加密成功但未返回密文字段');
    }
  } catch (error) {
    const message =
      error.response?.data?.message ||
      error.message ||
      '请求失败，请稍后重试';
    ElMessage.error(message);
  } finally {
    loading.encryptBinary = false;
  }
};

const handleEncryptHex = async () => {
  if (!encryptHexFormRef.value) return;
  encryptResult.value = '';
  const isValid = await encryptHexFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.encryptHex = true;
  try {
    const payload = {
      plaintext: normalizeHex(encryptHexForm.plaintext, BLOCK_HEX_DIGITS),
      key: normalizeHex(encryptHexForm.key, KEY_HEX_DIGITS)
    };
    encryptHexForm.plaintext = payload.plaintext;
    encryptHexForm.key = payload.key;

    const response = await httpClient.post('/encrypt', payload);
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    encryptResult.value = result.ciphertext || '';
    setEncryptResultMode('hex');
    if (!encryptResult.value) {
      ElMessage.warning('加密成功但未返回密文字段');
    }
  } catch (error) {
    const message =
      error.response?.data?.message ||
      error.message ||
      '请求失败，请稍后重试';
    ElMessage.error(message);
  } finally {
    loading.encryptHex = false;
  }
};

const handleEncryptBase64 = async () => {
  if (!encryptBase64FormRef.value) return;
  encryptResult.value = '';
  const isValid = await encryptBase64FormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.encryptBase64 = true;
  try {
    const payload = {
      plaintext: encryptBase64Form.plaintext,
      key: prepareBinaryOrHexValue(encryptBase64Form.key, KEY_BITS)
    };
    encryptBase64Form.key = payload.key;

    const response = await httpClient.post('/encrypt/base64', payload);
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    encryptResult.value = result.ciphertext || '';
    setEncryptResultMode('base64');
    if (!encryptResult.value) {
      ElMessage.warning('加密成功但未返回密文字段');
    }
  } catch (error) {
    const message =
      error.response?.data?.message ||
      error.message ||
      '请求失败，请稍后重试';
    ElMessage.error(message);
  } finally {
    loading.encryptBase64 = false;
  }
};

const handleDecryptBinary = async () => {
  if (!decryptBinaryFormRef.value) return;
  decryptResult.value = '';
  const isValid = await decryptBinaryFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.decryptBinary = true;
  try {
    const payload = {
      ciphertext: sanitizeBinary(decryptBinaryForm.ciphertext),
      key: prepareBinaryOrHexValue(decryptBinaryForm.key, KEY_BITS)
    };
    decryptBinaryForm.ciphertext = payload.ciphertext;
    decryptBinaryForm.key = payload.key;

    const response = await httpClient.post('/decrypt', payload);
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    decryptResult.value = result.plaintext || '';
    setDecryptResultMode('binary');
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
    loading.decryptBinary = false;
  }
};

const handleDecryptHex = async () => {
  if (!decryptHexFormRef.value) return;
  decryptResult.value = '';
  const isValid = await decryptHexFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.decryptHex = true;
  try {
    const payload = {
      ciphertext: normalizeHex(decryptHexForm.ciphertext, BLOCK_HEX_DIGITS),
      key: normalizeHex(decryptHexForm.key, KEY_HEX_DIGITS)
    };
    decryptHexForm.ciphertext = payload.ciphertext;
    decryptHexForm.key = payload.key;

    const response = await httpClient.post('/decrypt', payload);
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    decryptResult.value = result.plaintext || '';
    setDecryptResultMode('hex');
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
    loading.decryptHex = false;
  }
};

const handleDecryptBase64 = async () => {
  if (!decryptBase64FormRef.value) return;
  decryptResult.value = '';
  const isValid = await decryptBase64FormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.decryptBase64 = true;
  try {
    const payload = {
      ciphertext: sanitizeBase64(decryptBase64Form.ciphertext),
      key: prepareBinaryOrHexValue(decryptBase64Form.key, KEY_BITS)
    };
    decryptBase64Form.ciphertext = payload.ciphertext;
    decryptBase64Form.key = payload.key;

    const response = await httpClient.post('/decrypt/base64', payload);
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    decryptResult.value = result.plaintext || '';
    setDecryptResultMode('base64');
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
    loading.decryptBase64 = false;
  }
};

const resetEncryptBinary = () => {
  encryptBinaryForm.plaintext = '';
  encryptBinaryForm.key = '';
  encryptResult.value = '';
  setEncryptResultMode(encryptMode.value);
  encryptBinaryFormRef.value?.clearValidate();
};

const resetEncryptHex = () => {
  encryptHexForm.plaintext = '';
  encryptHexForm.key = '';
  encryptResult.value = '';
  setEncryptResultMode(encryptMode.value);
  encryptHexFormRef.value?.clearValidate();
};

const resetEncryptBase64 = () => {
  encryptBase64Form.plaintext = '';
  encryptBase64Form.key = '';
  encryptResult.value = '';
  setEncryptResultMode(encryptMode.value);
  encryptBase64FormRef.value?.clearValidate();
};

const resetDecryptBinary = () => {
  decryptBinaryForm.ciphertext = '';
  decryptBinaryForm.key = '';
  decryptResult.value = '';
  setDecryptResultMode(decryptMode.value);
  decryptBinaryFormRef.value?.clearValidate();
};

const resetDecryptHex = () => {
  decryptHexForm.ciphertext = '';
  decryptHexForm.key = '';
  decryptResult.value = '';
  setDecryptResultMode(decryptMode.value);
  decryptHexFormRef.value?.clearValidate();
};

const resetDecryptBase64 = () => {
  decryptBase64Form.ciphertext = '';
  decryptBase64Form.key = '';
  decryptResult.value = '';
  setDecryptResultMode(decryptMode.value);
  decryptBase64FormRef.value?.clearValidate();
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
  color: #909399;
  font-size: 0.92rem;
}

.form-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1rem;
}

.result-block {
  margin-top: 1.5rem;
}

.mode-switch {
  margin-bottom: 1rem;
}
</style>
