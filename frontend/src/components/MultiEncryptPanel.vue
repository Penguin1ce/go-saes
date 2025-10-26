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
              <el-form-item label="密钥（32 位二进制）" prop="key">
                <el-input v-model="encryptBinaryForm.key" placeholder="示例：00010000000100001111000011110000"
                  maxlength="32" show-word-limit />
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

        <template v-else>
          <el-form ref="encryptBase64FormRef" :model="encryptBase64Form" :rules="asciiFormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="明文（ASCII，自动按 16 bit 补齐）" prop="plaintext">
                <el-input v-model="encryptBase64Form.plaintext" placeholder="示例：et 或 ete" />
              </el-form-item>
              <el-form-item label="密钥（32 位二进制）" prop="key">
                <el-input v-model="encryptBase64Form.key" placeholder="示例：00010000000100001111000011110000"
                  maxlength="32" show-word-limit />
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
            : `密文（二进制）：${encryptResult}`" class="result-block" />
      </el-tab-pane>
      <el-tab-pane label="解密" name="decrypt">
        <div class="mode-switch">
          <el-radio-group v-model="decryptMode" size="small">
            <el-radio-button label="binary">16 位二进制</el-radio-button>
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
              <el-form-item label="密钥（32 位二进制）" prop="key">
                <el-input v-model="decryptBinaryForm.key" placeholder="示例：00010000000100001111000011110000"
                  maxlength="32" show-word-limit />
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

        <template v-else>
          <el-form ref="decryptBase64FormRef" :model="decryptBase64Form" :rules="base64FormRules" label-position="top"
            @submit.prevent>
            <div class="form-row">
              <el-form-item label="密文（Base64）" prop="ciphertext">
                <el-input v-model="decryptBase64Form.ciphertext" placeholder="示例：mSA=" />
              </el-form-item>
              <el-form-item label="密钥（32 位二进制）" prop="key">
                <el-input v-model="decryptBase64Form.key" placeholder="示例：00010000000100001111000011110000"
                  maxlength="32" show-word-limit />
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
            : `明文（二进制）：${decryptResult}`" class="result-block" />
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { reactive, ref, watch } from 'vue';
import { ElMessage } from 'element-plus';
import httpClient from '../api/httpClient';

const activeTab = ref('encrypt');
const encryptMode = ref('binary');
const decryptMode = ref('binary');

const encryptBinaryFormRef = ref();
const encryptBase64FormRef = ref();
const decryptBinaryFormRef = ref();
const decryptBase64FormRef = ref();

const encryptBinaryForm = reactive({
  plaintext: '',
  key: ''
});

const encryptBase64Form = reactive({
  plaintext: '',
  key: ''
});

const decryptBinaryForm = reactive({
  ciphertext: '',
  key: ''
});

const decryptBase64Form = reactive({
  ciphertext: '',
  key: ''
});

const loading = reactive({
  encryptBinary: false,
  encryptBase64: false,
  decryptBinary: false,
  decryptBase64: false
});

const encryptResult = ref('');
const encryptResultMode = ref('binary');
const decryptResult = ref('');
const decryptResultMode = ref('binary');

const sanitizeBinary = (value) => value.replace(/\s+/g, '').trim();
const sanitizeBase64 = (value) => value.replace(/\s+/g, '');

const createBinaryValidator = (expectedLength) => {
  const pattern = new RegExp(`^[01]{${expectedLength}}$`);
  return (_rule, value, callback) => {
    if (!value) {
      callback(new Error(`请输入 ${expectedLength} 位二进制字符串`));
      return;
    }
    const sanitized = sanitizeBinary(value);
    if (!pattern.test(sanitized)) {
      callback(new Error(`仅支持 ${expectedLength} 位二进制字符（0 或 1）`));
      return;
    }
    callback();
  };
};

const binary16Validator = createBinaryValidator(16);
const binary32Validator = createBinaryValidator(32);

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

const binaryFormRules = {
  plaintext: [{ validator: binary16Validator, trigger: 'blur' }],
  ciphertext: [{ validator: binary16Validator, trigger: 'blur' }],
  key: [{ validator: binary32Validator, trigger: 'blur' }]
};

const base64FormRules = {
  ciphertext: [{ validator: base64Validator, trigger: 'blur' }],
  key: [{ validator: binary32Validator, trigger: 'blur' }]
};

const asciiFormRules = {
  plaintext: [{ validator: asciiValidator, trigger: 'blur' }],
  key: [{ validator: binary32Validator, trigger: 'blur' }]
};

watch(encryptMode, (mode) => {
  encryptResult.value = '';
  encryptResultMode.value = mode;
  if (mode === 'binary') {
    encryptBase64FormRef.value?.clearValidate();
  } else {
    encryptBinaryFormRef.value?.clearValidate();
  }
});

watch(decryptMode, (mode) => {
  decryptResult.value = '';
  decryptResultMode.value = mode;
  if (mode === 'binary') {
    decryptBase64FormRef.value?.clearValidate();
  } else {
    decryptBinaryFormRef.value?.clearValidate();
  }
});

const handleEncryptBinary = async () => {
  if (!encryptBinaryFormRef.value) return;
  encryptResult.value = '';
  const isValid = await encryptBinaryFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.encryptBinary = true;
  try {
    const payload = {
      plaintext: sanitizeBinary(encryptBinaryForm.plaintext),
      key: sanitizeBinary(encryptBinaryForm.key)
    };
    encryptBinaryForm.plaintext = payload.plaintext;
    encryptBinaryForm.key = payload.key;

    const response = await httpClient.post('/encrypt', {
      plaintext: payload.plaintext,
      key: payload.key
    });
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    encryptResult.value = result.ciphertext || '';
    encryptResultMode.value = 'binary';
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

const handleEncryptBase64 = async () => {
  if (!encryptBase64FormRef.value) return;
  encryptResult.value = '';
  const isValid = await encryptBase64FormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.encryptBase64 = true;
  try {
    const payload = {
      plaintext: encryptBase64Form.plaintext,
      key: sanitizeBinary(encryptBase64Form.key)
    };
    encryptBase64Form.key = payload.key;

    const response = await httpClient.post('/encrypt/base64', {
      plaintext: payload.plaintext,
      key: payload.key
    });
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    encryptResult.value = result.ciphertext || '';
    encryptResultMode.value = 'base64';
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
      key: sanitizeBinary(decryptBinaryForm.key)
    };
    decryptBinaryForm.ciphertext = payload.ciphertext;
    decryptBinaryForm.key = payload.key;

    const response = await httpClient.post('/decrypt', {
      ciphertext: payload.ciphertext,
      key: payload.key
    });
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    decryptResult.value = result.plaintext || '';
    decryptResultMode.value = 'binary';
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

const handleDecryptBase64 = async () => {
  if (!decryptBase64FormRef.value) return;
  decryptResult.value = '';
  const isValid = await decryptBase64FormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.decryptBase64 = true;
  try {
    const payload = {
      ciphertext: sanitizeBase64(decryptBase64Form.ciphertext),
      key: sanitizeBinary(decryptBase64Form.key)
    };
    decryptBase64Form.ciphertext = payload.ciphertext;
    decryptBase64Form.key = payload.key;

    const response = await httpClient.post('/decrypt/base64', {
      ciphertext: payload.ciphertext,
      key: payload.key
    });
    const { code, message, data: payloadData } = response.data || {};
    if (code !== 0) {
      throw new Error(message || '服务处理失败');
    }
    const result = payloadData || {};
    decryptResult.value = result.plaintext || '';
    decryptResultMode.value = 'base64';
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
  encryptResultMode.value = encryptMode.value;
  encryptBinaryFormRef.value?.clearValidate();
};

const resetEncryptBase64 = () => {
  encryptBase64Form.plaintext = '';
  encryptBase64Form.key = '';
  encryptResult.value = '';
  encryptResultMode.value = encryptMode.value;
  encryptBase64FormRef.value?.clearValidate();
};

const resetDecryptBinary = () => {
  decryptBinaryForm.ciphertext = '';
  decryptBinaryForm.key = '';
  decryptResult.value = '';
  decryptResultMode.value = decryptMode.value;
  decryptBinaryFormRef.value?.clearValidate();
};

const resetDecryptBase64 = () => {
  decryptBase64Form.ciphertext = '';
  decryptBase64Form.key = '';
  decryptResult.value = '';
  decryptResultMode.value = decryptMode.value;
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
