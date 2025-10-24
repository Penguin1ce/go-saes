<template>
  <el-card shadow="never" class="panel-card" :body-style="{ padding: '24px' }">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <span>操作面板</span>
          <el-tag size="small" type="success" effect="light">16 位二进制</el-tag>
        </div>
        <p class="card-subtitle">
          当前支持16位二进制字符串的加解密操作 TODO: base64 编码支持
        </p>
      </div>
    </template>
    <el-tabs v-model="activeTab">
      <el-tab-pane label="加密" name="encrypt">
        <el-form ref="encryptFormRef" :model="encryptForm" :rules="formRules" label-position="top" @submit.prevent>
          <div class="form-row">
            <el-form-item label="明文（16 位二进制）" prop="plaintext">
              <el-input v-model="encryptForm.plaintext" placeholder="示例：0110010101110100" maxlength="16"
                show-word-limit />
            </el-form-item>
            <el-form-item label="密钥（16 位二进制）" prop="key">
              <el-input v-model="encryptForm.key" placeholder="示例：0001000000010000" maxlength="16" show-word-limit />
            </el-form-item>
          </div>
          <el-form-item>
            <el-button type="primary" :loading="loading.encrypt" @click="handleEncrypt">
              立即加密
            </el-button>
            <el-button @click="resetEncrypt">清空</el-button>
          </el-form-item>
        </el-form>
        <el-result v-if="encryptResult" icon="success" title="加密成功" :sub-title="`密文：${encryptResult}`"
          class="result-block" />
      </el-tab-pane>
      <el-tab-pane label="解密" name="decrypt">
        <el-form ref="decryptFormRef" :model="decryptForm" :rules="formRules" label-position="top" @submit.prevent>
          <div class="form-row">
            <el-form-item label="密文（16 位二进制）" prop="ciphertext">
              <el-input v-model="decryptForm.ciphertext" placeholder="示例：1111001010110011" maxlength="16"
                show-word-limit />
            </el-form-item>
            <el-form-item label="密钥（16 位二进制）" prop="key">
              <el-input v-model="decryptForm.key" placeholder="示例：0001000000010000" maxlength="16" show-word-limit />
            </el-form-item>
          </div>
          <el-form-item>
            <el-button type="primary" :loading="loading.decrypt" @click="handleDecrypt">
              立即解密
            </el-button>
            <el-button @click="resetDecrypt">清空</el-button>
          </el-form-item>
        </el-form>
        <el-result v-if="decryptResult" icon="success" title="解密成功" :sub-title="`明文：${decryptResult}`"
          class="result-block" />
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
  key: ''
});

const loading = reactive({
  encrypt: false,
  decrypt: false
});

const encryptResult = ref('');
const decryptResult = ref('');

const sanitizeBinary = (value) => value.replace(/\s+/g, '').trim();

const binaryValidator = (_rule, value, callback) => {
  if (!value) {
    callback(new Error('请输入二进制字符串'));
    return;
  }
  const sanitized = sanitizeBinary(value);
  if (!/^[01]{16}$/.test(sanitized)) {
    callback(new Error('仅支持 16 位二进制字符（0 或 1）'));
    return;
  }
  callback();
};

const formRules = {
  plaintext: [{ validator: binaryValidator, trigger: 'blur' }],
  ciphertext: [{ validator: binaryValidator, trigger: 'blur' }],
  key: [{ validator: binaryValidator, trigger: 'blur' }]
};

const handleEncrypt = async () => {
  if (!encryptFormRef.value) return;
  encryptResult.value = '';
  const isValid = await encryptFormRef.value.validate().then(() => true).catch(() => false);
  if (!isValid) return;

  loading.encrypt = true;
  try {
    const payload = {
      plaintext: sanitizeBinary(encryptForm.plaintext),
      key: sanitizeBinary(encryptForm.key)
    };
    encryptForm.plaintext = payload.plaintext;
    encryptForm.key = payload.key;

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
      ciphertext: sanitizeBinary(decryptForm.ciphertext),
      key: sanitizeBinary(decryptForm.key)
    };
    decryptForm.ciphertext = payload.ciphertext;
    decryptForm.key = payload.key;

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
  encryptResult.value = '';
  encryptFormRef.value?.clearValidate();
};

const resetDecrypt = () => {
  decryptForm.ciphertext = '';
  decryptForm.key = '';
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
</style>
