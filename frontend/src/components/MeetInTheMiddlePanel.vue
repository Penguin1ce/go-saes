<template>
  <el-card shadow="never" class="panel-card" :body-style="{ padding: '24px' }">
    <template #header>
      <div class="card-header">
        <div class="card-title">
          <span>中间相遇攻击面板</span>
          <el-tag size="small" type="info" effect="light">多组明密文匹配</el-tag>
        </div>
        <p class="card-subtitle">
          基于若干明密文对，枚举 K1/K2 组合并执行中间相遇攻击，寻找可能的 32 位密钥。
        </p>
      </div>
    </template>

    <el-form ref="formRef" :model="form" label-position="top" class="attack-form">
      <div class="pair-list">
        <div
          v-for="(pair, index) in form.pairs"
          :key="index"
          class="pair-item"
        >
          <div class="pair-item__header">
            <span>明密文对 {{ index + 1 }}</span>
            <el-button
              v-if="form.pairs.length > 1"
              type="danger"
              link
              size="small"
              @click="removePair(index)"
            >
              移除
            </el-button>
          </div>
          <div class="pair-item__fields">
            <el-form-item
              :prop="`pairs.${index}.plaintext`"
              label="明文（16 位二进制或十六进制）"
              :rules="pairFieldRules.plaintext"
            >
              <el-input
                v-model="pair.plaintext"
                maxlength="18"
                show-word-limit
              />
            </el-form-item>
            <el-form-item
              :prop="`pairs.${index}.ciphertext`"
              label="密文（16 位二进制或十六进制）"
              :rules="pairFieldRules.ciphertext"
            >
              <el-input
                v-model="pair.ciphertext"
                maxlength="18"
                show-word-limit
              />
            </el-form-item>
          </div>
          <el-divider v-if="index < form.pairs.length - 1" />
        </div>
      </div>

      <el-form-item class="form-actions">
        <el-button type="primary" :loading="loading" @click="handleAttack">
          执行中间相遇攻击
        </el-button>
        <el-button type="info" plain @click="addPair">
          新增明密文对
        </el-button>
        <el-button @click="resetForm">
          清空
        </el-button>
      </el-form-item>
    </el-form>

    <div v-if="result" class="result-wrapper">
      <el-alert
        class="result-summary"
        type="success"
        show-icon
        :title="`共匹配到 ${result.count} 组密钥`"
        :closable="false"
      />

      <el-empty
        v-if="result.count === 0"
        description="未匹配到密钥，请尝试补充更多明密文对"
        class="result-empty"
      />

      <el-table
        v-else
        :data="result.keys"
        border
        stripe
        size="small"
        class="result-table"
      >
        <el-table-column label="候选编号" type="index" width="90" align="center" />
        <el-table-column label="K1 (16 位 Hex / Bin)" min-width="220">
          <template #default="{ row }">
            <div class="table-field">
              <span class="field-label">Hex：</span>
              <span>{{ row.k1_hex }}</span>
            </div>
            <div class="table-field">
              <span class="field-label">Bin：</span>
              <span class="mono">{{ row.k1_bin }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="K2 (16 位 Hex / Bin)" min-width="220">
          <template #default="{ row }">
            <div class="table-field">
              <span class="field-label">Hex：</span>
              <span>{{ row.k2_hex }}</span>
            </div>
            <div class="table-field">
              <span class="field-label">Bin：</span>
              <span class="mono">{{ row.k2_bin }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="组合密钥 (32 位 Hex / Bin)" min-width="260">
          <template #default="{ row }">
            <div class="table-field">
              <span class="field-label">Hex：</span>
              <span>{{ row.combined_hex }}</span>
            </div>
            <div class="table-field">
              <span class="field-label">Bin：</span>
              <span class="mono">{{ row.combined_bin }}</span>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </el-card>
</template>

<script setup>
import { reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import httpClient from '../api/httpClient';

const formRef = ref();
const loading = ref(false);
const result = ref(null);

const form = reactive({
  pairs: [
    { plaintext: '', ciphertext: '' }
  ]
});

const pairFieldRules = {
  plaintext: [
    { required: true, message: '请输入明文', trigger: 'blur' }
  ],
  ciphertext: [
    { required: true, message: '请输入密文', trigger: 'blur' }
  ]
};

const addPair = () => {
  form.pairs.push({ plaintext: '', ciphertext: '' });
  formRef.value?.clearValidate();
};

const removePair = (index) => {
  form.pairs.splice(index, 1);
  formRef.value?.clearValidate();
};

const resetForm = () => {
  form.pairs = [{ plaintext: '', ciphertext: '' }];
  result.value = null;
  formRef.value?.clearValidate();
};

const normalizePairs = () =>
  form.pairs.map(({ plaintext, ciphertext }) => ({
    plaintext: plaintext.trim(),
    ciphertext: ciphertext.trim()
  }));

const hasEmptyField = (pairs) =>
  pairs.some((pair) => !pair.plaintext || !pair.ciphertext);

const handleAttack = async () => {
  if (!formRef.value) {
    return;
  }

  try {
    await formRef.value.validate();
  } catch (validationError) {
    ElMessage.warning('请完善所有明文与密文输入');
    return;
  }

  const payloadPairs = normalizePairs();
  if (hasEmptyField(payloadPairs)) {
    ElMessage.warning('请完善所有明文与密文输入');
    return;
  }

  loading.value = true;
  try {
    const { data } = await httpClient.post('/attack/meet-in-the-middle', {
      pairs: payloadPairs
    });

    if (data.code !== 0) {
      throw new Error(data.message || '服务返回错误');
    }

    const payload = data.data ?? { count: 0, keys: [] };
    result.value = {
      count: Number(payload.count) || 0,
      keys: Array.isArray(payload.keys) ? payload.keys : []
    };

    if (result.value.count === 0 || result.value.keys.length === 0) {
      result.value.count = 0;
      result.value.keys = [];
      ElMessage.info('未匹配到任何候选密钥，请尝试补充更多明密文对');
    } else {
      ElMessage.success(`匹配到 ${result.value.count} 组候选密钥`);
    }
  } catch (error) {
    const message = error?.message || '请求失败，请稍后重试';
    ElMessage.error(message);
  } finally {
    loading.value = false;
  }
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

.attack-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.pair-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.pair-item {
  padding: 12px 16px;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  background-color: #fafcff;
}

.pair-item__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  font-weight: 600;
  color: #303133;
}

.pair-item__fields {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px 24px;
}

.form-actions {
  margin-top: 8px;
}

.result-wrapper {
  margin-top: 24px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.result-summary {
  border-radius: 8px;
}

.result-empty {
  padding: 32px 0;
}

.result-table {
  border-radius: 8px;
  overflow: hidden;
}

.table-field {
  display: flex;
  gap: 8px;
  line-height: 1.6;
}

.field-label {
  color: #909399;
  flex-shrink: 0;
}

.mono {
  font-family: 'Fira Code', 'SFMono-Regular', Menlo, Monaco, Consolas, monospace;
}
</style>
