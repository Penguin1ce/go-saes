<template>
  <div class="app-shell">
    <header class="app-header">
      <h1>S-AES 加解密作业</h1>
      <p>2025 信息安全导论第 2 次作业</p>
    </header>
    <main class="app-main">
      <encrypt-decrypt-panel />
      <multi-encrypt-panel class="multi-panel" />
      <meet-in-the-middle-panel class="mitm-panel" />
    </main>
  </div>
</template>

<script setup>
import EncryptDecryptPanel from './components/EncryptDecryptPanel.vue';
import MultiEncryptPanel from './components/MultiEncryptPanel.vue';
import MeetInTheMiddlePanel from './components/MeetInTheMiddlePanel.vue';
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
  padding: 56px 24px 64px;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 32px;
}

.app-header {
  width: min(960px, 100%);
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.app-header h1 {
  margin: 0;
  font-size: 2rem;
  color: #303133;
}

.app-header p {
  margin: 0;
  color: #606266;
  line-height: 1.6;
}

.app-main {
  width: min(960px, 100%);
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.multi-panel {
  margin-top: 8px;
}

.mitm-panel {
  margin-top: 8px;
}
</style>
