<template>
  <div id="app">
    <el-container>
      <el-aside width="200px">
        <el-menu :default-active="currentView" router>
          <el-menu-item index="dashboard" @click="currentView='dashboard'">
            仪表盘
          </el-menu-item>
          <el-menu-item index="alerts" @click="currentView='alerts'">
            告警管理
          </el-menu-item>
          <el-submenu index="rules">
            <template slot="title">规则管理</template>
            <el-menu-item index="detection-rules" @click="currentView='detection-rules'">
              检测规则
            </el-menu-item>
            <el-menu-item index="correlation-rules" @click="currentView='correlation-rules'">
              关联规则
            </el-menu-item>
          </el-submenu>
          <el-menu-item index="correlation-alerts" @click="currentView='correlation-alerts'">
            关联告警
          </el-menu-item>
          <el-menu-item index="settings" @click="currentView='settings'">
            系统设置
          </el-menu-item>
        </el-menu>
      </el-aside>
      
      <el-main>
        <component :is="currentView"></component>
      </el-main>
    </el-container>
  </div>
</template>

<script>
import Dashboard from './components/Dashboard.vue'
import Alerts from './components/Alerts.vue'
import DetectionRules from './components/DetectionRules.vue'
import CorrelationRules from './components/CorrelationRules.vue'
import CorrelationAlerts from './components/CorrelationAlerts.vue'
import Settings from './components/Settings.vue'

export default {
  name: 'App',
  components: {
    Dashboard,
    Alerts,
    DetectionRules,
    CorrelationRules,
    CorrelationAlerts,
    Settings
  },
  data() {
    return {
      currentView: 'dashboard'
    }
  }
}
</script>

<style>
#app {
  font-family: Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
  height: 100vh;
}

.el-container {
  height: 100%;
}

.el-aside {
  background-color: #304156;
}

.el-menu {
  border-right: none;
}

.el-main {
  padding: 20px;
  background-color: #f0f2f5;
}
</style> 