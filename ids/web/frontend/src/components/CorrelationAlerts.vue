<template>
  <div class="correlation-alerts">
    <el-card class="alert-card">
      <div slot="header" class="clearfix">
        <span>关联告警</span>
        <el-button-group style="float: right">
          <el-button size="small" @click="refresh">刷新</el-button>
          <el-button size="small" type="primary" @click="exportAlerts">导出</el-button>
        </el-button-group>
      </div>

      <!-- 筛选条件 -->
      <el-form :inline="true" :model="filterForm" class="filter-form">
        <el-form-item label="时间范围">
          <el-date-picker
            v-model="filterForm.timeRange"
            type="datetimerange"
            range-separator="至"
            start-placeholder="开始时间"
            end-placeholder="结束时间"
            :picker-options="pickerOptions">
          </el-date-picker>
        </el-form-item>
        <el-form-item label="规则名称">
          <el-select v-model="filterForm.ruleName" clearable placeholder="选择规则">
            <el-option
              v-for="rule in rules"
              :key="rule.name"
              :label="rule.name"
              :value="rule.name">
            </el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="严重程度">
          <el-select v-model="filterForm.severity" clearable placeholder="选择级别">
            <el-option label="低" value="low"></el-option>
            <el-option label="中" value="medium"></el-option>
            <el-option label="高" value="high"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleFilter">查询</el-button>
          <el-button @click="resetFilter">重置</el-button>
        </el-form-item>
      </el-form>

      <!-- 告警列表 -->
      <el-table :data="alerts" style="width: 100%">
        <el-table-column prop="timestamp" label="时间" width="180">
          <template slot-scope="scope">
            {{ formatTime(scope.row.timestamp) }}
          </template>
        </el-table-column>
        <el-table-column prop="rule_name" label="规则名称" width="180">
        </el-table-column>
        <el-table-column prop="severity" label="严重程度" width="100">
          <template slot-scope="scope">
            <el-tag :type="getSeverityType(scope.row.severity)">
              {{ scope.row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="events_count" label="事件数量" width="100">
        </el-table-column>
        <el-table-column prop="description" label="描述">
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template slot-scope="scope">
            <el-button size="mini" @click="showDetails(scope.row)">
              详情
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination-container">
        <el-pagination
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
          :current-page="currentPage"
          :page-sizes="[10, 20, 50, 100]"
          :page-size="pageSize"
          layout="total, sizes, prev, pager, next, jumper"
          :total="total">
        </el-pagination>
      </div>
    </el-card>

    <!-- 详情对话框 -->
    <el-dialog title="告警详情" :visible.sync="detailsVisible" width="80%">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="规则名称">{{ currentAlert.rule_name }}</el-descriptions-item>
        <el-descriptions-item label="严重程度">
          <el-tag :type="getSeverityType(currentAlert.severity)">
            {{ currentAlert.severity }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="首次事件时间">
          {{ formatTime(currentAlert.first_event_time) }}
        </el-descriptions-item>
        <el-descriptions-item label="最后事件时间">
          {{ formatTime(currentAlert.last_event_time) }}
        </el-descriptions-item>
        <el-descriptions-item label="事件总数">{{ currentAlert.events_count }}</el-descriptions-item>
        <el-descriptions-item label="描述">{{ currentAlert.description }}</el-descriptions-item>
      </el-descriptions>

      <div class="related-events">
        <h3>相关事件</h3>
        <el-table :data="currentAlert.related_events" border style="width: 100%">
          <el-table-column prop="timestamp" label="时间" width="180">
            <template slot-scope="scope">
              {{ formatTime(scope.row.timestamp) }}
            </template>
          </el-table-column>
          <el-table-column prop="src_ip" label="源IP" width="140"></el-table-column>
          <el-table-column prop="dst_ip" label="目标IP" width="140"></el-table-column>
          <el-table-column prop="protocol" label="协议" width="100"></el-table-column>
          <el-table-column prop="alert_type" label="告警类型" width="100"></el-table-column>
          <el-table-column prop="severity" label="严重程度" width="100">
            <template slot-scope="scope">
              <el-tag :type="getSeverityType(scope.row.severity)">
                {{ scope.row.severity }}
              </el-tag>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { format } from 'date-fns'

export default {
  name: 'CorrelationAlerts',
  data() {
    return {
      alerts: [],
      rules: [],
      currentPage: 1,
      pageSize: 20,
      total: 0,
      filterForm: {
        timeRange: [],
        ruleName: '',
        severity: ''
      },
      pickerOptions: {
        shortcuts: [{
          text: '最近一小时',
          onClick(picker) {
            const end = new Date()
            const start = new Date()
            start.setTime(start.getTime() - 3600 * 1000)
            picker.$emit('pick', [start, end])
          }
        }, {
          text: '最近24小时',
          onClick(picker) {
            const end = new Date()
            const start = new Date()
            start.setTime(start.getTime() - 3600 * 1000 * 24)
            picker.$emit('pick', [start, end])
          }
        }]
      },
      detailsVisible: false,
      currentAlert: {}
    }
  },
  created() {
    this.fetchRules()
    this.fetchAlerts()
  },
  methods: {
    formatTime(time) {
      return format(new Date(time), 'yyyy-MM-dd HH:mm:ss')
    },
    getSeverityType(severity) {
      const types = {
        low: 'info',
        medium: 'warning',
        high: 'danger'
      }
      return types[severity] || 'info'
    },
    async fetchRules() {
      try {
        const response = await fetch('/api/correlation/rules')
        this.rules = await response.json()
      } catch (error) {
        this.$message.error('获取规则失败：' + error.message)
      }
    },
    async fetchAlerts() {
      try {
        const params = new URLSearchParams({
          page: this.currentPage,
          per_page: this.pageSize,
          rule_name: this.filterForm.ruleName,
          severity: this.filterForm.severity
        })
        
        if (this.filterForm.timeRange.length === 2) {
          params.append('start_time', this.filterForm.timeRange[0].toISOString())
          params.append('end_time', this.filterForm.timeRange[1].toISOString())
        }
        
        const response = await fetch(`/api/correlation/alerts?${params}`)
        const data = await response.json()
        this.alerts = data.alerts
        this.total = data.total
      } catch (error) {
        this.$message.error('获取告警失败：' + error.message)
      }
    },
    handleSizeChange(val) {
      this.pageSize = val
      this.fetchAlerts()
    },
    handleCurrentChange(val) {
      this.currentPage = val
      this.fetchAlerts()
    },
    handleFilter() {
      this.currentPage = 1
      this.fetchAlerts()
    },
    resetFilter() {
      this.filterForm = {
        timeRange: [],
        ruleName: '',
        severity: ''
      }
      this.handleFilter()
    },
    refresh() {
      this.fetchAlerts()
    },
    showDetails(alert) {
      this.currentAlert = alert
      this.detailsVisible = true
    },
    async exportAlerts() {
      try {
        const params = new URLSearchParams({
          rule_name: this.filterForm.ruleName,
          severity: this.filterForm.severity
        })
        
        if (this.filterForm.timeRange.length === 2) {
          params.append('start_time', this.filterForm.timeRange[0].toISOString())
          params.append('end_time', this.filterForm.timeRange[1].toISOString())
        }
        
        const response = await fetch(`/api/correlation/alerts/export?${params}`)
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `correlation_alerts_${format(new Date(), 'yyyyMMdd_HHmmss')}.csv`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
      } catch (error) {
        this.$message.error('导出失败：' + error.message)
      }
    }
  }
}
</script>

<style scoped>
.correlation-alerts {
  padding: 20px;
}
.alert-card {
  margin-bottom: 20px;
}
.filter-form {
  margin-bottom: 20px;
}
.pagination-container {
  margin-top: 20px;
  text-align: right;
}
.related-events {
  margin-top: 20px;
}
</style> 