<template>
  <div class="correlation-rules">
    <el-card class="rule-card">
      <div slot="header" class="clearfix">
        <span>关联规则管理</span>
        <el-button style="float: right; padding: 3px 0" type="text" @click="showAddDialog">
          添加规则
        </el-button>
      </div>

      <el-table :data="rules" style="width: 100%">
        <el-table-column prop="name" label="规则名称" width="180">
        </el-table-column>
        <el-table-column prop="time_window" label="时间窗口(秒)" width="120">
        </el-table-column>
        <el-table-column prop="threshold" label="触发阈值" width="120">
        </el-table-column>
        <el-table-column prop="severity" label="严重程度" width="120">
          <template slot-scope="scope">
            <el-tag :type="getSeverityType(scope.row.severity)">
              {{ scope.row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="分组字段" width="180">
          <template slot-scope="scope">
            <el-tag v-for="field in scope.row.conditions.group_by" 
                    :key="field" 
                    size="small" 
                    style="margin-right: 5px">
              {{ field }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作">
          <template slot-scope="scope">
            <el-button size="mini" @click="handleEdit(scope.$index, scope.row)">
              编辑
            </el-button>
            <el-button size="mini" type="danger" @click="handleDelete(scope.$index, scope.row)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 添加/编辑规则对话框 -->
    <el-dialog :title="dialogTitle" :visible.sync="dialogVisible">
      <el-form :model="ruleForm" :rules="rules" ref="ruleForm" label-width="100px">
        <el-form-item label="规则名称" prop="name">
          <el-input v-model="ruleForm.name"></el-input>
        </el-form-item>
        <el-form-item label="时间窗口" prop="time_window">
          <el-input-number v-model="ruleForm.time_window" :min="1"></el-input-number>
          <span class="unit">秒</span>
        </el-form-item>
        <el-form-item label="触发阈值" prop="threshold">
          <el-input-number v-model="ruleForm.threshold" :min="1"></el-input-number>
        </el-form-item>
        <el-form-item label="严重程度" prop="severity">
          <el-select v-model="ruleForm.severity">
            <el-option label="低" value="low"></el-option>
            <el-option label="中" value="medium"></el-option>
            <el-option label="高" value="high"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item label="分组字段" prop="group_by">
          <el-select v-model="ruleForm.conditions.group_by" multiple>
            <el-option label="源IP" value="src_ip"></el-option>
            <el-option label="目标IP" value="dst_ip"></el-option>
            <el-option label="源端口" value="src_port"></el-option>
            <el-option label="目标端口" value="dst_port"></el-option>
            <el-option label="协议" value="protocol"></el-option>
          </el-select>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="dialogVisible = false">取 消</el-button>
        <el-button type="primary" @click="submitForm('ruleForm')">确 定</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
export default {
  name: 'CorrelationRules',
  data() {
    return {
      rules: [],
      dialogVisible: false,
      dialogTitle: '添加关联规则',
      isEdit: false,
      editIndex: -1,
      ruleForm: {
        name: '',
        time_window: 300,
        threshold: 3,
        severity: 'medium',
        conditions: {
          group_by: []
        }
      },
      formRules: {
        name: [
          { required: true, message: '请输入规则名称', trigger: 'blur' }
        ],
        time_window: [
          { required: true, message: '请设置时间窗口', trigger: 'blur' }
        ],
        threshold: [
          { required: true, message: '请设置触发阈值', trigger: 'blur' }
        ]
      }
    }
  },
  created() {
    this.fetchRules()
  },
  methods: {
    async fetchRules() {
      try {
        const response = await fetch('/api/correlation/rules')
        this.rules = await response.json()
      } catch (error) {
        this.$message.error('获取规则失败：' + error.message)
      }
    },
    getSeverityType(severity) {
      const types = {
        low: 'info',
        medium: 'warning',
        high: 'danger'
      }
      return types[severity] || 'info'
    },
    showAddDialog() {
      this.isEdit = false
      this.dialogTitle = '添加关联规则'
      this.ruleForm = {
        name: '',
        time_window: 300,
        threshold: 3,
        severity: 'medium',
        conditions: {
          group_by: []
        }
      }
      this.dialogVisible = true
    },
    handleEdit(index, row) {
      this.isEdit = true
      this.editIndex = index
      this.dialogTitle = '编辑关联规则'
      this.ruleForm = { ...row }
      this.dialogVisible = true
    },
    async handleDelete(index, row) {
      try {
        await this.$confirm('确认删除该规则？', '提示', {
          confirmButtonText: '确定',
          cancelButtonText: '取消',
          type: 'warning'
        })
        
        const response = await fetch(`/api/correlation/rules/${row.id}`, {
          method: 'DELETE'
        })
        
        if (response.ok) {
          this.$message.success('删除成功')
          this.rules.splice(index, 1)
        } else {
          throw new Error('删除失败')
        }
      } catch (error) {
        this.$message.error(error.message)
      }
    },
    async submitForm(formName) {
      this.$refs[formName].validate(async (valid) => {
        if (valid) {
          try {
            const url = this.isEdit 
              ? `/api/correlation/rules/${this.ruleForm.id}`
              : '/api/correlation/rules'
            
            const method = this.isEdit ? 'PUT' : 'POST'
            const response = await fetch(url, {
              method,
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify(this.ruleForm)
            })
            
            if (response.ok) {
              const result = await response.json()
              if (this.isEdit) {
                this.rules[this.editIndex] = result
              } else {
                this.rules.push(result)
              }
              this.dialogVisible = false
              this.$message.success(this.isEdit ? '更新成功' : '添加成功')
            } else {
              throw new Error(this.isEdit ? '更新失败' : '添加失败')
            }
          } catch (error) {
            this.$message.error(error.message)
          }
        }
      })
    }
  }
}
</script>

<style scoped>
.correlation-rules {
  padding: 20px;
}
.rule-card {
  margin-bottom: 20px;
}
.unit {
  margin-left: 10px;
}
</style> 