from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

class IDSAPI:
    def __init__(self, db_manager, ids_instance):
        self.db = db_manager
        self.ids = ids_instance
        self.setup_routes()
        
    def setup_routes(self):
        # 告警相关
        app.route('/api/alerts')(self.get_alerts)
        app.route('/api/alerts/stats')(self.get_alert_stats)
        
        # 规则相关
        app.route('/api/rules', methods=['GET'])(self.get_rules)
        app.route('/api/rules', methods=['POST'])(self.add_rule)
        app.route('/api/rules/<int:rule_id>', methods=['PUT'])(self.update_rule)
        app.route('/api/rules/<int:rule_id>', methods=['DELETE'])(self.delete_rule)
        
        # 配置相关
        app.route('/api/config', methods=['GET'])(self.get_config)
        app.route('/api/config', methods=['POST'])(self.update_config)
        
        # 统计相关
        app.route('/api/stats/traffic')(self.get_traffic_stats)
        app.route('/api/stats/top-ips')(self.get_top_ips)
        
    def get_alerts(self):
        """获取告警列表"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        query = self.db.session.query(Alert)
        total = query.count()
        alerts = query.order_by(Alert.timestamp.desc())\
                     .offset((page-1)*per_page)\
                     .limit(per_page)\
                     .all()
                     
        return jsonify({
            'total': total,
            'alerts': [alert.to_dict() for alert in alerts]
        })
        
    def get_alert_stats(self):
        """获取告警统计信息"""
        # 最近24小时的告警统计
        start_time = datetime.utcnow() - timedelta(hours=24)
        stats = self.db.session.query(
            Alert.severity,
            func.count(Alert.id)
        ).filter(
            Alert.timestamp >= start_time
        ).group_by(
            Alert.severity
        ).all()
        
        return jsonify({
            'stats': dict(stats)
        })
        
    def get_rules(self):
        """获取所有规则"""
        rules = self.db.session.query(Rule).all()
        return jsonify([rule.to_dict() for rule in rules])
        
    def add_rule(self):
        """添加新规则"""
        data = request.get_json()
        rule = Rule(**data)
        self.db.session.add(rule)
        self.db.session.commit()
        
        # 更新IDS规则
        self.ids.rule_engine.add_rule(rule)
        return jsonify(rule.to_dict())
        
    def update_rule(self, rule_id):
        """更新规则"""
        data = request.get_json()
        rule = self.db.session.query(Rule).get(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
            
        for key, value in data.items():
            setattr(rule, key, value)
            
        self.db.session.commit()
        return jsonify(rule.to_dict())
        
    def get_traffic_stats(self):
        """获取流量统计"""
        interval = request.args.get('interval', '1h')
        # 实现统计逻辑
        return jsonify({})
        
    def run(self, host='0.0.0.0', port=5000):
        app.run(host=host, port=port) 