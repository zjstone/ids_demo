from sklearn.ensemble import RandomForestClassifier
import numpy as np

class MLEngine:
    def __init__(self):
        self.model = RandomForestClassifier()
        self.feature_names = None
        
    def train(self, X, y, feature_names):
        """训练模型"""
        self.feature_names = feature_names
        self.model.fit(X, y)
        
    def predict(self, features):
        """预测是否为攻击"""
        if not self.feature_names:
            return None
            
        # 将特征转换为模型所需的格式
        feature_vector = [features.get(name, 0) for name in self.feature_names]
        prediction = self.model.predict_proba([feature_vector])[0]
        
        return {
            'is_attack': bool(prediction[1] > 0.5),
            'confidence': float(max(prediction))
        } 