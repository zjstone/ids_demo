import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict

from ids.models.packet_features import PacketFeatures

class MLEngine:
    def __init__(self, model_path: str = None):
        self.model = IsolationForest(random_state=42)
        self.logger = logging.getLogger(__name__)
        
    def predict(self, features: Dict) -> bool:
        try:
            # 将特征转换为模型输入格式
            X = self._transform_features(features)
            return self.model.predict(X)[0] == 1
        except Exception as e:
            self.logger.error(f"预测失败: {str(e)}")
            return False 