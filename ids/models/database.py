from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import enum
from datetime import datetime

Base = declarative_base()

class AlertSeverity(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class Packet(Base):
    __tablename__ = 'packets'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String(50))
    dst_ip = Column(String(50))
    protocol = Column(String(10))
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    length = Column(Integer)
    raw_data = Column(JSON)  # 存储原始数据包信息
    features = Column(JSON)  # 存储提取的特征
    
    alerts = relationship("Alert", back_populates="packet")

class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    packet_id = Column(Integer, ForeignKey('packets.id'))
    alert_type = Column(String(50))  # 'rule' 或 'ml'
    rule_name = Column(String(100), nullable=True)
    severity = Column(Enum(AlertSeverity))
    confidence = Column(Float, nullable=True)  # ML检测的置信度
    description = Column(String(500))
    
    packet = relationship("Packet", back_populates="alerts")

class Rule(Base):
    __tablename__ = 'rules'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True)
    conditions = Column(JSON)
    severity = Column(Enum(AlertSeverity))
    enabled = Column(Boolean, default=True)
    description = Column(String(500))

class Config(Base):
    __tablename__ = 'configs'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True)
    value = Column(JSON)
    description = Column(String(500))

class CorrelationAlert(Base):
    __tablename__ = 'correlation_alerts'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    rule_name = Column(String(100))
    severity = Column(Enum(AlertSeverity))
    description = Column(String(500))
    events_count = Column(Integer)
    related_events = Column(JSON)  # 存储相关事件的ID列表
    first_event_time = Column(DateTime)
    last_event_time = Column(DateTime)

def init_db(db_url):
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session() 