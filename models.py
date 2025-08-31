from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from typing import List

db = SQLAlchemy()

# ---------------------
# User Model
# ---------------------
class User(db.Model, UserMixin):
    __tablename__ = "users"

    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(80), unique=True, nullable=False)
    email: str = db.Column(db.String(120), unique=True, nullable=False)
    password: str = db.Column(db.String(200), nullable=False)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    complaints: List["Complaint"] = db.relationship("Complaint", back_populates="user", lazy=True)

    def __repr__(self) -> str:
        return f"<User {self.username}>"

# ---------------------
# Complaint Model
# ---------------------
class Complaint(db.Model):
    __tablename__ = "complaints"

    id: int = db.Column(db.Integer, primary_key=True)
    subject: str = db.Column(db.String(200), nullable=False)
    message: str = db.Column(db.Text, nullable=False)
    email: str = db.Column(db.String(120), nullable=False)
    created_at: datetime = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign key
    user_id: int = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Relationship
    user: User = db.relationship("User", back_populates="complaints")

    def __repr__(self) -> str:
        return f"<Complaint {self.subject}>"

