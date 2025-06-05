from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    sounds = db.relationship('Sound', backref='uploader', lazy=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True)

class Sound(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(
        db.Integer,
        db.ForeignKey('user.id', name='fk_sound_user'),
        nullable=False
    )

    favorites = db.relationship('Favorite', backref='sound', lazy=True)

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', name='fk_favorite_user'),
        nullable=False
    )
    sound_id = db.Column(
        db.Integer,
        db.ForeignKey('sound.id', name='fk_favorite_sound'),
        nullable=False
    )
    added_on = db.Column(db.DateTime, default=datetime.utcnow)
