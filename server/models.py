from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import Bcrypt

from config import db

bcrypt = Bcrypt()

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    # Username must be unique and present
    username = db.Column(db.String, unique=True, nullable=False)
    # Store hashed password (never plain text)
    _password_hash = db.Column(db.String, nullable=False)
    # Optional profile image URL
    image_url = db.Column(db.String)
    # Optional user bio
    bio = db.Column(db.String)

    # Relationship: a user has many recipes
    recipes = db.relationship('Recipe', back_populates='user')

    # Serialization rule to avoid circular reference
    serialize_rules = ('-recipes.user',)

    # Write-only password property
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    # Hash and set the password
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')

    # Check if a password matches the hash
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    # Validate username is present
    @validates('username')
    def validate_username(self, key, username):
        if not username or username.strip() == "":
            raise ValueError("Username must be present.")
        return username

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    # Recipe title (required)
    title = db.Column(db.String, nullable=False)
    # Recipe instructions (required)
    instructions = db.Column(db.String, nullable=False)
    # Time to complete recipe (optional)
    minutes_to_complete = db.Column(db.Integer)
    # Foreign key: which user owns this recipe
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationship: recipe belongs to a user
    user = db.relationship('User', back_populates='recipes')

    # Serialization rule to avoid circular reference
    serialize_rules = ('-user.recipes',)

    # Validate title is present
    @validates('title')
    def validate_title(self, key, title):
        if not title or title.strip() == "":
            raise ValueError("Title must be present.")
        return title

    # Validate instructions are present and long enough
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions



