#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from models import db


from config import app, db, api
from models import User, Recipe

# Signup for handling user registration
class Signup(Resource):
    def post(self):
        # Get data from the request
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        errors = []
        # Validate input
        if not username:
            errors.append("Username is required.")
        if not password:
            errors.append("Password is required.")
        if User.query.filter_by(username=username).first():
            errors.append("Username already exists.")

        # If there are errors
        if errors:
            return {'errors': errors}, 422

        # Create and save the new user
        user = User(username=username, image_url=image_url, bio=bio)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()

        # Log the user in by saving their id in the session
        session['user_id'] = user.id

        # Return the new user's info
        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 201

class CheckSession(Resource):
    def get(self):
        # Check if user is logged in
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                # Return user info if session is active
                return {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }, 200
        # If not logged in, return 401
        return {"error": "Unauthorized"}, 401

class Login(Resource):
    def post(self):
        # Get login data from request
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Find user by username
        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            # Set user_id in session
            session['user_id'] = user.id
            # Return user info
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200
        # If authentication fails, return 401
        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        # Check if user is logged in
        if session.get('user_id'):
            # Remove user_id from session
            session.pop('user_id', None)
            # Return empty response with 204
            return '', 204
        # If not logged in, return 401
        return {"error": "Unauthorized"}, 401

class RecipeIndex(Resource):
    def get(self):
        # Only allow access if user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        # Get all recipes for the logged-in user
        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        recipes = [
            {
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }
            }
            for recipe in user.recipes
        ]
        return recipes, 200

    def post(self):
        # Only allow access if user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')
        errors = []
        # Validate input
        if not title:
            errors.append("Title is required.")
        if not instructions or len(instructions) < 50:
            errors.append("Instructions must be at least 50 characters long.")
        if errors:
            return {"errors": errors}, 422
        # Create and save the new recipe
        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 422
        user = User.query.get(user_id)
        return {
            "id": recipe.id,
            "title": recipe.title,
            "instructions": recipe.instructions,
            "minutes_to_complete": recipe.minutes_to_complete,
            "user": {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }
        }, 201

# Register the Signup resource with the API
api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)