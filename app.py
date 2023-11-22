from flask import Flask, request,jsonify
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from flask_restful import Resource, Api
from Verify import is_valid_email, send_email,is_valid_password,generate_access_token
import random
from flask_jwt_extended import JWTManager, get_jwt_identity, jwt_required

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/social_network'
api = Api(app)
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'my_secret_key_here'
jwt = JWTManager(app)
class BaseRegistration:
    @staticmethod
    def get_user_data(data):
        # Check if the username is already taken
        if mongo.db.users.find_one({'username': data['username']}):
            return {'message': 'Username already taken'}, 400
        if is_valid_password(data['password']):
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            return {'username': data['username'], 'password': hashed_password}
        else:
            return {'message': 'Invalid Password'}, 400
class Register(Resource):
    def post(self):
        data = request.get_json()
        # Validate JSON data
        if not data or 'username' not in data or 'password' not in data:
            return {'message': 'Invalid JSON data'}, 400
        user_data = BaseRegistration.get_user_data(data)
        try:
            # Insert the user into the database
            mongo.db.users.insert_one({'username': user_data['username'], 'password': user_data['password']}).inserted_id
        except Exception as e:
            return {'message': f'Registration failed: {str(e)}'}, 500
        return {'message': 'Registration Completed'}, 201
class RegisterVerify(Resource):
    def post(self, username):
        # Check if the username exists in the database
        existing_user = mongo.db.users.find_one({'username': username})
        if not existing_user:
            return {'message': 'Username not found'}, 404
        data = request.get_json()
        incoming = data['verify']
        Email = None  # Initialize Email before the try-except block
        try:
            code = int(incoming)
        except ValueError:
            Email = incoming
        if Email:
            email = Email
            # Step 1: Send verification code to the provided email
            code = random.randrange(100000, 999999)
            existing_user = mongo.db.users.find_one({'email': email})
            if existing_user:
                # Email is already present in the database
                print("Email is already registered.")
            else:
                if is_valid_email(email):
                    send_email(email, f"{code} Is Your Verification Code", f"{code} Is Your Verification Code Of Social Networking App")
                    # Store the verification code in the database
                    user_junk = {
                        'username': username,
                        'email': email,
                        'verification_code': code
                    }
                    mongo.db.junk.insert_one(user_junk)
                    return {'message': 'Verification Code Sent'}
                else:
                    return {'message': 'Invalid Email'}
        elif code:
            existing_user = mongo.db.junk.find_one({'username': username}, {'verification_code': 1, 'email': 1})
            stored_code = existing_user.get('verification_code')
            email = existing_user.get('email')
            if stored_code is not None and int(stored_code) == code:
                try:
                    # Insert the user into the database
                    mongo.db.users.update_one({'username': username}, {'$set': {'Email': email}})
                    # Generate an access token
                    access_token = generate_access_token(username)
                    return {
                        'message': 'Verification Completed',
                        'access_token': access_token
                    }, 201
                except Exception as e:
                    return {'message': f'Verification failed: {str(e)}'}, 500
            else:
                return {'message': 'Invalid verification code'}, 400
        else:
            return {'message': 'Error'}, 400
class Login(Resource):
    def post(self):
        data = request.get_json()
        # Check if the required fields are in the request
        if 'username' not in data or 'password' not in data:
            return {'message': 'Missing username or password'}, 400
        # Find the user in the database
        user = mongo.db.users.find_one({
            '$or': [
                {'username': data['username']},
                {'email': data['username']}
            ]
        })
        # Check if the user exists and the password is correct
        if user and bcrypt.check_password_hash(user['password'], data['password']):
            access_token = generate_access_token(user['username'])
            return {
                'message': 'Verification Completed',
                'access_token': access_token
            }, 201
        else:
            return {'message': 'Invalid username or password'}, 401
class ForgetPassword(Resource):
    def post(self):
        data = request.get_json()
        forget = data['forget']
        existing_user = mongo.db.users.find_one({
            '$or': [
                {'Email': forget},
                {'username': forget}
            ]
        })
        print(existing_user)
        if existing_user:
            email = existing_user.get('Email')  # Use get() method to avoid KeyError
            code = random.randrange(100000, 999999)
            send_email(email, f"{code} Is Your Verification Code",
                       f"{code} Is Your Verification Code Of Social Networking App")
            user_junk = {
                'username': existing_user['username'],
                'email': email,
                'verification_code': code
            }
            mongo.db.junk.insert_one(user_junk)
            return {'message': 'Verification Mail Sent'}, 201
        else:
            try:
                code = int(forget)
                if code:
                    user_junk = mongo.db.junk.find_one({'verification_code': code})
                    if user_junk:
                        mongo.db.junk.delete_one({'verification_code': code})
                        return {'message': 'User Verified', 'username': user_junk['username']}, 200
                    else:
                        return {'message': 'Invalid Code'}, 400
                else:
                    return {'message': 'Invalid Code'}, 400
            except ValueError:
                return {'message': 'Invalid Code'}, 400
class ResetPassword(Resource):
    def post(self, username):
        data = request.get_json()
        # Validate JSON data
        if not data or 'password' not in data:
            return {'message': 'Invalid JSON data'}, 400
        new_password = data['password']
        if is_valid_password(new_password):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            # Update the user's password in the database
            mongo.db.users.update_one({'username': username}, {'$set': {'password': hashed_password}})
            return {'message': 'Password Reset Successful'}, 200
        else:
            return {'message':'Invalid Password'},400

class Profile(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()


        user_profile = mongo.db.users.find_one({'username': current_user})
        number_friends = len(user_profile.get('friends', []))
        number_tweets = len(user_profile.get('tweets', []))
        number_reels = len(user_profile.get('reels', []))

        if user_profile:
            return {
                'display_picture': user_profile.get('display_picture', None),
                'username': user_profile.get('username', None),
                'email': user_profile.get('Email', None),
                'country': user_profile.get('country', None),
                'number-friends': number_friends,
                'number-tweets': number_tweets,
                'number-reels': number_reels
            }
        else:
            return {'message': 'User not found'}, 404

    @jwt_required()
    def put(self):
        current_user = get_jwt_identity()
        data = request.get_json()

        # Update the user profile in the database
        result = (mongo.db.users.update_one({'username': current_user}, {'$set': data}))

        if result.modified_count > 0:
            return {'message': 'Profile updated successfully'}, 200
        else:
            return {'message': 'User not found or no changes made'}, 404



api.add_resource(Register, '/register')
api.add_resource(RegisterVerify, '/register_verify/<username>')
# email as verify
api.add_resource(Login, '/login')
#input as forget
api.add_resource(ForgetPassword, '/forget_password')
# input as password
api.add_resource(ResetPassword, '/reset_password/<username>')
# field to get or post "username","email","display_picture","country","friends","tweets","reels"
api.add_resource(Profile, '/profile')


if __name__ == '__main__':
    app.run(debug=True)
