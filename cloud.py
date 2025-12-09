import bcrypt
import grpc
from concurrent import futures
import cloudsecurity_pb2
import cloudsecurity_pb2_grpc
from utils import send_otp, hash_password
import os

class UserServiceSkeleton(cloudsecurity_pb2_grpc.UserServiceServicer):
    def login(self, request, context):
        print(f'[LOGIN] New incoming request ... \nUsername: {request.login}')
        result = self.checkId(request.login, request.password)
        return cloudsecurity_pb2.Response(result=result)

    def signup(self, request, context):
        print(f'[SIGNUP] New registration request ... \nUsername: {request.username}, Email: {request.email}')
        result = self.createUser(request.username, request.email, request.password)
        return cloudsecurity_pb2.Response(result=result)

    def checkId(self, login, pwd) -> str:
        credentials = {}
        emails = {}
        file_path = 'credentials'
        
        if not os.path.exists(file_path):
            return "Error: No users registered yet. Please sign up first."
        
        with open(file_path, 'r') as file:
            for line in file:
                username, email, password = line.strip().split(',')
                credentials[username] = password
                emails[username] = email
        
        if (credentials.get(login,None) and 
            bcrypt.checkpw(pwd.encode('utf-8'), credentials[login].encode('utf-8'))):
            return send_otp(emails[login])
        else:
            return "Unauthorized - Invalid username or password"

    def createUser(self, username, email, password) -> str:
        """Create a new user and add to credentials file"""
        file_path = 'credentials'
        
        # Check if user already exists
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                for line in file:
                    existing_username = line.strip().split(',')[0]
                    if existing_username == username:
                        return f"Error: Username '{username}' already exists. Please choose a different username."
        
        # Hash the password
        hashed_password = hash_password(password)
        
        # Add user to credentials file
        with open(file_path, 'a') as file:
            file.write(f'{username},{email},{hashed_password}\n')
        
        print(f"[SUCCESS] New user registered: {username} ({email})")
        return f"Successfully registered user '{username}'. You can now login with your credentials."

def run():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    cloudsecurity_pb2_grpc.add_UserServiceServicer_to_server(UserServiceSkeleton(), server)
    server.add_insecure_port('[::]:51234')
    print('Starting Server on port 51234 ............', end='')
    server.start()
    print('[OK]')
    print('Server is running and ready for connections!')
    server.wait_for_termination()

if __name__ == '__main__':
    run()