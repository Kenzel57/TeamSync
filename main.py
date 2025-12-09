import os
import sys
import bcrypt
import grpc
from concurrent import futures
import threading
import time

# Import the generated gRPC files
import cloudsecurity_pb2
import cloudsecurity_pb2_grpc

# Import utility functions
from utils import hash_password, send_otp

class UserServiceSkeleton(cloudsecurity_pb2_grpc.UserServiceServicer):
    def login(self, request, context):
        print(f'[LOGIN] New incoming request ... \nUsername: {request.login}')
        result = self.checkId(request.login, request.password)
        return cloudsecurity_pb2.Response(result=result)

    def signup(self, request, context):
        print(f'[SIGNUP] New registration request ... \nUsername: {request.username}, Email: {request.email}')
        result = self.createUser(request.username, request.email, request.password)
        return cloudsecurity_pb2.Response(result=result)

    def checkId(self, login, pwd):
        credentials = {}
        emails = {}
        file_path = 'credentials'
        
        if not os.path.exists(file_path):
            return "Error: No users registered yet. Please sign up first."
        
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        username, email, password = parts[0], parts[1], parts[2]
                        credentials[username] = password
                        emails[username] = email
        except Exception as e:
            return f"Error reading credentials: {e}"
        
        if login not in credentials:
            print(f"User '{login}' not found in credentials file")
            return "Unauthorized - User not found"
        
        try:
            # Get the stored hash
            stored_hash = credentials[login]
            
            # Verify it's a valid bcrypt hash
            if not stored_hash.startswith('$2b$'):
                print(f"Invalid hash format for user {login}")
                return "Authentication error - Invalid credentials format"
            
            # Verify the password
            if bcrypt.checkpw(pwd.encode('utf-8'), stored_hash.encode('utf-8')):
                print(f"Authentication successful for user: {login}")
                return send_otp(emails[login])
            else:
                print(f"Password mismatch for user: {login}")
                return "Unauthorized - Invalid password"
                
        except Exception as e:
            print(f"Authentication error for user {login}: {e}")
            return f"Authentication error: {str(e)}"

    def createUser(self, username, email, password):
        """Create a new user and add to credentials file"""
        file_path = 'credentials'
        
        # Check if user already exists
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                for line in file:
                    parts = line.strip().split(',')
                    if len(parts) >= 1 and parts[0] == username:
                        return f"Error: Username '{username}' already exists. Please choose a different username."
        
        # Hash the password
        hashed_password = hash_password(password)
        
        # Add user to credentials file
        with open(file_path, 'a') as file:
            file.write(f'{username},{email},{hashed_password}\n')
        
        print(f"[SUCCESS] New user registered: {username} ({email})")
        return f"Successfully registered user '{username}'. You can now login with your credentials."

def run_server():
    """Start the gRPC server"""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    cloudsecurity_pb2_grpc.add_UserServiceServicer_to_server(UserServiceSkeleton(), server)
    server.add_insecure_port('[::]:51234')
    print('Starting gRPC Server on port 51234 ............', end='')
    server.start()
    print('[OK]')
    print('Server is running and ready for connections!')
    print('Press Ctrl+C to stop the server.\n')
    
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop(0)
        print("Server stopped.")

def run_client_test():
    """Run client tests for both signup and login"""
    import cloudsecurity_pb2_grpc
    
    # Wait a moment for server to start
    time.sleep(2)
    
    print("\n" + "="*50)
    print("TESTING SIGNUP AND LOGIN")
    print("="*50)
    
    try:
        with grpc.insecure_channel('localhost:51234') as channel:
            stub = cloudsecurity_pb2_grpc.UserServiceStub(channel)
            
            # Test signup
            print("\n1. Testing SIGNUP...")
            signup_response = stub.signup(cloudsecurity_pb2.SignupRequest(
                username="testuser",
                email="testuser@example.com", 
                password="testpass123"
            ))
            print(f"Signup Result: {signup_response.result}")
            
            time.sleep(1)
            
            # Test login with new user
            print("\n2. Testing LOGIN with new user...")
            login_response = stub.login(cloudsecurity_pb2.Request(
                login="testuser", 
                password="testpass123"
            ))
            print(f"Login Result: {login_response.result}")
            
    except Exception as e:
        print(f"Client error: {e}")

def view_users():
    """View all registered users"""
    if not os.path.exists('credentials'):
        print("No users registered yet.")
        return
    
    print("\n" + "="*50)
    print("REGISTERED USERS")
    print("="*50)
    with open('credentials', 'r') as file:
        for i, line in enumerate(file, 1):
            parts = line.strip().split(',')
            if len(parts) >= 3:
                print(f"{i}. Username: {parts[0]} | Email: {parts[1]}")
    print("="*50)

def setup_environment():
    """Setup the required environment"""
    print("Setting up environment...")
    
    # Check if required packages are installed
    try:
        import bcrypt
        import grpc
        print("✓ All required packages are installed")
    except ImportError as e:
        print(f"✗ Missing package: {e}")
        print("Please run: pip install grpcio grpcio-tools bcrypt")
        return False
    
    # Check if proto files are compiled
    if not os.path.exists('cloudsecurity_pb2.py') or not os.path.exists('cloudsecurity_pb2_grpc.py'):
        print("Compiling protocol buffers...")
        try:
            os.system('python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. cloudsecurity.proto')
            if os.path.exists('cloudsecurity_pb2.py'):
                print("✓ Protocol buffers compiled successfully")
            else:
                print("✗ Failed to compile protocol buffers")
                return False
        except Exception as e:
            print(f"✗ Failed to compile protocol buffers: {e}")
            return False
    else:
        print("✓ Protocol buffers already compiled")
    
    return True

def main():
    """Main function to run the entire application"""
    print("="*60)
    print("CLOUD SECURITY AUTHENTICATION SYSTEM")
    print("="*60)
    
    # Setup environment
    if not setup_environment():
        print("Failed to setup environment. Exiting.")
        return
    
    while True:
        print("\nOptions:")
        print("1. Run Server only")
        print("2. Run Server + Test Signup/Login")
        print("3. View all registered users")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            print("\nStarting server...")
            run_server()
            break
            
        elif choice == "2":
            print("\nStarting server and client tests...")
            # Start server in a separate thread
            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()
            
            # Run client test
            run_client_test()
            
            # Keep server running
            print("\nServer is still running. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutting down...")
                break
                
        elif choice == "3":
            view_users()
            
        elif choice == "4":
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please select 1-4.")

if __name__ == '__main__':
    main()