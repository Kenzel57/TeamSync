import sys
import grpc
import cloudsecurity_pb2
import cloudsecurity_pb2_grpc

def run():
    with grpc.insecure_channel('localhost:51234') as channel:
        stub = cloudsecurity_pb2_grpc.UserServiceStub(channel)
        
        if len(sys.argv) < 2:
            print("Usage:")
            print("  python client.py login <username> <password>")
            print("  python client.py signup <username> <email> <password>")
            return
        
        request_type = sys.argv[1]
        
        if request_type == "login":
            if len(sys.argv) != 4:
                print("Usage: python client.py login <username> <password>")
                return
            username = sys.argv[2]
            password = sys.argv[3]
            response = stub.login(cloudsecurity_pb2.Request(login=username, password=password))
            print(f"Login Result: {response.result}")
            
        elif request_type == "signup":
            if len(sys.argv) != 5:
                print("Usage: python client.py signup <username> <email> <password>")
                return
            username = sys.argv[2]
            email = sys.argv[3]
            password = sys.argv[4]
            response = stub.signup(cloudsecurity_pb2.SignupRequest(username=username, email=email, password=password))
            print(f"Signup Result: {response.result}")
            
        else:
            print("Invalid request type. Use 'login' or 'signup'")
            print("Usage:")
            print("  python client.py login <username> <password>")
            print("  python client.py signup <username> <email> <password>")

if __name__ == '__main__':
    run()