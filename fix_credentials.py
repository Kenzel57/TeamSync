import bcrypt
import os

def hash_password(password):
    """Properly hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_proper_credentials():
    """Create a properly formatted credentials file"""
    
    # Sample users with real passwords
    users = [
        {"username": "kenzel", "email": "kenzel@example.com", "password": "kenzel0123"},
        {"username": "johndoe", "email": "johndoe@example.com", "password": "1234567890"},
        {"username": "alice", "email": "alice@example.com", "password": "password123"},
        {"username": "bob", "email": "bob@example.com", "password": "secret456"}
    ]
    
    print("Creating proper credentials file...")
    
    with open('credentials', 'w') as file:
        for user in users:
            hashed_password = hash_password(user['password'])
            file.write(f"{user['username']},{user['email']},{hashed_password}\n")
            print(f"✓ Created user: {user['username']}")
            print(f"  Email: {user['email']}")
            print(f"  Password: {user['password']}")
            print(f"  Hash: {hashed_password}\n")
    
    print("Credentials file created successfully!")
    return True

def verify_credentials():
    """Verify the credentials file is properly formatted"""
    if not os.path.exists('credentials'):
        print("No credentials file found!")
        return False
    
    print("Verifying credentials file...")
    
    with open('credentials', 'r') as file:
        for i, line in enumerate(file, 1):
            line = line.strip()
            if not line:
                continue
                
            parts = line.split(',')
            if len(parts) != 3:
                print(f"✗ Line {i}: Invalid format - expected 3 parts, got {len(parts)}")
                return False
            
            username, email, password_hash = parts
            
            # Check if hash looks like a valid bcrypt hash
            if not password_hash.startswith('$2b$'):
                print(f"✗ Line {i}: Invalid bcrypt hash - should start with '$2b$'")
                print(f"  Current hash: {password_hash}")
                return False
            
            if len(password_hash) < 50:
                print(f"✗ Line {i}: Hash too short - likely corrupted")
                return False
            
            print(f"✓ Line {i}: Valid - Username: {username}, Email: {email}")
    
    print("All credentials are properly formatted!")
    return True

if __name__ == '__main__':
    print("=" * 60)
    print("CREDENTIALS FILE FIXER")
    print("=" * 60)
    
    # Check current file
    if os.path.exists('credentials'):
        print("Current credentials file found. Verifying...")
        if verify_credentials():
            print("\nYour credentials file is already valid!")
            choice = input("Do you want to recreate it anyway? (y/n): ").lower()
            if choice != 'y':
                exit()
        else:
            print("\nCurrent credentials file is invalid. Recreating...")
    else:
        print("No credentials file found. Creating new one...")
    
    # Create proper credentials file
    create_proper_credentials()
    
    # Verify the new file
    print("\n" + "=" * 40)
    print("VERIFICATION")
    print("=" * 40)
    verify_credentials()