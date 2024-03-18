from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
import bcrypt

cluster = "mongodb://127.0.0.1:27017/"
client = MongoClient(cluster)
db = client.mydb
userCollection = db.user
machineCollection = db.machine
packageCollection = db.package

current_user = None  

def login():
    global current_user
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    try:
        user = userCollection.find_one({"username": username})

        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                print("Login successful!")
                current_user = user
                return True
            else:
                print("Invalid username or password.")
                return False
        else:
            print("Invalid username or password.")
            return False
    except Exception as e:
        print("An error occurred:", e)
        return False


def logout():
    global current_user
    current_user = None
    print("Logged out successfully.")


def createAccount():
    name = input("Enter your name: ").strip()
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    if not (name and username and password):
        print("All mandatory fields (name, username, password) are required.")
        return

    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        data = {
            "name": name,
            "username": username,
            "password": hashed_password.decode('utf-8'),
            "role": "user",  
            "machines": []
        }

        inserted_id = userCollection.insert_one(data).inserted_id
        print("Account created successfully with ID:", inserted_id)
    except Exception as e:
        print("An error occurred:", e)

def viewUsers():
    global current_user
    if not current_user:
        print("You must be logged in to view users.")
        return

    if current_user.get("role") != "admin":
        print("Only the admin user can view user data.")
        return

    cursor = userCollection.find()
    print("Data in 'user' collection:")
    for user in cursor:
        print(user)

def deleteUser():
    global current_user

    if not current_user:
        print("You must be logged in to delete your account.")
        return

    if current_user.get("role") == "admin":
        user_id_str = input("Enter the ObjectId of the user you want to delete: ").strip()
        try:
            user_id = ObjectId(user_id_str)
        except ValueError:
            print("Invalid ObjectId.")
            return
    else:
        user_id = current_user["_id"]

    confirmation = input("Are you sure you want to delete this user? (yes/no): ").strip().lower()
    if confirmation != "yes":
        print("Account deletion cancelled.")
        return

    try:
        result_user = userCollection.delete_one({"_id": user_id})
        if result_user.deleted_count == 1:
            print("User account has been deleted successfully.")
            if current_user["_id"] == user_id:
                logout()  
        else:
            print("An error occurred. User account could not be deleted.")
            return
        
        result_machines = machineCollection.delete_many({"user_id": user_id})
        print(f"{result_machines.deleted_count} machines associated with the user have been deleted.")
    except Exception as e:
        print("An error occurred:", e)

def createMachine():
    global current_user

    if not current_user:
        print("You must be logged in to create a machine.")
        return
    machine_id = input("Enter 8-digit machine ID: ").strip()

    if not machine_id or not machine_id.isdigit() or len(machine_id) != 8:
        print("Machine ID must be an 8-digit number.")
        return

    try:
        machine_data = {
            "user_id": current_user["_id"],
            "machine_id": machine_id,
            "packages": []
        }

        inserted_machine = machineCollection.insert_one(machine_data)
        machine_id = inserted_machine.inserted_id
        print("Machine created successfully with ID:", machine_id)

        userCollection.update_one({"_id": current_user["_id"]}, {"$push": {"machines": machine_id}})
    except Exception as e:
        print("An error occurred:", e)

def viewMachines():
    global current_user

    if not current_user:
        print("You must be logged in to view machines.")
        return

    current_user_id = current_user["_id"]

    user_machines = machineCollection.find({"user_id": current_user_id})
    for machine in user_machines:
        print("Machine details:")
        print("Machine ID:", machine["machine_id"])
        print("Packages:")
        for package_id in machine["packages"]:
            package = packageCollection.find_one({"_id": package_id})
            if package:
                print("Package ID:", package["packageid"])
                print("Dimension:", package["dimension"])
                print("Volume:", package["volume"])
                print("Timestamp:", package["timestamp"])
                print("Thumbnail:", package["thumbnail"])
                print("Barcode:", package["barcode"])
                print()


def deleteMachine():
    global current_user

    if not current_user:
        print("You must be logged in to delete a machine.")
        return
    
    machine_id_str = input("Enter the ObjectId of the machine you want to delete: ").strip()
    try:
        machine_id = ObjectId(machine_id_str)
    except ValueError:
        print("Invalid ObjectId.")
        return
    try:
        machine = machineCollection.find_one({"_id": machine_id})

        if not machine:
            print("Machine not found.")
            return

        if machine["user_id"] != current_user["_id"]:
            print("You are not authorized to delete this machine.")
            return

        confirmation = input("Are you sure you want to delete this machine? (yes/no): ").strip().lower()
        if confirmation != "yes":
            print("Machine deletion cancelled.")
            return

        result = machineCollection.delete_one({"_id": machine_id})
        if result.deleted_count == 1:
            print("Machine deleted successfully.")
        else:
            print("An error occurred. Machine could not be deleted.")

    except Exception as e:
        print("An error occurred:", e)

def createPackage():
    global current_user

    if not current_user:
        print("You must be logged in to create a package.")
        return

    packageid = input("Enter package ID: ").strip()
    dimension = input("Enter package dimension: ").strip()
    volume = input("Enter package volume: ").strip()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    thumbnail = input("Enter package thumbnail URL: ").strip()
    barcode = input("Enter package barcode: ").strip()
    machine_id = input("Enter machine id to associate this package with: ").strip()

    if not (packageid and dimension and volume and thumbnail and barcode and machine_id):
        print("All fields (package ID, dimension, volume, thumbnail URL, barcode, machine name) are required.")
        return

    try:
        machine = machineCollection.find_one({"machine_id": machine_id})

        if not machine:
            print("Machine not found.")
            return

        package_data = {
            "packageid": packageid,
            "dimension": dimension,
            "volume": volume,
            "timestamp": timestamp,
            "thumbnail": thumbnail,
            "barcode": barcode
        }

        inserted_package = packageCollection.insert_one(package_data)
        package_id = inserted_package.inserted_id
        print("Package created successfully with ID:", package_id)

        machineCollection.update_one({"_id": machine["_id"]}, {"$push": {"packages": package_id}})
    except Exception as e:
        print("An error occurred:", e)

def exit_program():
    logout()
    exit()


def main():
    while True:
        if current_user:
            if current_user.get("role") == "admin":
                options = {
                    "view": viewUsers,
                    "delete": deleteUser,
                    "machines": viewMachines,
                    "create": lambda: createMachine(current_user["_id"]),
                    "logout": logout,
                    "exit": exit_program
                }
            else:
                options = {
                    "machines": viewMachines,
                    "create_machine": createMachine,
                    "delete_machine": deleteMachine,
                    "create_package": createPackage,
                    "logout": logout,
                    "exit": exit_program
                }
        else:
            options = {
                "create": createAccount,
                "login": login,
                "exit": exit_program
            }

        if current_user:
            if current_user.get("role") == "admin":
                print("Options: view , machines, create_machine, delete_machine, create_package, logout, Exit")
            else:
                print("Options: machines, create_machine, delete_machine, create_package, logout, Exit")
        else:
            print("Options: create, login, Exit")

        choice = input("Enter your choice: ").strip().lower()

        if choice in options:
            options[choice]()
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()