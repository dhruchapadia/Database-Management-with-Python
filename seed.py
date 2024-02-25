from pymongo import MongoClient
import bcrypt
import random
import string
from openpyxl import Workbook

cluster = 
client = MongoClient(cluster)
db = client.mydb
personCollection = db.person
postCollection = db.post

names = ["John", "Emma", "Michael", "Sophia", "James", "Olivia", "William", "Isabella", "Benjamin", "Mia"]
passwords = ["password1", "123456", "12345678", "qwerty", "abc123"]
emails = ["example1@example.com", "example2@example.com", "example3@example.com"]
ages = [20, 25, 30, 35, 40]
addresses = ["123 Street, City", "456 Avenue, Town", "789 Road, Village"]
contact_numbers = ["1234567890", "9876543210", "5555555555"]

def generate_unique_username(username):
    while personCollection.find_one({"username": username}):
        username += str(random.randint(1, 999))
    return username

def generate_random_posts(author_id):
    privacy_options = ["hidden", "private", "public"]
    posts = []

    for _ in range(random.randint(2, 3)):
        name = random.choice(names)
        post_name = f"This is {name} post {random.randint(1, 100)}"
        privacy = random.choice(privacy_options)

        post_data = {
            "author_id": author_id,
            "img": post_name,
            "privacy": privacy
        }
        posts.append(post_data)

    return posts

admin_username = "dhru"
admin_password = "admin123"
hashed_admin_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())

admin_data = {
    "name": "Admin",
    "username": admin_username,
    "password": hashed_admin_password.decode('utf-8'),
    "role": "admin",  
    "posts": []
}

personCollection.insert_one(admin_data)


wb = Workbook()
ws = wb.active

ws.append(["Username", "Password"])

for _ in range(50):
    name = random.choice(names)
    username = generate_unique_username(name.lower().replace(" ", ""))
    password = random.choice(passwords)
    ws.append([username, password])
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    email = random.choice(emails) if random.random() < 0.8 else None  
    age = random.choice(ages) if random.random() < 0.6 else None  
    address = random.choice(addresses) if random.random() < 0.7 else None  
    contact_number = random.choice(contact_numbers) if random.random() < 0.5 else None  

    user_data = {
    "username": username,
    "password": hashed_password.decode('utf-8'),
    "role": "user",
    "posts": []
    }

    if name is not None:
        user_data["name"] = name
    if email is not None:
        user_data["email"] = email
    if age is not None:
        user_data["age"] = age
    if address is not None:
        user_data["address"] = address
    if contact_number is not None:
        user_data["contact_number"] = contact_number

    user = personCollection.insert_one(user_data)


    posts = generate_random_posts(user.inserted_id)
    for post in posts:
        post_id = postCollection.insert_one(post).inserted_id
        personCollection.update_one({"_id": user.inserted_id}, {"$push": {"posts": post_id}})


print("Database generation complete.")

wb.save("user_credentials.xlsx")
print("Excel sheet generated.")
