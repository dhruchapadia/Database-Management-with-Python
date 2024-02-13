from pymongo import MongoClient
import bcrypt
import random
import string
from openpyxl import Workbook

cluster = "mongodb://127.0.0.1:27017/"
client = MongoClient(cluster)
db = client.mydb
personCollection = db.person
postCollection = db.post

names = ["John", "Emma", "Michael", "Sophia", "James", "Olivia", "William", "Isabella", "Benjamin", "Mia"]
passwords = ["password1", "123456", "12345678", "qwerty", "abc123"]


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
            "name": post_name,
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


normal_usernames = ["user1", "user2", "user3"]

for username in normal_usernames:
    password = "user123"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user_data = {
        "name": random.choice(names),
        "username": username,
        "password": hashed_password.decode('utf-8'),
        "role": "user",  
        "posts": []
    }

    user = personCollection.insert_one(user_data)
    posts = generate_random_posts(user.inserted_id)
    for post in posts:
        post_id = postCollection.insert_one(post).inserted_id
        personCollection.update_one({"_id": user.inserted_id}, {"$push": {"posts": post_id}})


wb = Workbook()
ws = wb.active

ws.append(["Username", "Password"])

for _ in range(50):
    name = random.choice(names)
    username = generate_unique_username(name.lower().replace(" ", ""))
    password = random.choice(passwords)
    ws.append([username, password])
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user_data = {
        "name": name,
        "username": username,
        "password": hashed_password.decode('utf-8'),
        "role": "user",  
        "posts": []
    }

    user = personCollection.insert_one(user_data)


    posts = generate_random_posts(user.inserted_id)
    for post in posts:
        post_id = postCollection.insert_one(post).inserted_id
        personCollection.update_one({"_id": user.inserted_id}, {"$push": {"posts": post_id}})


print("Database generation complete.")

wb.save("user_credentials.xlsx")
print("Excel sheet generated.")
