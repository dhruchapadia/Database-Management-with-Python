from pymongo import MongoClient
from bson.objectid import ObjectId
# import json
import datetime
import bcrypt

cluster = "mongodb://127.0.0.1:27017/"
client = MongoClient(cluster)
db = client.mydb
personCollection = db.person
postCollection = db.post

current_user = None  

def login():
    global current_user
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    try:
        user = personCollection.find_one({"username": username})

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
            "posts": []
        }

        inserted_id = personCollection.insert_one(data).inserted_id
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

    cursor = personCollection.find()
    print("Data in 'person' collection:")
    for person in cursor:
        print(person)

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
        result_user = personCollection.delete_one({"_id": user_id})
        if result_user.deleted_count == 1:
            print("User account has been deleted successfully.")
            if current_user["_id"] == user_id:
                logout()  
        else:
            print("An error occurred. User account could not be deleted.")
            return
        
        result_posts = postCollection.delete_many({"author_id": user_id})
        print(f"{result_posts.deleted_count} posts by the user have been deleted.")
    except Exception as e:
        print("An error occurred:", e)



def createPost(author_id):
    img = input("Enter your post content (text): ").strip()
    privacy = input("Enter post privacy (private or public, press Enter for public): ").strip().lower()

    if not img:
        print("Post content is required.")
        return

    if privacy == '':
        privacy = 'public'

    try:
        post_data = {
            "author_id": author_id,
            "img": img,
            "privacy": privacy,
            "timestamp": datetime.datetime.now()
        }

        inserted_post = postCollection.insert_one(post_data)
        post_id = inserted_post.inserted_id
        print("Post created successfully with ID:", post_id)

        personCollection.update_one({"_id": author_id}, {"$push": {"posts": post_id}})
    except Exception as e:
        print("An error occurred:", e)

def viewPosts():
    global current_user

    if not current_user:
        print("You must be logged in to view posts.")
        return

    current_user_id = current_user["_id"]

    user_posts = postCollection.find({
        "$or": [
            {"author_id": current_user_id, "privacy": {"$ne": "hidden"}},
            {"$and": [
                {"author_id": {"$ne": current_user_id}},
                {"$or": [
                    {"privacy": "public"},
                    {"$and": [
                        {"privacy": "private", "author_id": current_user_id}
                    ]}
                ]}
            ]}
        ]
    })
    for post in user_posts:
        print(post)

def viewAllPosts():
    global current_user

    if not current_user:
        print("You must be logged in to view posts.")
        return

    if current_user.get("role") == "admin":
        all_posts = postCollection.find()
        print("All posts:")
        for post in all_posts:
            print(post)
    else:
        print("Only admin users can view all posts.")


def deletePost():
    global current_user

    if not current_user:
        print("You must be logged in to delete a post.")
        return
    
    post_id_str = input("Enter the ObjectId of the post you want to delete: ").strip()
    try:
        post_id = ObjectId(post_id_str)
    except ValueError:
        print("Invalid ObjectId.")
        return
    try:
        post = postCollection.find_one({"_id": post_id})

        if not post:
            print("Post not found.")
            return

        if post["author_id"] != current_user["_id"]:
            print("You are not authorized to delete this post.")
            return

        confirmation = input("Are you sure you want to delete this post? (yes/no): ").strip().lower()
        if confirmation != "yes":
            print("Post deletion cancelled.")
            return

        result = postCollection.update_one({"_id": post_id}, {"$set": {"privacy": "hidden"}})
        if result.modified_count == 1:
            print("Post deleted successfully.")
        else:
            print("An error occurred. Post could not be deleted.")

    except Exception as e:
        print("An error occurred:", e)

def adminDeletePost():
    global current_user

    if not current_user:
        print("You must be logged in to delete a post.")
        return

    post_id_str = input("Enter the ObjectId of the post you want to delete: ").strip()
    try:
        post_id = ObjectId(post_id_str)
    except ValueError:
        print("Invalid ObjectId.")
        return
    if current_user.get("role") != "admin":
        print("Only admin users can delete posts.")
        return

    try:
        result = postCollection.delete_one({"_id": post_id})
        if result.deleted_count == 1:
            print("Post deleted successfully.")
        else:
            print("Post not found or could not be deleted.")
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
                    "feed": viewAllPosts,
                    "post": lambda: createPost(current_user["_id"]),
                    "logout": logout,
                    "delete": adminDeletePost,
                    "exit": exit_program
                }
            else:
                options = {
                    "delete": deleteUser,
                    "feed": viewPosts,
                    "post": lambda: createPost(current_user["_id"]),
                    "logout": logout,
                    "delete": deletePost,
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
                print("Options: view, feed, delete, post, logout, Exit")
            else:
                print("Options: feed, delete, post, logout, Exit")
        else:
            print("Options: create, login, Exit")

        choice = input("Enter your choice: ").strip().lower()

        if choice in options:
            options[choice]()
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
