import mysql.connector as ms
import hashlib
import secrets


mycon=ms.connect(host='localhost',user='root',password='saisabs',database='Reauth')

mycur=mycon.cursor()

def add_user():
    username=input("Enter your username:")
    password=input("Enter your password:")

    #Hash the password
    password_hash=hashlib.sha256(password.encode()).hexdigest()

    q="insert into users(username,password_hash) values(%s,%s)"
    mycur.execute(q,(username,password_hash))
    mycon.commit()

    user_id=mycur.lastrowid
    recovery_code=give_recovery_code()
    store_recovery_code(user_id,recovery_code)


    print("User succesfully added")
    print("User ID:",user_id)
    


def give_recovery_code():
    recovery_code=secrets.token_hex(8)
    print("Your recovery codde is:",recovery_code)
    return recovery_code
def store_recovery_code():
    code_hash=hashlib.sha256(recovery_code.encode()).hexdigest()
    q="insert into recovery_codes(user_id,code_hash) values(%s,%s)"
    mycur.execute(q,(user_id,code_hash))
    mycon.commit()
    print('Recovery code is stored succesfully')

