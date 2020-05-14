from flask import Flask, jsonify, request, json
from flask_mysqldb import MySQL
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
import random
import string

app = Flask(__name__)

with open('./connections.json') as f:
    data = json.load(f)

print(data)

app.config['MYSQL_USER'] = data['user']
app.config['MYSQL_PASSWORD'] = data['password']
app.config['MYSQL_HOST'] = data['host']
app.config['MYSQL_DB'] = 'YouChoose'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['JWT_SECRET_KEY'] = 'secret'


mysql = MySQL(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


def id_generator():

    random_id = ''.join(
        [random.choice(string.ascii_letters + string.digits) for i in range(32)])

    return random_id


def check_existing(email):

    cur = mysql.connection.cursor()
    # cur.execute('''SELECT * FROM Users where email= '''email''' )
    cur.execute("SELECT * FROM YouChoose.Users where email= '" + email + "'")
    result = cur.fetchall()

    print(len(result))

    if(len(result) >= 1):

        return True

    else:

        return False


@app.route('/signup', methods=['POST'])
def signup():
    cur = mysql.connection.cursor()
    full_name = request.get_json()['full_name']
    email = request.get_json()['email']  # check client side
    password = bcrypt.generate_password_hash(
        request.get_json()['password']).decode('utf-8')  # check client side
    created = datetime.utcnow()
    user_id = id_generator()
    email_validation = False

    check = check_existing(email)

    if(check == True):

        return('An account with this email already exists')

    else:

        cur.execute("INSERT INTO Users (full_name, email, password, user_id, created, email_validation) VALUES ('" +
                    full_name + "', '" +
                    email + "', '" +
                    password + "', '" +
                    user_id + "', '" +
                    str(created) + "', '" +
                    str(email_validation) + "')")

        mysql.connection.commit()

        return('Success')

    # print( '\\)


@app.route('/')
def index():
    # cur = mysql.connection.cursor()

    # # creating a table
    # cur.execute('''CREATE Table example (id INTEGER, name VARCHAR(20))''')

    # # inserting into table
    # cur.execute('''INSERT into example VALUES(1,Ned)''')

    # # saves data
    # mysql.connection.commit()

    # # select query
    # cur.execute('''SELECT * FROM example''')
    # result = cur.fetchall()
    # print(result)

    return 'Done!'


if __name__ == "__main__":
    app.run(debug=True)
