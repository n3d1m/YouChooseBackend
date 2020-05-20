from flask import Flask, jsonify, request, json, url_for, make_response
from flask_mysqldb import MySQL
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Mail, Message
import random
import string

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
mail = Mail(app)

with open('./connections.json') as f:
    data = json.load(f)

print(data)

app.config['MYSQL_USER'] = data['user']
app.config['MYSQL_PASSWORD'] = data['password']
app.config['MYSQL_HOST'] = data['host']
app.config['MYSQL_DB'] = 'YouChoose'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['JWT_SECRET_KEY'] = data['secret']

s = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

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
    email_validation = 0
    session = 1

    check = check_existing(email)

    print(check)

    if(check == True):

        return jsonify(response='An account with this email already exists')

    else:

        cur.execute("INSERT INTO Users (full_name, email, password, user_id, created, email_validation, session) VALUES ('" +
                    full_name + "', '" +
                    email + "', '" +
                    password + "', '" +
                    user_id + "', '" +
                    str(created) + "', '" +
                    str(email_validation) + "', '" +
                    str(session) + "')")

        mysql.connection.commit()

        email_token = s.dumps([email], salt='email-confirm')
        #user_id_dump = s.dumps(user_id, salt='user-id')
        link = url_for('confirm_email',
                       email_token=email_token, _external=True)

        print(email_token)

        email_message = Message(
            'Confirm Email', sender='youchoose@noreply.com', recipients=[email])
        email_message.body = 'Your confirmation link is {}'.format(link)
        mail.send(email_message)

        return jsonify(response='Success')

    # print( '\\)


@app.route('/confirm_email/<email_token>')
def confirm_email(email_token):
    try:
        email = s.loads(email_token, salt='email-confirm', max_age=3600)
        print(email)
        cur = mysql.connection.cursor()

        # update the email confirmed column in db
        cur.execute(
            "UPDATE Users SET email_validation = True WHERE email = '" + email[0] + "'")
        mysql.connection.commit()
    except SignatureExpired:
        return 'The token is expired'

    return 'Email Confirmed!'


@app.route('/login', methods=['POST'])
def login():

    cur = mysql.connection.cursor()
    email = request.get_json()['email']
    password = request.get_json()['password']

    print(email, password)

    result = ''

    cur.execute("SELECT * FROM Users where email = '" + email + "'")
    mysql.connection.commit()
    data = cur.fetchone()

    if(data == None):

        return jsonify(response='There is no account linked to this email', ok=False)

    else:

        if bcrypt.check_password_hash(data['password'], password):

            access_token = create_access_token(
                identity={'full_name': data['full_name'], 'email': data['email']})
            result = jsonify(
                access_token=access_token, email=data['email'], ok=True)

            cur.execute(
                "UPDATE Users SET session = True WHERE email = '" + email + "'")
            mysql.connection.commit()

        else:

            result = jsonify(response='Invalid username or password', ok=False)

    return result


@app.route('/logout', methods=['POST'])
def logout():

    email = request.get_json()['email']
    cur = mysql.connection.cursor()

    cur.execute(
        "UPDATE Users SET session = False WHERE email = '" + email + "'")
    mysql.connection.commit()

    return jsonify({'success': True})


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
