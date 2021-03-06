from flask import Flask, jsonify, request, json, url_for, make_response
from flask_mysqldb import MySQL
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Mail, Message
from io import BytesIO, TextIOWrapper
import numpy as np
import sys
import random
import string
import requests
import time
import math

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
mail = Mail(app)

with open('./connections.json') as f:
    data = json.load(f)

# print(data)

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

    # print(len(result))

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

    # print(check)

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
        # user_id_dump = s.dumps(user_id, salt='user-id')
        link = url_for('confirm_email',
                       email_token=email_token, _external=True)

        # print(email_token)

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
        # print(email)
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

    # print(email, password)

    result = ''

    cur.execute("SELECT * FROM Users where email = '" + email + "'")
    mysql.connection.commit()
    data = cur.fetchone()

    # print(data)

    if(data == None):

        return jsonify(response='There is no account linked to this email', ok=False)

    else:

        if bcrypt.check_password_hash(data['password'], password):

            access_token = create_access_token(
                identity={'user_id': data['user_id']}, expires_delta=False)
            result = jsonify(
                access_token=access_token, email=data['email'], full_name=data['full_name'], user_id=data['user_id'], ok=True)

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


@app.route('/random_selection', methods=['POST'])
def places():

    auth_header = request.headers.get('Authorization').split(' ')

    # print(auth_header)

    if(len(auth_header) < 2):

        return(jsonify(ok=False, response='Invalid access token'))

    else:

        decode = decode_token(auth_header[1])

        # print(not isinstance(decode, str))

        # print(decode)

        if not isinstance(decode, str):

            lat = request.get_json()['lat']
            lng = request.get_json()['long']

            endpoint = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?parameters"
            params = {
                'location': str(lat) + ',' + str(lng),
                'radius': '5000',
                'type': 'restaurant|meal_delivery|meal_takeaway',
                'key': data['google_key']
            }

            places = []

            res = requests.get(endpoint, params=params)
            results = json.loads(res.content)
            places.extend(results['results'])
            time.sleep(2)

            while "next_page_token" in results:
                params['pagetoken'] = results['next_page_token'],
                res = requests.get(endpoint, params=params)
                results = json.loads(res.content)
                places.extend(results['results'])
                time.sleep(2)

            places_length = len(places)
            random_index = random.randint(0, places_length-1)

            return_data = places[random_index]

            try:
                image = ('https://maps.googleapis.com/maps/api/place/photo'
                         '?maxwidth=%s'
                         '&?maxheight=%s'
                         '&photoreference=%s'
                         '&key=%s') % (return_data['photos'][0]['width'], return_data['photos'][0]['height'],
                                       return_data['photos'][0]['photo_reference'], data['google_key'])

            except:
                image = None

            return_data['image_url'] = image

            return_data = filter_place_details(
                return_data['place_id'], return_data)

            # print(return_data)

            return(
                jsonify(data=return_data, ok=True)
            )

        else:

            return(jsonify(ok=False, response='Invalid access token'))


def filter_place_details(id, obj):

    place_detail_url = "https://maps.googleapis.com/maps/api/place/details/json?parameters"
    detail_params = {
        'key': data['google_key'],
        'place_id': id
    }

    detail_res = requests.get(place_detail_url, params=detail_params)
    place_details = json.loads(detail_res.content)

    # print(place_details['result']['reviews'])
    # print(place_details['result']['opening_hours']['weekday_text'])
    # print(place_details['result']['website'])

    # get_place_logo(place_details['result']['name'],
    # place_details['result']['formatted_address'].split(',')[1])

    blacklist = ['facebook.com']
    obj['address'] = place_details['result']['formatted_address'].split(',')[0]
    obj['photo_array'] = get_photos(place_details['result']['photos'])

    try:

        obj['opening_hours']['hours'] = place_details['result']['opening_hours']['weekday_text']

    except:

        try:

            obj['opening_hours']['hours'] = None

        except:

            obj['opening_hours'] = None

    try:

        obj['phone_number'] = place_details['result']['formatted_phone_number']

    except:

        obj['phone_number'] = None

    try:

        obj['reviews'] = place_details['result']['reviews']

    except:

        obj['reviews'] = None

    try:
        website = place_details['result']['website'].split(
            '://')[1].split('/')[0].split('www.')

        if website in blacklist:

            website = None

        elif len(website) > 1:

            website = website[1]

        else:

            website = website[0]

        # print(website)

        obj['logo_url'] = website
        obj['full_website'] = place_details['result']['website']

    except:

        obj['logo_url'] = None
        obj['full_website'] = None

    return obj


def get_photos(arr):

    photo_bucket = []

    for i in arr:

        try:
            image = ('https://maps.googleapis.com/maps/api/place/photo'
                     '?maxwidth=%s'
                     '&?maxheight=%s'
                     '&photoreference=%s'
                     '&key=%s') % (i['width'], i['height'],
                                   i['photo_reference'], data['google_key'])
        except:

            image = None

        photo_bucket.append(image)

    return photo_bucket


@app.route('/filtered_selection', methods=['POST'])
def places_filtered():

    auth_header = request.headers.get('Authorization').split(' ')

    # print(auth_header)

    if(len(auth_header) < 2):

        return(jsonify(ok=False, response='Invalid access token'))

    else:

        decode = decode_token(auth_header[1])

        if not isinstance(decode, str):

            lat = request.get_json()['lat']
            lng = request.get_json()['long']
            category = request.get_json()['category']
            price_range = request.get_json()['price_range']
            distance = request.get_json()['distance']
            rating = request.get_json()['rating'],
            city = request.get_json()['city']

            print(request.get_json())

            distance_val = None if distance == None else str(distance*1000)
            rating_val = None if rating[0] == None else str(
                rating).strip('()').split(',')

            print(rating)

            endpoint = "https://maps.googleapis.com/maps/api/place/details/json?parameters" if category == None else 'https://maps.googleapis.com/maps/api/place/textsearch/json?parameters'
            params = {
                'key': data['google_key'],
                'query': str(category) + ' food in ' + str(city),
                'location': str(lat) + ',' + str(lng),
                'radius': distance_val,
                'minprice': price_range_convert(price_range)['minprice'],
                'maxprice': price_range_convert(price_range)['maxprice'],
                'type': 'restaurant|meal_delivery|meal_takeaway',
            }

            # {
            #     'location': str(lat) + ',' + str(lng),
            #     'radius': '5000',
            #     'type': 'restaurant|meal_delivery|meal_takeaway',
            #     'key': data['google_key']
            # }

            places = []

            print(endpoint)

            res = requests.get(endpoint, params=params)
            results = json.loads(res.content)

            places.extend(results['results'])
            time.sleep(2)

            while "next_page_token" in results:
                params['pagetoken'] = results['next_page_token'],
                res = requests.get(endpoint, params=params)
                results = json.loads(res.content)
                places.extend(results['results'])
                time.sleep(2)

            return_data = None

            #print('places: ', places)

            if(rating_val == None):

                places_length = len(places)
                random_index = random.randint(
                    0, math.ceil(abs(np.log(places_length)/np.log(0.75))))
                return_data = places[random_index]

            else:

                filtered_data = []
                rating_val.remove('')
                rating_val = rating_val[0]

                for i in places:

                    if i['rating'] >= int(rating_val):
                        filtered_data.append(i)

                filtered_length = len(filtered_data)
                print(filtered_length)

                if(filtered_length == 0):

                    return_data = None

                else:

                    random_index = random.randint(
                        0, math.ceil(abs(np.log(filtered_length)/np.log(0.75))))
                    return_data = filtered_data[random_index]

            if(return_data != None):

                try:
                    image = ('https://maps.googleapis.com/maps/api/place/photo'
                             '?maxwidth=%s'
                             '&?maxheight=%s'
                             '&photoreference=%s'
                             '&key=%s') % (return_data['photos'][0]['width'], return_data['photos'][0]['height'],
                                           return_data['photos'][0]['photo_reference'], data['google_key'])

                except:
                    image = None

                return_data['image_url'] = image

                return_data = filter_place_details(
                    return_data['place_id'], return_data)

            return(
                jsonify(data=return_data, ok=True)
            )

        else:

            return(jsonify(ok=False, response='Invalid access token'))


def price_range_convert(arr):
    returnObj = {
        'minprice': '',
        'maxprice': ''
    }

    if(arr == None):
        returnObj['maxprice'] = None
        returnObj['minprice'] = None

    else:

        arr = arr.split(', ')
        intArr = []

        for i in arr:

            intArr.append(len(i)-1)

        intArr.sort()

        if len(intArr) == 1:
            returnObj['maxprice'] = intArr[0] if intArr[0] > 0 else intArr[0]+1
            returnObj['minprice'] = None
        else:
            returnObj['maxprice'] = max(intArr)
            returnObj['minprice'] = min(intArr)

    return returnObj


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
