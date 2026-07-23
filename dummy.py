from flask import Flask, jsonify, request, url_for, session
from flask_session import Session
import re
import random
import os
from mysql.connector import connection
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from cmail import send_mail
from stoken import endata, dndata
from werkzeug.utils import secure_filename
from otp import genotp

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'webp', 'gif', 'png'}


app = Flask(__name__)
CORS(app, supports_credentials=True)
bcrypt = Bcrypt(app)

app.secret_key = 'Code@123'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024

Session(app)


mydb = connection.MySQLConnection(
    user='root',
    host='localhost',
    password='Admin@23',
    db='ecom29db'
)



def allowed_extension(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "success",
        "message": "Welcome to ecom app"
    }), 200


@app.route('/api/admin/register', methods=['POST'])
def admincreate():
    cursor = None

    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "failed",
                "message": "No valid JSON input given"
            }), 400

        adminname = data.get('username', '').strip()
        adminemail = data.get('useremail', '').strip()
        adminpassword = data.get('userpassword', '').strip()
        adminaddress = data.get('useraddress', '').strip()
        adminagree = data.get('useragree')

        if not adminname:
            return jsonify({
                "status": "failed",
                "message": "Username required"
            }), 400

        if not adminemail:
            return jsonify({
                "status": "failed",
                "message": "Email required"
            }), 400

        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

        if not re.match(email_pattern, adminemail):
            return jsonify({
                "status": "failed",
                "message": "Invalid email address"
            }), 400

        if not adminpassword:
            return jsonify({
                "status": "failed",
                "message": "Password required"
            }), 400

        if len(adminpassword) < 6:
            return jsonify({
                "status": "failed",
                "message": "Password is too short"
            }), 400

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute("select adminemail from admindata where adminemail=%s", (adminemail,))

        existing_admin = cursor.fetchone()

        if existing_admin:
            return jsonify({
                "status": "failed",
                "message": "Email already exists"
            }), 409

        gotp = genotp()

        hashed_password = bcrypt.generate_password_hash(adminpassword).decode('utf-8')

        admindata = {
            "admin_username": adminname,
            "admin_useremail": adminemail,
            "admin_address": adminaddress,
            "admin_userpassword": hashed_password,
            "admin_agree": adminagree,
            "admin_otp": gotp
        }

        subject = "Verification code for admin"

        body = f"""Hello Admin,Your OTP is: {gotp}This OTP is valid for 5 minutes."""

        send_mail(
            to=adminemail,
            subject=subject,
            body=body
        )

        token = endata(admindata)

        return jsonify({
            "status": "success",
            "message": "OTP sent successfully",
            "token": token
        }), 200

    except Exception as e:
        print("Error in admin register:", str(e))

        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()


@app.route('/api/admin/verify-otp', methods=['POST'])
def adminotpverify():
    cursor = None

    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "status": "failed",
                "message": "No valid JSON input given"
            }), 400

        userotp = data.get('otp')
        token = data.get('token')

        if userotp is None or not token:
            return jsonify({
                "status": "failed",
                "message": "OTP and token required"
            }), 400

        try:
            admin_details = dndata(token)

        except Exception:
            return jsonify({
                "status": "failed",
                "message": "Invalid or expired token"
            }), 400

        tokenotp = admin_details.get('admin_otp')

        if int(userotp) != int(tokenotp):
            return jsonify({
                "status": "failed",
                "message": "Invalid OTP"
            }), 400

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute("select count(*) from admindata where adminemail=%s", (admin_details['admin_useremail'],))

        email_exists = cursor.fetchone()[0]

        if email_exists > 0:
            return jsonify({
                "status": "failed",
                "message": "Email already exists"
            }), 409

        cursor.execute("insert into admindata(adminid,adminname,adminemail,adminpassword,adminaddress,adminagree) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s)", (admin_details['admin_username'], admin_details['admin_useremail'], admin_details['admin_userpassword'], admin_details['admin_address'], admin_details['admin_agree']))

        mydb.commit()

        return jsonify({
            "status": "success",
            "message": "Admin details registered successfully"
        }), 200

    except Exception as e:
        mydb.rollback()
        print("MySQL Error:", str(e))

        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()


@app.route('/api/admin/login', methods=['POST'])
def adminlogin():
    cursor = None

    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "status": "failed",
                "message": "No input data given"
            }), 400

        login_email = data.get('email', '').strip()
        login_password = data.get('password', '').strip()

        if not login_email or not login_password:
            return jsonify({
                "status": "failed",
                "message": "Login email and password required"
            }), 400

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute("select bin_to_uuid(adminid),adminname,adminemail,adminpassword from admindata where adminemail=%s", (login_email,))

        admin_data = cursor.fetchone()

        if not admin_data:
            return jsonify({
                "status": "failed",
                "message": "Invalid email"
            }), 400

        adminid = admin_data[0]
        adminname = admin_data[1]
        adminemail = admin_data[2]
        stored_password = admin_data[3]

        if not bcrypt.check_password_hash(stored_password, login_password):
            return jsonify({
                "status": "failed",
                "message": "Invalid password"
            }), 400

        session.permanent = True
        session['adminid'] = adminid
        session['adminemail'] = adminemail
        print(session)
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "admin": {
                "adminid": adminid,
                "adminname": adminname,
                "adminemail": adminemail
            }
        }), 200

    except Exception as e:
        mydb.rollback()
        print("MySQL Error:", str(e))

        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()


@app.route('/api/admin/dashboard', methods=['GET'])
def admindashboard():
    try:
        if 'adminid' not in session:
            return jsonify({
                "status": "failure",
                "message": "Please login first"
            }), 401

        return jsonify({
            "status": "success",
            "message": "Welcome admin",
            "admin": {
                "adminid": session.get('adminid'),
                "adminemail": session.get('adminemail')
            }
        }), 200

    except Exception as e:
        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 500


@app.route('/api/admin/add-item', methods=['POST'])
def additem():
    cursor = None
    save_path = None
    print(session)
    try:
        if 'adminid' not in session:
            return jsonify({
                "status": "failure",
                "message": "Please login first"
            }), 401

        item_name = request.form.get('title', '').strip()
        item_description = request.form.get('Description', '').strip()
        item_about = request.form.get('About_item', '').strip()
        item_price = request.form.get('price', '').strip()
        item_quantity = request.form.get('quantity', '').strip()
        item_category = request.form.get('category', '').strip()

        if not item_name:
            return jsonify({
                "status": "failure",
                "message": "Item name required"
            }), 400

        if not item_description:
            return jsonify({
                "status": "failure",
                "message": "Item description required"
            }), 400

        if not item_price or not item_quantity:
            return jsonify({
                "status": "failure",
                "message": "Price and quantity required"
            }), 400

        try:
            item_price = int(item_price)
            item_quantity = int(item_quantity)

        except ValueError:
            return jsonify({
                "status": "failure",
                "message": "Price and quantity must be integers"
            }), 400

        item_filedata = request.files.get('file')

        if not item_filedata or not item_filedata.filename:
            return jsonify({
                "status": "failure",
                "message": "Item image required"
            }), 400

        filename = item_filedata.filename

        if not allowed_extension(filename):
            return jsonify({
                "status": "failure",
                "message": "Invalid file type"
            }), 400

        if not item_filedata.mimetype.startswith('image/'):
            return jsonify({
                "status": "failure",
                "message": "Invalid image"
            }), 400

        sec_filename = secure_filename(filename)
        ext = os.path.splitext(sec_filename)[1]
        new_filename = str(genotp()) + ext

        save_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)

        item_filedata.save(save_path)
        #mysql connection
        mydb.ping(reconnect=True)
        userid = session.get('adminid')
        cursor = mydb.cursor(buffered=True)
        cursor.execute('insert into items(itemid,itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename,added_by) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s,%s,uuid_to_bin(%s))', [item_name, item_description, item_about, item_price, item_quantity, item_category, new_filename, userid])
        mydb.commit()

        return jsonify({
            "status": "success",
            "message": "Item details registered successfully",
            "image_url": url_for(
                'static',
                filename=f'uploads/{new_filename}',
                _external=True
            )
        }), 200

    except Exception as e:
        mydb.rollback()
        print("MySQL Error:", str(e))

        if save_path and os.path.exists(save_path):
            os.remove(save_path)

        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/items',methods=['GET'])
def viewallitems():
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({
                "status": "failure",
                "message": "Please login first"
            })
        #mysql connection
        mydb.ping(reconnect=True)
        userid = session.get('adminid')
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where added_by=uuid_to_bin(%s)',[userid])
        allitems_data=cursor.fetchall()
        if not allitems_data:
            return jsonify({
                "status":"failure",
                "message":"No item found"
            })
        
        products=[]
        for item in allitems_data:
            products.append({
                'itemid':item[0],
                'itemname':item[1],
                'item_desc':item[2],
                'item_about':item[3],
                'price':float(item[4]),
                'quantity':item[5],
                'category':item[6],
                'image':url_for('static',filename=f'upload/{item[7]}',_external=True)
            })
        return jsonify({
            "status":"success",
            "message":"All items data",
            "products":products
        })
    except Exception as e:
        print('Mysql Error',str(e))
        return jsonify({
            "status":"failed",
            "message":f"{str(e)}"
        }),500
    finally:
        if cursor:
            cursor.close()
        


@app.route('/api/admin/item/<id>',methods=['GET'])
def viewitems(id):
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({
                "status": "failure",
                "message": "Please login first"
            })
        #mysql connection
        mydb.ping(reconnect=True)
        userid = session.get('adminid')
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,id])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({
                "status":"failure",
                "message":"No item found"
            })
        
        products=({
                'itemid':item_data[0],
                'itemname':item_data[1],
                'item_desc':item_data[2],
                'item_about':item_data[3],
                'price':float(item_data[4]),
                'quantity':item_data[5],
                'category':item_data[6],
                'image':url_for('static',filename=f'upload/{item_data[7]}',_external=True)
            })
        return jsonify({
            "status":"success",
            "message":"All items data",
            "product":products
        })
    except Exception as e:
        print('Mysql Error',str(e))
        return jsonify({
            "status":"failed",
            "message":f"{str(e)}"
        }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/delete-item/<itemid>',methods=['DELETE'])
def deleteitems(itemid):
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({
                "status": "failure",
                "message": "Please login first"
            })
         #mysql connection
        mydb.ping(reconnect=True)
        userid = session.get('adminid')
        cursor = mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,itemid])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({
                "status":"failure",
                "message":"No item found"
            })
        image_name=item_data[7]   #old image filename
        remove_path=os.path.join(app.config['UPLOAD_FOLDER'],image_name)
        #delete from db
        cursor.execute('delete from items where itemid=uuid_to_bin(%s) and added_by=uuid_to_bin(%s)',[itemid ,userid])
        mydb.commit()
        #delete from static folder after db delete
        if os.path.exists(remove_path):
            os.remove(remove_path)
        return jsonify ({
            "status":"success",
            "message":"item deleted successfully"
        })
    except Exception as e:
        mydb.rollback()
        print('Mysql Error',str(e))
        return jsonify({
            "status":"failed",
            "message":f"{str(e)}"
        }),500
    finally:
        if cursor:
            cursor.close()
        


if __name__ == '__main__':
    app.run()