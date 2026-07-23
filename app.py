from flask import Flask,request,url_for,jsonify,session,make_response
from flask_session import Session
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import razorpay 
import re
from mysql.connector import connection
from flask_bcrypt import Bcrypt #to hash the plain passwords
from otp import genotp
from cmail import send_mail
from stoken import endata,dndata
from werkzeug.utils import secure_filename #used to remove extra space,',',.,/
mydb=connection.MySQLConnection(user='root',host='localhost',password='Admin@23',db='ecom29db')
client = razorpay.Client(auth=("rzp_test_TEuFBgBKeyncR9", "fvQPMFoCIbPQkWe1u50zFwAW"))
import os
from io import BytesIO
from reportlab.platypus import (SimpleDocTemplate,Table,TableStyle,Paragraph,Spacer)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.platypus.flowables import HRFlowable
from datetime import timedelta

BASE_DIR=os.path.abspath(os.path.dirname(__file__)) #finds the base directory of app file
print(BASE_DIR)
UPLOAD_FOLDER=os.path.join(BASE_DIR,'static','uploads') #sets static folder path
print(UPLOAD_FOLDER)
os.makedirs(UPLOAD_FOLDER,exist_ok=True) #create static folder if not exists
ALLOWED_EXTENSIONS={'jpg','jpeg','webp','gif','png'}
MAX_CONTENT_LENGTH=6*1024*1024  #6MB
app=Flask(__name__)
app.wsgi_app=ProxyFix(app.wsgi_app,x_proto=1,x_host=1)
app.config['PREFERED_URL_SCHEME']='HTTPS'
app.permanent_session_lifetime=timedelta(days=1)
CORS(app,supports_credentials=True)
bcrypt=Bcrypt(app)
app.secret_key='Code@123'
app.config['SESSION_TYPE']='filesystem'
app.config['SESSION_COOKIE_SECURE']=True
app.config['SESSION_COOKIE_HTTPONLY']=True
app.config['SESSION_COOKIE_SAMESITE']="None"
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER
Session(app)

@app.route('/',methods=['GET'])
def home():
    return jsonify({
        "status":"success",
        "Message":"Welcome to Ecom ApPy"
    }),200

@app.route('/api/admin/register',methods=['POST'])
def admincreate():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({
                "status":"failed",
                "message":"No input given"
            }),400
        adminname=data.get('username','').strip()
        adminemail=data.get('useremail','').strip()
        adminpassword=data.get('userpassword','').strip()
        adminaddress=data.get('useraddress','').strip()
        adminagree=data.get('useragree')
        if not adminname:
            return jsonify({
                "status":"failed",
                "message":"Username required"
            }),400
        email_pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern,adminemail):
            return  jsonify({
                "status":"failed",
                "message":"Invalid email"
            }),400
        if len(adminpassword)<6:
            return jsonify({
                "status":"failed",
                "message":"password is too short"
            }),400
        mydb.ping(reconnect=True) #if connection lost it reconnects the mysql server
        cursor=mydb.cursor(buffered=True)
        #email recheck
        cursor.execute('select count(*) from admindata where adminemail=%s',[adminemail])
        email_exists=cursor.fetchone()[0]
        if email_exists>0:
            return jsonify({
                "status":"failed",
                "message":f"Email already existed"
            }),400
        gotp=genotp()
        #generate hashpassword value
        hashed_password=bcrypt.generate_password_hash(adminpassword).decode('utf-8')
        admindata={
            "admin_username":adminname,
            "admin_useremail":adminemail,
            "admin_address":adminaddress,
            'admin_userpassword':hashed_password,
            "admin_agree":adminagree,
            "admin_otp":gotp
        }
        subject='Admin Registration Verification'
        body=f''' Hello Admin,
                  Your OTP is {gotp}
                  This otp is valid for 5 mins'''
        send_mail(to=adminemail,subject=subject,body=body)
        token=endata(admindata)
        return jsonify({
                "status":"success",
                "message":"OTP sent successfully",
                "token":token
            }),200
    except Exception as e:
        print('Eroor in admin register',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/verify-otp',methods=["POST"])
def adminotpverify():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({
                "status":"failed",
                "message":f"No input data"
            }),401
        userotp=data.get('otp')
        token=data.get('token')
        if not userotp or not token:
            return jsonify({
                "status":"failed",
                "message":f"otp and token required"
            }),400
        try:
            admin_details=dndata(token)
        except Exception:
            return jsonify({
                "status":"failed",
                "message":f"Invalid or expired token"
            }),400
        #otp validation
        print(admin_details,userotp)
        if str(userotp)!=str(admin_details['admin_otp']):
            return jsonify({
                "status":"failed",
                "message":f"Invalid otp"
            }),400
        mydb.ping(reconnect=True) #if connection lost it reconnects the mysql server
        cursor=mydb.cursor(buffered=True)
        #email recheck
        cursor.execute('select count(*) from admindata where adminemail=%s',[admin_details['admin_useremail']])
        email_exists=cursor.fetchone()[0]
        if email_exists>0:
            return jsonify({
                "status":"failed",
                "message":f"Email already existed"
            }),400
        cursor.execute('insert into admindata(adminid,adminname,adminemail,adminpassword,adminaddress,adminagree) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s)',[admin_details['admin_username'],admin_details['admin_useremail'],admin_details['admin_userpassword'],admin_details['admin_address'],admin_details['admin_agree']])
        mydb.commit()
        return jsonify({
                "status":"success",
                "message":f"Admin details Registered successfully"
            }),200
    except Exception as e:
        mydb.rollback()
        print('Mysql error',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/login',methods=['POST'])
def adminlogin():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({
                "status":"failed",
                "message":"No Input data given"
            }),401
        login_email=data.get('email','').strip()
        login_password=data.get('password','').strip()
        if not login_email or not login_password:
            return jsonify({
                "status":"failed",
                "message":"Login email and password required"
            }),401
        mydb.ping(reconnect=True) #if connection lost it reconnects the mysql server
        cursor=mydb.cursor(buffered=True)
        #email recheck
        cursor.execute('select bin_to_uuid(adminid),adminname,adminemail,adminpassword  from admindata where adminemail=%s',[login_email])
        admin_data=cursor.fetchone()
        if not admin_data:
            return jsonify({
                "status":"failed",
                "message":f"Invalid email"
            }),400
        adminid=admin_data[0]
        adminname=admin_data[1]
        adminemail=admin_data[2]
        stored_password=admin_data[3]
        if not bcrypt.check_password_hash(stored_password,login_password):
            return jsonify({
                "status":"failed",
                "message":f"Invalid password"
            }),400
        session.permenant=True
        session['adminid']=adminid
        session['adminemail']=adminemail
        return jsonify({
                "status":"success",
                "message":f"login successful",
                'admin':{
                    'adminid':adminid,
                    'adminname':adminname,
                    'adminemail':adminemail
                }
            }),200
    except Exception as e:
        print('Mysql error',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/dashboard',methods=['GET'])
def admindashboard():
    try:
        if  'adminid' not in session:
            return jsonify({
                "status":"failure",
                "message":"pls login first"
            })
        return jsonify({
            "status":"success",
            "message":"Welcome Admin",
            "admin":{
                "adminid":session.get('adminid'),
                "adminemail":session.get('adminemail')
            }
        })
    except Exception as e:
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
def allowed_extension(filename:str)->bool:
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS
    
@app.route('/api/admin/add-item',methods=['POST'])
def additem():
    cursor = None
    save_path = None

    try:
        if 'adminid' not in session:
            return  jsonify({
                "status":"failure",
                "message":"pls login first"
            })
        data=request.form
        if not data:
            return jsonify({
                "status":"failure",
                "message":"No input given "
            })
        item_name=request.form.get('title','').strip()
        item_description=request.form.get('Description').strip()
        item_about=request.form.get('About_item','').strip()
        item_price=request.form.get('price','').strip()
        item_quantity=request.form.get('quantity','').strip()
        item_category=request.form.get('category','').strip()
        if not item_name:
            return jsonify({
                "status":"failure",
                "message":"Item name required "
            }),400
        try:
            item_price=int(item_price) #'670' or 'hi'
            item_quantity=int(item_quantity)
        except ValueError:
            return jsonify({
                "status":"failure",
                "message":"price and quantity must be integers "
            }),400
        item_filedata=request.files.get('file')
        print(item_filedata.filename)
        if not item_filedata:
            return jsonify({
                "status":"failure",
                "message":"item image required"
            }),400
        filename=item_filedata.filename
        if not allowed_extension(filename):
            return jsonify({
                "status":"failure",
                "message":"Invalid file type"
            }),400
        if not item_filedata.mimetype.startswith('image/'):
            return jsonify({
                "status":"failure",
                "message":"Invalid image"
            }),400
        sec_filename=secure_filename(filename)
        ext=os.path.splitext(sec_filename)[1] #only extracts extension
        new_filename=genotp()+ext
        save_path=os.path.join(app.config['UPLOAD_FOLDER'],new_filename)
        try:
            item_filedata.save(save_path)
        except Exception as e:
            print(e)
            return jsonify({
                "status":"failed",
                "message":"Could not save file"
            })
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('adminid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('insert into items(itemid,itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename,added_by) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s,%s,uuid_to_bin(%s))',[item_name,item_description,item_about,item_price,item_quantity,item_category,new_filename,userid])
        mydb.commit()
        return jsonify({
                "status":"success",
                "message":"Item details registered successfully",
                "image_url":url_for('static',filename=f'uploads/{new_filename}',_external=True)
            })
    except Exception as e:
        mydb.rollback()
        print('Mysql Error',str(e))
        if save_path and os.path.exists(save_path):
            os.remove(save_path)
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/items',methods=['GET'])
def viewallitems():
    cursor=None
    try:
        if 'adminid' not in session:
            return  jsonify({
                "status":"failure",
                "message":"pls login first"
            })
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('adminid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where added_by=uuid_to_bin(%s)',[userid])
        allitems_data=cursor.fetchall()
        if not allitems_data:
            return jsonify({
                "status":"failure",
                "message":"No items found"
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
                'image':url_for('static',filename=f'uploads/{item[7]}',_external=True)
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
def viewitem(id):
    cursor=None
    try:
        if 'adminid' not in session:
            return  jsonify({
                "status":"failure",
                "message":"pls login first"
            })
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('adminid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,id])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({
                "status":"failure",
                "message":"No item found"
            })
        products={
                'itemid':item_data[0],
                'itemname':item_data[1],
                'item_desc':item_data[2],
                'item_about':item_data[3],
                'price':float(item_data[4]),
                'quantity':item_data[5],
                'category':item_data[6],
                'image':url_for('static',filename=f'uploads/{item_data[7]}',_external=True)
            }
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
        
@app.route('/api/admin/delete-item/<id>',methods=['DELETE'])
def deleteitem(id):
    cursor=None
    try:
        if 'adminid' not in session:
            return  jsonify({
                "status":"failure",
                "message":"pls login first"
            })
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('adminid')
        cursor=mydb.cursor(buffered=True) 
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,id])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({
                "status":"failure",
                "message":"No item found"
            })
        image_name=item_data[7] #old image filename
        remove_path=os.path.join(app.config['UPLOAD_FOLDER'],image_name) 
        #delete from db
        cursor.execute('delete from items where itemid=uuid_to_bin(%s) and added_by=uuid_to_bin(%s)',[id,userid])
        mydb.commit()
        #delete from static folder after db delete
        if os.path.exists(remove_path):
            os.remove(remove_path)
        return jsonify({
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

@app.route('/api/admin/update-item/<itemid>',methods=['PUT'])
def updateitem(itemid):
    new_image_path=None
    old_image_path=None
    cursor=None
    try:
        if 'adminid' not in session:
            return  jsonify({
                "status":"failure",
                "message":"pls login first"
            })
        data=request.form
        if not data:
            return jsonify({
                "status":"failure",
                "message":"No input given "
            })
        updateditem_name=request.form.get('title','').strip()
        updateditem_description=request.form.get('Description').strip()
        updateditem_about=request.form.get('About_item','').strip()
        updateditem_price=request.form.get('price','').strip()
        updateditem_quantity=request.form.get('quantity','').strip()
        updateditem_category=request.form.get('category','').strip()
        if not updateditem_name:
            return jsonify({
                "status":"failure",
                "message":"Item name required "
            }),400
        try:
            updateditem_price=int(updateditem_price) #'670' or 'hi'
            updateditem_quantity=int(updateditem_quantity)
        except ValueError:
            return jsonify({
                "status":"failure",
                "message":"price and quantity must be integers "
            }),400
        mydb.ping(reconnect=True)
        userid=session.get('adminid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select itemfilename from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,itemid])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({
                "status":"failure",
                "message":"Item not found "
            }),400
        old_img=item_data[0]
        filename=old_img
        #receive new image
        updateditem_filedata=request.files.get('file')
        print(updateditem_filedata,'user filedata')
        #if new image uploaded
        if updateditem_filedata:
            uploaded_filename=updateditem_filedata.filename
            if not allowed_extension(uploaded_filename):
                return jsonify({
                    "status":"failure",
                    "message":"Invalid file type"
                }),400
            if not updateditem_filedata.mimetype.startswith('image/'):
                return jsonify({
                    "status":"failure",
                    "message":"Invalid image"
                }),400
            sec_filename=secure_filename(uploaded_filename)
            ext=os.path.splitext(sec_filename)[1] #only extracts extension
            filename=genotp()+ext
            new_image_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
            try:
                updateditem_filedata.save(new_image_path)
            except Exception as e:
                print(e)
                return jsonify({
                    "status":"failed",
                    "message":"Could not save file"
                }) 
            old_image_path=os.path.join(app.config['UPLOAD_FOLDER'],old_img)
        cursor.execute('update items set itemname=%s,itemdescription=%s,itemAbout=%s,itemprice=%s,itemquantity=%s,category=%s,itemfilename=%s  where itemid=uuid_to_bin(%s) and added_by=uuid_to_bin(%s)',[updateditem_name,updateditem_description,updateditem_about,updateditem_price,updateditem_quantity,updateditem_category,filename,itemid,userid])
        mydb.commit()
        cursor.close()
        #delete old image from static folder
        if (old_image_path and updateditem_filedata and os.path.exists(old_image_path)):
            os.remove(old_image_path)
        return jsonify({
            "status":"success",
            "message":"updated successfully",
            "image_url":url_for("static",filename=f'uploads/{filename}')
        }),200
    except Exception as e:
        mydb.rollback()
        print('MYsql Error:',str(e))
        if new_image_path  and os.path.exists(new_image_path):
            os.remove(new_image_path)
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/logout',methods=['POST'])
def adminlogout():
    try:
        if 'adminid' not in session:
            return jsonify({
                "status":"failed",
                "message":"pls login first"
            }),400
        session.clear()
        return jsonify({
            "status":"success",
            "message":"logout successful"
        }),200
    except Exception as e:
        print(e)
        return jsonify({
            "status":"failed",
            "message":f"{str(e)}"
        }),500
    
@app.route('/api/user/register',methods=['POST'])
def usercreate():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({
                "status":"failed",
                "message":"No input given"
            }),400
        username=data.get('username','').strip()
        useremail=data.get('useremail','').strip()
        userpassword=data.get('userpassword','').strip()
        useraddress=data.get('useraddress','').strip()
        usergender=data.get('usergender')
        userphone=data.get('userphone')
        if not username:
            return jsonify({
                "status":"failed",
                "message":"Username required"
            }),400
        email_pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern,useremail):
            return  jsonify({
                "status":"failed",
                "message":"Invalid email"
            }),400
        if len(userpassword)<6:
            return jsonify({
                "status":"failed",
                "message":"password is too short"
            }),400
        mydb.ping(reconnect=True) #if connection lost it reconnects the mysql server
        cursor=mydb.cursor(buffered=True)
        #email recheck
        cursor.execute('select count(*) from userdata where useremail=%s',[useremail])
        email_exists=cursor.fetchone()[0]
        if email_exists>0:
            return jsonify({
                "status":"failed",
                "message":f"Email already existed"
            }),400
        gotp=genotp()
        #generate hashpassword value
        hashed_password=bcrypt.generate_password_hash(userpassword).decode('utf-8')
        userdata={
            "user_username":username,
            "user_useremail":useremail,
            "user_address":useraddress,
            'user_userpassword':hashed_password,
            "usergender":usergender,
            "user_phone":userphone,
            "user_otp":gotp
        }
        subject='User Registration Verification'
        body=f''' Hello {username},
                  Your OTP is {gotp}
                  This otp is valid for 5 mins'''
        send_mail(to=useremail,subject=subject,body=body)
        token=endata(userdata)
        return jsonify({
                "status":"success",
                "message":"OTP sent successfully",
                "token":token
            }),200
    except Exception as e:
        print('Eroor in user register',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/user/logout',methods=['POST'])
def userlogout():
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"pls login first"
            }),400
        session.clear()
        return jsonify({
            "status":"success",
            "message":"logout successful"
        }),200
    except Exception as e:
        print(e)
        return jsonify({
            "status":"failed",
            "message":f"{str(e)}"
        }),500  

@app.route('/api/user/verify-otp',methods=["POST"])
def userotpverify():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({
                "status":"failed",
                "message":f"No input data"
            }),401
        userotp=data.get('otp')
        token=data.get('token')
        if not userotp or not token:
            return jsonify({
                "status":"failed",
                "message":f"otp and token required"
            }),400
        try:
            user_details=dndata(token)
        except Exception:
            return jsonify({
                "status":"failed",
                "message":f"Invalid or expired token"
            }),400
        #otp validation
        print(user_details,userotp)
        if str(userotp)!=str(user_details['user_otp']):
            return jsonify({
                "status":"failed",
                "message":f"Invalid otp"
            }),400
        mydb.ping(reconnect=True) #if connection lost it reconnects the mysql server
        cursor=mydb.cursor(buffered=True)
        #email recheck
        cursor.execute('select count(*) from userdata where useremail=%s',[user_details['user_useremail']])
        email_exists=cursor.fetchone()[0]
        if email_exists>0:
            return jsonify({
                "status":"failed",
                "message":f"Email already existed"
            }),400
        cursor.execute('insert into userdata(userid,username,useremail,password,useraddress,usergender,userphone) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s)',[user_details['user_username'],user_details['user_useremail'],user_details['user_userpassword'],user_details['user_address'],user_details['usergender'],user_details['user_phone']])
        mydb.commit()
        return jsonify({
                "status":"success",
                "message":f"User details Registered successfully"
            }),200
    except Exception as e:
        mydb.rollback()
        print('Mysql error',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()  

@app.route('/api/user/login',methods=['POST'])
def userlogin():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({
                "status":"failed",
                "message":"No Input data given"
            }),401
        login_email=data.get('email','').strip()
        login_password=data.get('password','').strip()
        if not login_email or not login_password:
            return jsonify({
                "status":"failed",
                "message":"Login email and password required"
            }),401
        mydb.ping(reconnect=True) #if connection lost it reconnects the mysql server
        cursor=mydb.cursor(buffered=True)
        #email recheck
        cursor.execute('select bin_to_uuid(userid),username,useremail,password  from userdata where useremail=%s',[login_email])
        user_data=cursor.fetchone()
        if not user_data:
            return jsonify({
                "status":"failed",
                "message":f"Invalid email"
            }),400
        userid=user_data[0]
        username=user_data[1]
        useremail=user_data[2]
        stored_password=user_data[3]
        if not bcrypt.check_password_hash(stored_password,login_password):
            return jsonify({
                "status":"failed",
                "message":f"Invalid password"
            }),400
        session.permenant=True
        session['userid']=userid
        session['useremail']=useremail
        return jsonify({
                "status":"success",
                "message":f"login successful",
                'user':{
                    'userid':userid,
                    'username':username,
                    'useremail':useremail
                }
            }),200
    except Exception as e:
        print('Mysql error',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/products',methods=['GET'])
def products():
    cursor=None
    try:
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items')
        allitems_data=cursor.fetchall()
        if not allitems_data:
            return jsonify({
                "status":"failure",
                "message":"No items found"
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
                'image':url_for('static',filename=f'uploads/{item[7]}',_external=True)
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

@app.route('/api/category/<ctype>',methods=['GET'])
def category(ctype):
    cursor=None
    try:
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where category=%s',[ctype])
        allitems_data=cursor.fetchall()
        if not allitems_data:
            return jsonify({
                "status":"failure",
                "message":"No items found"
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
                'image':url_for('static',filename=f'uploads/{item[7]}',_external=True)
            })
        return jsonify({
          "status":"success",
          "message":"All items data",
          'category':ctype,
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
@app.route('/api/cart/add',methods=['POST'])
def addcart():
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        data=request.get_json()
        if not data:
            return jsonify({
                "status":"failed",
                "message":"No Input data given"
            }),401
        itemid=data.get('itemid')
        try:
            quantity=int(data.get('qunatity',1))
        except ValueError:
            return jsonify({
                "status":"failed","message":"invalid quantity"
            })
        if not itemid:
            return jsonify({
                "status":"failed","message":"itemid required"
            })
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select itemquantity from items where itemid=uuid_to_bin(%s)',[itemid])
        item=cursor.fetchone()
        if not item:
            return jsonify({
                "status":"failed","message":"No item found"
            })
        available_stock=item[0]
        #quantity validation
        if quantity>available_stock:
            return jsonify({
                "status":"failed",
                "message":"Insufficient stock"
            }),401
        #check item already in cart
        cursor.execute('select quantity from cart where userid=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,itemid])
        existing_cart=cursor.fetchone()
        if existing_cart: #update qunatity
            new_quantity=existing_cart[0]+quantity
            if new_quantity> available_stock:
                return jsonify({
                "status":"failed",
                "message":"Insufficient stock"
                }),401
            cursor.execute('update cart set quantity=%s where itemid=uuid_to_bin(%s) and userid=uuid_to_bin(%s)',[new_quantity,itemid,userid])
            message='Cart quantity updated'
        else:
            #insert new item into cart
            cursor.execute('insert into cart(cartid,userid,itemid,quantity) values(uuid_to_bin(uuid()),uuid_to_bin(%s),uuid_to_bin(%s),%s)',[userid,itemid,quantity])
            message='Cart item added successfully'
        mydb.commit()
        return jsonify({
            "status":"success",
            "message":message
        }),200
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

@app.route('/api/cart/view',methods=['GET'])
def viewcart():
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        #mysql connection
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(i.itemid),i.itemname,i.itemprice,i.category,i.itemfilename,c.quantity from items i inner join cart c on c.itemid=i.itemid where c.userid=uuid_to_bin(%s)',[userid])
        cart_items=cursor.fetchall()
        if not cart_items:
            return jsonify({
                "status":"failed",
                "message":"Cart is empty"
            }),401
        subtotal=0
        items_data=[]
        for item in cart_items:
            itemid=item[0]
            item_name=item[1]
            item_price=float(item[2])
            item_quantity=int(item[5])
            item_category=item[3]
            item_imgname=item[4]
            amount=item_price*item_quantity
            subtotal=subtotal+amount
            image_url=url_for('static',filename=f'uploads/{item_imgname}',_external=True)
            items_data.append({'itemid':itemid,'itemname':item_name,'price':item_price,'quantity':item_quantity,'category':item_category,'image':image_url,'total':amount})
        delivery=40
        tax=round(subtotal*0.05,2)
        grand_total=delivery+tax+subtotal
        return jsonify({
            "status":"success",
            "cart_items":items_data,
            "summary":{
                "subtotal":subtotal,
                "delivery":delivery,
                "tax":tax,
                "grand_total":grand_total
            }
        }),200
    except Exception as e:
        print('Mysql Error',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/cart/update',methods=['PUT'])
def updatecart():
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        data=request.get_json()
        print(data)
        if not data:
            return jsonify({
                "status":"failed",
                "message":"No Input data given"
            }),401
        itemid=data.get('itemid')
        try:
            updated_quantity=int(data.get('quantity',0))
        except ValueError:
            return jsonify({
                "status":"failed","message":"invalid quantity"
            })
        if not itemid:
            return jsonify({
                "status":"failed","message":"itemid required"
            })
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select quantity from cart where userid=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,itemid])
        existing_cart=cursor.fetchone()
        if not existing_cart:
            return jsonify({
                "status":"failed",
                "message":"No item in cart"
            }),401
        cursor.execute('select itemquantity from items where itemid=uuid_to_bin(%s)',[itemid])
        item=cursor.fetchone()
        if not item:
            return jsonify({
                "status":"failed","message":"No item found"
            })
        available_stock=item[0]
        if updated_quantity>available_stock:
            return jsonify({
                "status":"failed",
                "message":"Insufficient stock"
            }),400
        cursor.execute('update cart set quantity=%s where userid=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[updated_quantity,userid,itemid])
        mydb.commit()
        return jsonify({
            "status":"success",
            "message":"cart Update succesfully"
        }),200
    except Exception as e:
        mydb.rollback
        print('Mysql Error',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/cart/remove/<itemid>',methods=['DELETE'])
def removecart(itemid):
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select itemquantity from items where itemid=uuid_to_bin(%s)',[itemid])
        item=cursor.fetchone()
        if not item:
            return jsonify({
                "status":"failed","message":"No item found"
            }),401
        cursor.execute('select quantity from cart where userid=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,itemid])
        existing_cart=cursor.fetchone()
        if not existing_cart:
            return jsonify({
                "status":"failed",
                "message":"No item in cart"
            }),401
        cursor.execute('delete from cart where userid=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)',[userid,itemid])
        mydb.commit()
        return jsonify({
            "status":"success",
            "message":"cart item removed succesfully"
        }),200
    except Exception as e:
        mydb.rollback
        print('Mysql Error',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/payment/create-order',methods=['POST'])
def pay_cart():
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        data=request.get_json()
        payment_type=data.get('type','cart')
        #mysql connection 
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        if payment_type=='cart':
            cursor.execute('select bin_to_uuid(i.itemid),i.itemname,i.itemprice,i.category,i.itemfilename,c.quantity from items i inner join cart c on c.itemid=i.itemid where c.userid=uuid_to_bin(%s)',[userid])
            cart_items=cursor.fetchall()
            if not cart_items:
                return jsonify({
                    "status":"failed",
                    "message":"Cart is empty"
                }),401
        else:
            #single buy option
            itemid=data.get('itemid')
            quantity=int(data.get('quantity',1))
            cursor.execute('select bin_to_uuid(itemid),itemname,itemprice,category,itemfilename,itemquantity from items where itemid=uuid_to_bin(%s)',[itemid])
            item=cursor.fetchone()
            if not item:
                return jsonify({"status":"failed","message":"No item found"}),404
            available_stock=item[5]
            if quantity>available_stock:
                return jsonify({"status":"failed","message":"Insufficient stock "}),404
            cart_items=[(item[0],item[1],item[2],item[3],item[4],quantity)]
        if not cart_items:
            return jsonify({"status":"failed","message":"cart is empty"}),404
        subtotal=0
        items_data=[]
        for item in cart_items:
            itemid=item[0]
            item_name=item[1]
            item_price=float(item[2])
            item_quantity=int(item[5])
            item_category=item[3]
            item_imgname=item[4]
            amount=item_price*item_quantity
            subtotal=subtotal+amount
            image_url=url_for('static',filename=f'uploads/{item_imgname}',_external=True)
            items_data.append({'itemid':itemid,'itemname':item_name,'price':item_price,'quantity':item_quantity,'category':item_category,'image':image_url,'amount':amount})
        delivery=40
        tax=round(subtotal*0.05,2)
        grand_total=delivery+tax+subtotal
        razorpay_amount=int(grand_total*100) #convert into paisa
        order=client.order.create({
                    "amount": razorpay_amount,
                    "currency": "INR",
                    "receipt": f"{session.get('userid')}",
                    "payment_capture":1
                    })
        print(order)
        return jsonify({
            "status":"success",
            "order":{
                'order_id':order['id'],
                "amount":order['amount'],
                "currency":order['currency']
            },
            "cart_item":items_data,
            "summary":{
                "subtotal":subtotal,
                "tax":tax,
                "delivery":delivery,
                "grand_total":grand_total
            },
            'razorpay_key':"rzp_test_TEuFBgBKeyncR9"
        })
    except Exception as e:
        print('order creation',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/payment/verify',methods=['POST'])
def verify_payment():
    cursor=None
    try:
        data=request.get_json()
        #get forntend data
        payment_id=data.get('razorpay_payment_id') 
        order_id=data.get('razorpay_order_id')
        signature=data.get('razorpay_signature')
        mode=data.get('mode','cart')
        #verify Signature details
        params_dict={
            "razorpay_order_id":order_id,
            "razorpay_payment_id":payment_id,
            "razorpay_signature":signature
        }
        try:
            client.utility.verify_payment_signature(params_dict)
        except Exception as e:
            print(e)
            return jsonify({
                "status":"failed",
                "message":"could not verify razorpay details"
            }),400
        #login validation
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"pls login first"
            }),401
        #mysql connect
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        if mode=='cart':
            cursor.execute('select bin_to_uuid(i.itemid),i.itemname,i.itemprice,i.category,i.itemfilename,c.quantity from items i inner join cart c on c.itemid=i.itemid where c.userid=uuid_to_bin(%s)',[userid])
            cart_items=cursor.fetchall()
            if not cart_items:
                return jsonify({
                    "status":"failed",
                    "message":"Cart is empty"
                }),401
        else:
            #single buy option
            itemid=data.get('itemid')
            quantity=int(data.get('quantity',1))
            cursor.execute('select bin_to_uuid(itemid),itemname,itemprice,category,itemfilename,itemquantity from items where itemid=uuid_to_bin(%s)',[itemid])
            item=cursor.fetchone()
            if not item:
                return jsonify({"status":"failed","message":"No item found"}),404
            available_stock=item[5]
            if quantity>available_stock:
                return jsonify({"status":"failed","message":"Insufficient stock "}),404
            cart_items=[(item[0],item[1],item[2],item[3],item[4],quantity)]
        if not cart_items:
            return jsonify({"status":"failed","message":"cart is empty"}),404
        subtotal=0
        for item in cart_items:
            itemid=item[0]
            item_name=item[1]
            item_price=float(item[2])
            item_quantity=int(item[5])
            item_category=item[3]
            item_imgname=item[4]
            amount=item_price*item_quantity
            subtotal=subtotal+amount
        delivery=40
        tax=round(subtotal*0.05,2)
        grand_total=delivery+tax+subtotal
        #store order details
        cursor.execute('''insert into orders(razorpay_orderid,razorpay_paymentid,userid,total_amount,delivery,tax,grand_total,status) values(%s,%s,uuid_to_bin(%s),%s,%s,%s,%s,'paid')''',[order_id,payment_id,userid,subtotal,delivery,tax,grand_total])
        order_table_id=cursor.lastrowid
        orderdetails_insert='''insert into order_item_details(orderid,itemid,item_name,item_price,item_quantity,subtotal,item_category,item_filename) values(%s,uuid_to_bin(%s),%s,%s,%s,%s,%s,%s)'''
        ordered_items=[]
        for item in cart_items:
            itemid=item[0]
            item_name=item[1]
            item_price=float(item[2])
            item_quantity=int(item[5])
            item_category=item[3]
            item_imgname=item[4]
            print(amount,'before update')
            amount=item_price*item_quantity
            cursor.execute(orderdetails_insert,[order_table_id,itemid,item_name,item_price,item_quantity,amount,item_category,item_imgname])
            #reduce stock
            cursor.execute('''update items set itemquantity=itemquantity-%s where itemid=uuid_to_bin(%s)''',[item_quantity,itemid])
            ordered_items.append({
                "itemid":itemid,
                "itemname":item_name,
                "price":item_price,
                "quantity":item_quantity,
                'subtotal':amount
            })
        #------------after order successfull clear the cart
        if mode=='cart':
            cursor.execute('delete from cart where userid=uuid_to_bin(%s)',[userid])
        mydb.commit()
        return jsonify({"status":"success",
                        "message":"Payment verified successfully",
                        "payment":{
                            "payment_id":payment_id,
                            "order_id":order_id
                        },
                        "summary":{
                            'subtotal':subtotal,
                            "delivery":delivery,
                            "tax":tax,
                            "grand_total":grand_total
                        },"ordered_items":ordered_items})
    except Exception as e:
        mydb.rollback()
        print('order creation',str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/myorders',methods=['GET'])
def myorders():
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        #mysql connect
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select orderid,razorpay_orderid,razorpay_paymentid,total_amount,delivery,tax,grand_total,status,created_at from orders where userid=uuid_to_bin(%s) order by created_at desc''',[userid])
        orderslist=cursor.fetchall()
        all_orders=[]
        for order in orderslist:
            orderid=order[0]
            #fetch ordered items based on orderid
            cursor.execute('''select bin_to_uuid(itemid),item_name,item_price,item_quantity,subtotal,item_category,item_filename from order_item_details where orderid=%s''',[orderid])
            items=cursor.fetchall()
            order_items=[]
            for item in items:
                image_url=url_for('static',filename=f'uploads/{item[6]}',_external=True)
                order_items.append({
                    'itemid':item[0],
                    'itemname':item[1],
                    'price':float(item[2]),
                    'quantity':item[3],
                    'subtotal':float(item[4]),
                    'category':item[5],
                    'image':image_url
                })
            all_orders.append({
                "orderid":orderid,
                "razorpay_order_id":order[1],
                "razorpay_payment_id":order[2],
                "subtotal":float(order[3]),
                "delivery":float(order[4]),
                "tax":float(order[5]),
                "grand_total":float(order[6]),
                "created_at":order[8],
                "items":order_items
            })
        return jsonify({
            "status":"success",
            "orders":all_orders
        })
    except Exception as e:
        print(str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/orders/<ordid>',methods=['GET'])
def myorder_details(ordid):
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        #mysql connect
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select orderid,razorpay_orderid,razorpay_paymentid,total_amount,delivery,tax,grand_total,status,created_at from orders where userid=uuid_to_bin(%s) and orderid=%s''',[userid,ordid])   
        order_data=cursor.fetchone()
        if not order_data:
            return jsonify({
                "status":"failed",
                "message":"order not found"
            }),401
        cursor.execute('''select orderdetails_id,orderid,bin_to_uuid(itemid),item_name,item_price,item_quantity,subtotal,item_category,item_filename from order_item_details where orderid=%s''',[ordid])
        orders_itemsdata=cursor.fetchall()
        order_json={
            "orderid":ordid,
            "razorpay_order_id":order_data[1],
            "razorpay_payment_id":order_data[2],
            "total_amount":float(order_data[3]),
            "delivery":float(order_data[4]),
            "tax":float(order_data[5]),
            "grand_total":float(order_data[6]),
            "created_at":order_data[8]            
        }
        items_json=[]
        for item in orders_itemsdata:
            image_url=url_for('static',filename=f'uploads/{item[8]}',_external=True)
            items_json.append({
                "order_details_id":item[0],
                "order_id":item[1],
                'itemid':item[2],
                'item_name':item[3],
                'item_price':float(item[4]),
                'item_quantity':item[5],
                'subtotal':float(item[6]),
                'item_category':item[7],
                'item_image':image_url   
            })
        return jsonify({
            "status":"success",
            "order":order_json,
            "items":items_json
        }),200
    except Exception as e:
        print(str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/search',methods=['GET'])
def usersearch():
    cursor=None
    try:
        #get search query from url
        searchdata=request.args.get('q','').strip()
        #empty validation
        if not searchdata:
            return jsonify({
                "status":"failed",
                "message":"search query required"
            }),401
        #regex validation
        pattern=re.compile(r'^[A_Za-z0-9]+$',re.IGNORECASE)
        if not pattern.match(searchdata):
            return jsonify({
                "status":"failed",
                "message":"Invalid search"
            }),401
        mydb.ping(reconnect=True)
        userid=session.get('adminid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),itemname,itemdescription,itemAbout,itemprice,itemquantity,category,itemfilename from items where itemname like %s or itemdescription like %s or category like %s',[searchdata+'%',searchdata+'%',searchdata+'%'])
        allitems_data=cursor.fetchall()
        items=[]
        for item in allitems_data:
            items.append({
                'itemid':item[0],
                'itemname':item[1],
                'item_desc':item[2],
                'item_about':item[3],
                'price':float(item[4]),
                'quantity':item[5],
                'category':item[6],
                'image':url_for('static',filename=f'uploads/{item[7]}',_external=True)
            })
        return jsonify({
          "status":"success",
          "message":"All items data",
          "items":items  
        }),200
    except Exception as e:
        print(str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/invoice/<int:ordid>',methods=['GET'])
def get_invoice(ordid):
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({
                "status":"failed",
                "message":"Pls login first"
            }),401
        #mysql connect
        mydb.ping(reconnect=True)
        userid=session.get('userid')
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select orderid,razorpay_orderid,razorpay_paymentid,total_amount,delivery,tax,grand_total,status,created_at from orders where userid=uuid_to_bin(%s) and orderid=%s''',[userid,ordid])   
        order_data=cursor.fetchone()
        if not order_data:
            return jsonify({
                "status":"failed",
                "message":"order not found"
            }),401
        cursor.execute('''select item_name,item_price,item_quantity,subtotal,item_category,item_filename from order_item_details where orderid=%s''',[ordid])
        orders_items=cursor.fetchall()
        #----------------CREATE PDF BUFFER--------------
        pdf_buffer=BytesIO()
        #--------------------create document---------------
        doc=SimpleDocTemplate(
            pdf_buffer,
            pagesize=A4,
            rightmargin=30,
            leftMargin=30,
            topMargin=30,
            buttomMargin=20
        )
        styles=getSampleStyleSheet()
        elements=[]
        #-----------------------Set Title--------
        title=Paragraph(
            "<b>BUYROUTE Invoice</b>",styles['Title']
        )
        elements.append(title)
        elements.append(Spacer(1,15))
        
        #-----------------------order details-------------
        order_info=f'''
        <b>ORDER ID:</b> {order_data[0]}<br/>
        <b>Razorpay order ID:</b> {order_data[1]}<br/>
        <b>Razorpay Payment ID:</b> {order_data[2]}<br/>
        <b>Order date:</b> {order_data[8]}<br/>'''
        order_para=Paragraph(
            order_info,
            styles['BodyText']
        )
        elements.append(order_para)
        elements.append(Spacer(1,10))
        elements.append(HRFlowable(width="100%"))
        elements.append(Spacer(1,15))
        #-------------------Table Format and data ---------------
        table_data=[['Itemname','Itemcategory','Itemprice','Itemquantity','subtotal']]
        for item in orders_items:
            table_data.append([item[0][0:20],item[4],f"₹{float(item[1])}",str(item[2]),f"₹{float(item[3])}"])
        #---------------create table----------------
        table=Table(table_data,colWidths=[180,100,80,70,80])
        #------------table style
        table.setStyle(
            TableStyle([
                ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0d6efd')),
                ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
                ('FONTSIZE',(0,0),(-1,-1),10),
                ('BOTTOMPADDING',(0,0),(-1,0),10),
                ('GRID',(0,0),(-1,-1),1,colors.black),
                ('BACKGROUND',(0,1),(-1,-1),colors.beige),
                ('ALIGN',(2,1),(-1,-1),'CENTER')                
            ])
        )
        elements.append(table)
        elements.append(Spacer(1,20))
        #---------------------------Summary----------------
        summary=f"""
        <b>ITEM ToTAL:</b> ₹{float(order_data[3])}<br/><br/>
        <b>Delivery:</b> ₹{float(order_data[4])}<br/><br/>
        <b>Tax:</b> ₹{float(order_data[5])}<br/><br/>
        <b>GRAND ToTAL:</b> ₹{float(order_data[6])}<br/><br/>"""
        summary_para=Paragraph(
            summary,
            styles['Heading3']
        )
        elements.append(summary_para)
        elements.append(Spacer(1,25))
        #------------------Footer----------
        footer=Paragraph("Thank you for shopping with BUYROUTE",styles['Italic'])
        elements.append(footer)
        #-----------------Build pdf-------
        doc.build(elements)
        pdf_buffer.seek(0)
        #---------------------------RESPONSE----------------------
        response=make_response(
            pdf_buffer.getvalue()
        )
        response.headers['Content-Type']='application/pdf'
        response.headers['Content-Disposition']=(
            f'attachment; filename=invoice_{ordid}.pdf'
        )
        return response
    except Exception as e:
        print(str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()
    

@app.route('/api/user/forgotpassword',methods=['POST'])
def forgotpassword():
    try:
        data=request.get_json()
        f_email=data.get('email')
        mydb.ping(reconnect=True) #if connection lost it reconnects the mysql server
        cursor=mydb.cursor(buffered=True)
        #email recheck
        cursor.execute('select count(*) from userdata where useremail=%s',[f_email])
        email_exists=cursor.fetchone()[0]
        if email_exists==0:
            return jsonify({
                "status":"failed",
                "message":f"Email Not found"
                }),400
        reset_link=f"{url_for('resetpassword',token=endata(f_email),_external=True)}"
        subject='User forgotpassword Reset link for Ecommy Appy'
        body=f"click the given :\n{reset_link}"
        send_mail(to=f_email,subject=subject,body=body)
        return jsonify({
            "status":"success",
            "message":"Reset link has been sent to given mail"
        })
    except Exception as e:
        print(str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()


@app.route('/resetpassword/<token>',methods=['PUT'])
def resetpassword(token):
    cursor=None
    try:
        data=request.get_json()
        npassword=data.get('password')
        cpassword=data.get('confirm_password')
        if npassword!=cpassword:
            return jsonify({
                    "status":"failed",
                    "message":f"password does not match"
                }),400
        email=dndata(token)
        hashed_pwd=bcrypt.generate_password_hash(npassword)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('update userdata set password=%s where useremail=%s ',[hashed_pwd,email])
        mydb.commit()
        return jsonify({
                    "status":"success",
                    "message":f"password updated successfully"
                }),200
    except Exception as e:
        print(str(e))
        return jsonify({
                "status":"failed",
                "message":f"{str(e)}"
            }),500
    finally:
        if cursor:
            cursor.close()
    


        
if __name__=='__main__':
    app.run()