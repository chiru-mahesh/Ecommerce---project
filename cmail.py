import smtplib
from email.message import EmailMessage
def send_mail(to, subject, body):
    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login('mahesh520004@gmail.com', 'igyg bipy pcqa tigy')
    msg=EmailMessage()
    msg['FROM']='mahesh520004@gmail.com'
    msg['SUBJECT']=subject
    msg['TO']=to
    msg.set_content(body)
    server.send_message(msg)
    print('mail sent')
    server.close
