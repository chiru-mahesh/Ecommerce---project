import random
def genotp():
    otp = ''
    c_l = [chr(i) for i in range(ord('A'), ord('Z')+1)]
    s_l = [chr(j) for j in range(ord('a'), ord('z')+1)]
    for z in range(2):
        otp = otp + random.choice(c_l) + str(random.randint(0, 9)) + random.choice(s_l)
    return otp