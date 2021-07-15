import math
import random
#scep256k1
#a=0
#b=7
#p=int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
#n=int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
#G=[int(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798),int(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)]
a=2
b=2
p=17
m='wangyibiao'
G=[5,1]
n=19
print('椭圆曲线的参数：a={},b={},p={},明文消息m={},基点G={},阶n={}'.format(a,b,p,m,G,n))

global lk     #用来泄露的k

def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b
def findmod(a, m): #扩展欧几里得
    if gcd(a, m) != 1 and gcd(a,m)!=-1:
        return None 
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 
        v1 , v2, v3, u1 , u2, u3 = (u1-q*v1), (u2-q*v2), (u3-q*v3), v1 , v2, v3
    if u1>0:
        
        return u1 % m
    else:
        return (u1+m)%m
def addition(m,n):#点的加法
    if(m==0):
        return n
    if(n==0):
        return m
    t=[]
    if(m!=n):
        if(gcd(m[0]-n[0],p)!=1 and gcd(m[0]-n[0],p)!=-1):
            return 0
        else:
            k=((m[1]-n[1])*findmod(m[0]-n[0],p))%p
    else:
        k=((3*(m[0]**2)+a)*findmod(2*m[1],p))%p
    t.append((k**2-m[0]-n[0])%p)
    t.append((k*(m[0]-t[0])-m[1])%p)
    return t

def point_addition(n,l):#点的数乘
    if n==0:
        return 0
    if n==1:
        return l
    t=l
    while(n>=2):
        
        t=addition(t,l)
        n=n-1
    return t

#椭圆曲线参数（a,b,p,G,n,h）
def sign(m,n,G,d):
    global lk
    r=0
    s=0
    e=hash(m)
    while(s==0):
        while(r==0):
            k=random.randrange(1,n-1)
            lk=k
            R=point_addition(k,G)
            r=R[0]%n
        s=(findmod(k,n)*(e+d*r))%n
    return r,s
def sign_error(m,n,G,d):#使用同一个k的签名算法
    global lk
    e=hash(m)
    k=lk

    R=point_addition(k,G)
    r=R[0]%n
    s=(findmod(k,n)*(e+d*r))%n
    return r,s
def verify(m,n,G,r,s,P):#验证算法
    e=hash(m)
    w=findmod(s,n)
    v1=(e*w)%n
    v2=(r*w)%n
    w=addition(point_addition(v1,G),point_addition(v2,P))
    if(w==0):
        print('wrong sign')
    else:
        if(w[0]%n==r):
            print('right sign')
        else:
            print('wrong sign')
def verify_ncheck(e,n,G,r,s,P):#验证算法
    w=findmod(s,n)
    v1=(e*w)%n
    v2=(r*w)%n
    w=addition(point_addition(v1,G),point_addition(v2,P))
    if(w==0):
        print('wrong sign')
    else:
        if(w[0]%n==r):
            print('right sign')
        else:
            print('wrong sign')

d=5 #私钥
P=point_addition(d,G) #公钥
print('选择的私钥d={}，计算得到的公钥P={}'.format(d,P))

r,s=sign(m,n,G,d)
#verify(m,n,G,r,s,P)


def leak_k(k,m,r,s):#泄露k，导致泄露d
    return (findmod(r,n)*(k*s-hash(m)))%n


def reuse_k(m1,m2):#签名不同消息使用同一个k，导致泄露d
    r1,s1=sign(m1,n,G,d)
    r2,s2=sign_error(m2,n,G,d)
    e1=hash(m1)
    e2=hash(m2)#----
    return ((s1*e2-s2*e1)*findmod((s2*r1-s1*r1),n))%n



#A和B使用同一个k
def A_duser_k(r,s1,s2,m1,m2,d1):#A猜测B的私钥
    e1=hash(m1)
    e2=hash(m2)
    d2=((s2*e1-s1*e2+s2*r*5)*findmod(s1*r,n))%n
    return d2
def B_duser_k(r,s1,s2,m1,m2,d2):#B猜测A的私钥
    e1=hash(m1)
    e2=hash(m2)
    d1=((s1*e2-s2*e1+s1*r*7)*findmod(s2*r,n))%n
    return d1    

def rust(m,n,G,d,P):
    print('使用s和-s分别进行验证：')
    r,s=sign(m,n,G,d)
    verify(m,n,G,r,s,P)
    verify(m,n,G,r,(-1)*s,P)
    

def forge(r,s,n,G,P):
    print('我们进行伪造消息（验证方不检查m）：')
    u=random.randrange(1,n-1)
    v=random.randrange(1,n-1)
    r1=addition(point_addition(u,G),point_addition(v,P))[0]
    e1=(r1*u*findmod(v,n))%n
    s1=(r1*findmod(v,n))%n
    print('发给验证方的消息r={},s={},消息哈希值={}'.format(r1,s1,e1))
    verify_ncheck(e1,n,G,r1,s1,P)

def schnorr(m,n,G,d):
    k=random.randrange(1,n-1)
    R=point_addition(k,G)
    e=hash(str(R[0])+m)
    s=(k+e*d)%n
    return R,s

def schnorr_error(m,n,G,d):
    k=lk
    R=point_addition(k,G)
    e=hash(str(R[0])+m)
    s=(k+e*d)%n
    return R,s


def verify_schnorr(R,s,m,P,G):
    e=hash(str(R[0])+m)
    if(point_addition(s,G)==addition(R,point_addition(e%n,P))):
        print('right sign')
    else:
        print('wrong sign')
    
def s_and_e(r1,s1,R,s2,m,n):
    e1=hash(m)
    e2=hash(str(R[0])+m)
    d=((s1*s2-e1)*findmod((s1*e2+r1),n))%n
    return d

ld=leak_k(lk,m,r,s)
print('使用相同的k={}，计算出来的私钥d={}'.format(lk,ld))


m1='yibiao'
m2='erbiao'
reuse_k(m1,m2)
print('签名两条不一样的消息m1={}，m2={}，使用同样的k={}，计算的私钥为d={}'.format(m1,m2,lk,d))


d1=5
d2=7
r,s1=sign(m1,n,G,d1)
r,s2=sign_error(m2,n,G,d2)
d2_cp=A_duser_k(r,s1,s2,m1,m2,d1)
d1_cp=B_duser_k(r,s1,s2,m1,m2,d2)
print('Alice和Bob使用相同的k={}\nAlice使用私钥d1={},计算得到BOb的私钥d2={}\nBob使用私钥d2={},计算得到Alice的私钥d1={}'.format(lk,d1,d2_cp,d2,d1_cp))

rust(m,n,G,d,P)

r,s=sign(m,n,G,d)
forge(r,s,n,G,P)


#R,s=schnorr(m,n,G,d)
#verify_schnorr(R,s,m,P,G)

r1,s1=sign(m,n,G,d)    
R,s2=schnorr_error(m,n,G,d)    
dd=s_and_e(r1,s1,R,s2,m,n)
print('schnorr签名与ECDSA使用同一个k={}，同一个私钥d={}，计算得到的私钥dd={}'.format(lk,d,dd))
