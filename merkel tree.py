import hashlib
import random
def hash_1(h,c):
    sha = hashlib.sha256()
    sha.update((h+c).encode('utf8'))
    return sha.hexdigest()   
def hash(ha,hb,c):
    sha = hashlib.sha256()
    sha.update((ha+hb+c).encode('utf8'))
    return sha.hexdigest()
def merkeltree(data_leaf):
    tree_note=[]
    tree_note.append(data_leaf)
    deep=0
    while(len(data_leaf)!=1):
        data_temp = []
        if len(data_leaf) % 2 == 0:
            for i in range(0, len(data_leaf),2):
                data_temp.append(hash(data_leaf[i],data_leaf[i+1],'0x01'))
        else:
            for i in range(0,len(data_leaf)-1,2):
                data_temp.append(hash(data_leaf[i],data_leaf[i+1],'0x01'))
            data_temp.append(data_leaf[len(data_leaf)-1])
        deep =deep+1
        data_leaf=data_temp
        tree_note.append(data_temp)
    return tree_note,deep #return the tree and its deep

def proof_merkel(idex,tree):
    dep=0
    proof=[]       
    while(len(tree[dep])!=1):
        if(len(tree[dep])%2==0):
            if idex%2==0:
                leaf=(hash(tree[dep][idex],tree[dep][idex+1],'0x01'))
                proof.append(tree[dep][idex+1])
            else:
                leaf=(hash(tree[dep][idex-1],tree[dep][idex],'0x01'))
                proof.append(tree[dep][idex-1])
        else:
            if idex==(len(tree[dep])-1):
                proof.append('none')
                idex=idex//2
                continue
            if idex%2==0:
                leaf=(hash(tree[dep][idex],tree[dep][idex+1],'0x01'))
                proof.append(tree[dep][idex+1])
            else:
                leaf=(hash(tree[dep][idex],tree[dep][idex-1],'0x01'))
                proof.append(tree[dep][idex-1])
        idex=idex//2
        dep=dep+1
    return leaf,proof
if __name__ == '__main__':
    leaf=[hash_1(str(i),'0x00') for i in range(0,100000)]
    t,d=merkeltree(leaf)
    #print(t)
    print(t[d])#root note value
    idex=random.randint(0,99999)
    result,proof=proof_merkel(idex,t)#proof value
    print(proof)
    if(t[d][0]==result):
        print('the leaf is right')
    

    
