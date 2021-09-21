#/usr/bin/python
#coding=utf-8
import sys,os,hashlib,time,base64
def rc4(string, op = 'encode', public_key = 'ddd', expirytime = 0):
    ckey_lenth = 4  #定义IV的长度
    public_key = public_key and public_key or ''
    key = hashlib.md5(public_key).hexdigest() #将密码public_key进行md5，返回32字节的key
    keya = hashlib.md5(key[0:16]).hexdigest() #将Key的前16字节md5，返回32字节的keya
    keyb = hashlib.md5(key[16:32]).hexdigest() #将key的后16字节md5，返回32字节的keyb

    #当加密时，keyc取time.time()的md5前4字节，用作IV
    #当解密时，从密文的前4字节取出IV
    keyc = ckey_lenth and (op == 'decode' and string[0:ckey_lenth] or hashlib.md5(str(time.time())).hexdigest()[32 - ckey_lenth:32]) or ''

    #真正的密钥cryptkey是由keya拼接keya以及keyc的md5得来的共64字节的字符串
    cryptkey = keya + hashlib.md5(keya + keyc).hexdigest()
    key_lenth = len(cryptkey)   #64

    #当加密时，待加密的明文是由10字节的0以及待加密的明文string与keyb的md5值的前前16字节以及明文string拼接而成
    #当解密时，密文即为传入的string的前4字节以后的内容并解码
    string = op == 'decode' and base64.b64decode(string[4:]) or '0000000000' + hashlib.md5(string + keyb).hexdigest()[0:16] + string
    string_lenth = len(string)

    result = ''
    box = list(range(256))
    randkey = []

    for i in xrange(255):
        #随机填充cryptokey中字符的ascii码值,会出现4轮的重复，randkey[0]~randkey[63],randkey[64]~randkey[127],……
        randkey.append(ord(cryptkey[i % key_lenth]))

    #随机打乱box列表
    #cryptkey的真正目的是生成伪随机的box
    for i in xrange(255):
        j = 0
        j = (j + box[i] + randkey[i]) % 256
        tmp = box[i]
        box[i] = box[j]
        box[j] = tmp

    for i in xrange(string_lenth):
        a = j = 0
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        tmp = box[a]
        box[a] = box[j]
        box[j] = tmp
        #以上再次进行了打乱

        #真正的明文string逐字节与box中的随机值异或生成加密的result
        #不管怎么随机打乱，由于cryptkey以及string_length总是一样的，因此box最终也一样
        result += chr(ord(string[i]) ^ (box[(box[a] + box[j]) % 256]))
        #解密时，密文在与box异或则返回明文

    if op == 'decode':
        #result[10:26] == hashlib.md5(result[26:] + keyb).hexdigest()[0:16]，用来验证string的完整性
        if (result[0:10] == '0000000000' or int(result[0:10]) - int(time.time()) > 0) and result[10:26] == hashlib.md5(result[26:] + keyb).hexdigest()[0:16]:
            return result[26:]  #前十字节是0，再16字节是明文string与keyb的md5前16字节，最后的则是string
        else:
            return None
    else:
        #加密，返回IV+result的base64编码
        return keyc + base64.b64encode(result)

if __name__ == '__main__':
    #print rc4('我们','encode','98765')
    print rc4('fd09GMhYylNXC5t550VwC5oX9WS4zrB0bI9rs6kvTAMoiGI=','decode','98765')
