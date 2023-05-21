from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Cipher import AES
import base64
import hashlib


def winGetName(var0):
    dict = {37:'IBM037',437:'IBM437',500:'IBM500',708:'ISO-8859-6',709:'null',710:'null',720:'IBM437',737:'x-IBM737',775:'IBM775',850:'IBM850',852:'IBM852',855:'IBM855',857:'IBM857',858:'IBM00858',860:'IBM860',861:'IBM861',862:'IBM862',863:'IBM863',864:'IBM864',865:'IBM865',866:'IBM866',869:'IBM869',870:'IBM870',874:'x-windows-874',875:'IBM875',932:'Shift_JIS',936:'x-mswin-936',949:'x-windows-949',950:'Big5',1026:'IBM1026',1047:'IBM1047',1140:'IBM01140',1141:'IBM01141',1142:'IBM01142',1143:'IBM01143',1144:'IBM01144',1145:'IBM01145',1146:'IBM01146',1147:'IBM01147',1148:'IBM01148',1149:'IBM01149',1200:'UTF-16LE',1201:'UTF-16BE',1250:'windows-1250',1251:'windows-1251',1252:'windows-1252',1253:'windows-1253',1254:'windows-1254',1255:'windows-1255',1256:'windows-1256',1257:'windows-1257',1258:'windows-1258',1361:'x-Johab',10000:'x-MacRoman',10001:'null',10002:'null',10003:'null',10004:'x-MacArabic',10005:'x-MacHebrew',10006:'x-MacGreek',10007:'x-MacCyrillic',10008:'null',10010:'x-MacRomania',10017:'x-MacUkraine',10021:'x-MacThai',10029:'x-MacCentralEurope',10079:'x-MacIceland',10081:'x-MacTurkish',10082:'x-MacCroatian',12000:'UTF-32LE',12001:'UTF-32BE',20000:'x-ISO-2022-CN-CNS',20001:'null',20002:'null',20003:'null',20004:'null',20005:'null',20105:'null',20106:'null',20107:'null',20108:'null',20127:'US-ASCII',20261:'null',20269:'null',20273:'IBM273',20277:'IBM277',20278:'IBM278',20280:'IBM280',20284:'IBM284',20285:'IBM285',20290:'IBM290',20297:'IBM297',20420:'IBM420',20423:'null',20424:'IBM424',20833:'null',20838:'IBM-Thai',20866:'KOI8-R',20871:'IBM871',20880:'null',20905:'null',20924:'null',20932:'EUC-JP',20936:'GB2312',20949:'null',21025:'x-IBM1025',21027:'null',21866:'KOI8-U',28591:'ISO-8859-1',28592:'ISO-8859-2',28593:'ISO-8859-3',28594:'ISO-8859-4',28595:'ISO-8859-5',28596:'ISO-8859-6',28597:'ISO-8859-7',28598:'ISO-8859-8',28599:'ISO-8859-9',28603:'ISO-8859-13',28605:'ISO-8859-15',29001:'null',38598:'ISO-8859-8',50220:'ISO-2022-JP',50221:'ISO-2022-JP-2',50222:'ISO-2022-JP',50225:'ISO-2022-KR',50227:'ISO-2022-CN',50229:'ISO-2022-CN',50930:'x-IBM930',50931:'null',50933:'x-IBM933',50935:'x-IBM935',50936:'null',50937:'x-IBM937',50939:'x-IBM939',51932:'EUC-JP',51936:'GB2312',51949:'EUC-KR',51950:'null',52936:'GB2312',54936:'GB18030',57002:'x-ISCII91',57003:'x-ISCII91',57004:'x-ISCII91',57005:'x-ISCII91',57006:'x-ISCII91',57007:'x-ISCII91',57008:'x-ISCII91',57009:'x-ISCII91',57010:'x-ISCII91',57011:'x-ISCII91',65000:'null',65001:'UTF-8'}
    return dict[var0]

def flag(var0,var1):
    return (var0 & var1) == var1



def rsaDecrypt(text):
    cipher = Cipher_pkcs1_v1_5.new(RSA.importKey(private_key))
    retval = cipher.decrypt(base64.b64decode(text), 'ERROR')
    return retval


def metadataDec(metadata):
    dict = {}
    metadata_dec = rsaDecrypt(metadata)
    # print(metadata_dec)
    dict['magic_number'] = int.from_bytes(rsaDecrypt(metadata)[0:4],byteorder='big',signed=False)
    dict['metadata_len'] = int.from_bytes(rsaDecrypt(metadata)[4:8],byteorder='big',signed=False)
    key = metadata_dec[8:24]
    digest = hashlib.sha256(key).digest()
    global aes_key
    aes_key = digest[:16]
    global hmac_key
    hmac_key = digest[16:]
    dict['aes_key'] = aes_key
    dict['hmac_key'] = hmac_key

    dict['charset1'] = winGetName(int.from_bytes(metadata_dec[24:26],byteorder='little',signed=False))
    dict['charset2'] = winGetName(int.from_bytes(metadata_dec[26:28],byteorder='little',signed=False))
    dict['beacon session id'] = int.from_bytes(metadata_dec[28:32],byteorder='big',signed=False)
    dict['pid'] = int.from_bytes(metadata_dec[32:46],byteorder='big',signed=False)
    dict['port'] = int.from_bytes(metadata_dec[36:38],byteorder='big',signed=False)
    var7 = int.from_bytes(metadata_dec[38:39],byteorder='big',signed=False)
    # var7 = 4
    dict['windows nt ver'] = '.'.join(map(lambda x:str(x), list(metadata_dec[39:41])))
    dict['windows build'] = int.from_bytes(metadata_dec[41:43],byteorder='big',signed=False)
    var10 = metadata_dec[43:47]
    dict['ptr_gmh'] = metadata_dec[47:51]
    dict['ptr_gpa'] = metadata_dec[51:55]
    dict['Intranet ip'] = '.'.join(map(lambda x:str(x), list(metadata_dec[55:59][::-1])))

    try:
        other = metadata_dec[59:].decode('utf-8').split("\t")
    except UnicodeDecodeError:
        other = metadata_dec[59:].decode('gbk').split("\t")
    except:
        other = ['err','err','err']
        print('名字相关编码不匹配')
    dict['computer'] = other[0]
    dict['user'] = other[1]+'*' if flag(var7,8) else other[1]
    dict['var7'] = var7
    dict['process'] = other[2]


    dict['system_is64'] = flag(var7,4)
    if flag(var7,1):
        dict['barch'] =""
        dict['pid'] =""
    elif(flag(var7,2)):
        dict['barch'] ="x64"
    else:
        dict['barch'] ="x86"

    print('\n##########metadata_dec###########')
    for k in dict:
        print(k+':',dict[k])




def respDecrypt(resp, aes_key, iv):
    encrypt_data=base64.b64decode(resp)
    aesenc_data=encrypt_data[0:-16]
    dec = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(aesenc_data)
    dict = {}
    dict['timesharp']=int.from_bytes(dec[0:4], byteorder='big', signed=False)
    dict['data_len']=int.from_bytes(dec[4:8], byteorder='big', signed=False)
    data=dec[8:]
    dict['data_command_type']=int.from_bytes(data[0:4], byteorder='big', signed=False)
    dict['data_command_buf_len']=int.from_bytes(data[4:8], byteorder='big', signed=False)
    data_command_buf=data[8:8+dict['data_command_buf_len']]
    # print(dec)
    dict['data_command_buf_env_len']=int.from_bytes(data_command_buf[:4], byteorder='big', signed=False)
    dict['data_command_buf_env'] = data_command_buf[4:4+dict['data_command_buf_env_len']].decode('utf-8')
    dict['data_command_buf_cmd_len']=int.from_bytes(data_command_buf[4+dict['data_command_buf_env_len']:8+dict['data_command_buf_env_len']], byteorder='big', signed=False)
    dict['data_command_buf_cmd']=data_command_buf[8+dict['data_command_buf_env_len']:8+dict['data_command_buf_env_len']+dict['data_command_buf_cmd_len']].decode('utf-8')

    print('\n##########resp_dec###########')
    for k in dict:
        print(k+':',dict[k])


def taskResultDecrypt(taskRst, aes_key, iv):
    encrypt_data=base64.b64decode(taskRst)[4:]
    aesenc_data=encrypt_data[0:-16]
    dec=AES.new(aes_key, AES.MODE_CBC, iv).decrypt(aesenc_data)
    dict = {}
    dict['cs防重放int']=int.from_bytes(dec[0:4], byteorder='big', signed=False)
    dict['data_len']=int.from_bytes(dec[4:8], byteorder='big', signed=False)
    data=dec[8:8+dict['data_len']]
    dict['task_type']=int.from_bytes(data[0:4], byteorder='big', signed=False)
    dict['task_result']=data[4:].decode('utf-8')

    print('\n##########task_result_dec###########')
    for k in dict:
        print(k+':',dict[k])


private_key = '''-----BEGIN RSA PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAI2FQaDW/vuqrr1nV5sSone+vTNq
kUEkXh5ARHlbl07v3hSLAMybscK2q0cJNwSkEU71AkZebQFnRAtrEdliireimdIZb8JsJ3RzL5NI
G2LeFUladQObTSbgOGQX/pFmn3BaRIhSW8KcOFWgZav7khyrirtwEhgz4EfBtqRYvu7tAgMBAAEC
gYBgDwdQ6R4CLQSWw0KPm8JzjSBXegpGMS1BU1YnGahGiEIxp3hPaY7rH5p6iSKzH7ov4dY9dXJ/
9VwWdAKVj3Gf2JqG2Is/W5ZNypwD6QZurZJjWEZoFzSVReu4xDuxS4qXZLDtdYh8qhodP1DVIRP+
GnUxiAieBlKbiCwr2rl18QJBAM542SWwq+LHDYGtiXqVhklg21zWTCUTcHAqxtKX+6WHDNwkLv9Q
nTXjD6H/BJPRLjM6EMBS+lEU6QLVKhilLZsCQQCvd9QIwE8CnFwqPZwb3iqMRgXVyUEtpBsoHInd
rBJ0lD1gYiBWQUxhQLiB8g66mCsubTAfoc0SDMIDRgDrv+IXAkAAwy16GCbqVXXVTsC9NSQjzTnC
JABv+pxlraLCUFFbkR4ZCgEqbC/IbSg3nutzaEhVZBd/vk6yUfNyUTswkBuVAkAfaUAX4PVD7mHB
Xg4YHwlW2yIoR0LXvMzvvUwg1rDnFbJ3EpnfVwkpT8C34nEojh0MzpcS0pA3bvk8RMfdbBg5AkEA
vfmNN9TgG/BVxDybPDM6Brbhd3b2ADIVaqOoR4mUM8E+k0rjQH6spSeMPTCJDuUUVUVCHXaaxaz4
MYQZeCqX3g==
-----END RSA PRIVATE KEY-----
'''


metadata = 'WtgpCtxgnQgXZ8OBnxNLJdXDt7+ZerMjfl1H9Kch1f4WHuKoSyh8A1hYsxhIE2y+YgTa3ExKKp0/MqqjD8x3B6gR4tnHQzWJtPNERk+UXuLVlxKz/WiNfddOP84WV9aKQSXMBISIMvciH15GLDRrTW/MBA2pako6gidWUznbxqI='
teamserver_rev_data = '3r0elzAwFjWj52IRqdspkpLO9e0yhf/KjQ5yUqNPnPiaUgRMWGUNwAjw+i41hfAokm/XoYGeWfu7U+O2y7/TQA=='
task_result ='AAAAMFLm2K54LIsHw5vR9eYc33asrFgFDocs05/VN7dxt736CMeKCKZ0juZeu6VVJzXZ/g=='

metadataDec(metadata)
respDecrypt(teamserver_rev_data, aes_key, bytes("abcdefghijklmnop",'utf-8'))
taskResultDecrypt(task_result, aes_key, bytes("abcdefghijklmnop",'utf-8'))