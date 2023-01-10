import base64
import os
import string
import random
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import *
# import dissector


last_file = "NoName"


def name_generator(size=9, chars=string.ascii_uppercase + string.digits):
    """
    this method is for generating a randndom name for the downloaded files
    @param size: number of random characters
    @param chars: type of the random characters
    """
    return ''.join(random.choice(chars) for x in range(size))


def clean_file_name(name, path):
    """
    this method is for cleaning the carved file name if it has some special chars
    which is not allowed in most of the operating systems or if the specified folder
    in path variable has another file has the same name.
    @param name: the carved file name
    @param path: the directory path
    """
    ls = list(name)
    result = ""
    length = len(ls)
    files = os.listdir(path)
    if len(name) > 25 or name in files or name == "NoName":
        return name_generator()
    i = 0
    while i < length:
        if not ls[i].isdigit() and not ls[i].isalpha and not ls[i] == ".":
            del(ls[i])
        else:
            result = result + ls[i]
        i = i + 1
    if len(result) > 0:
        return result
    else:
        return name_generator()


def add_file(name):
    """
    this method is for storing the carved file name.
    @param name: the carved file name
    """
    global last_file
    ls = []
    if "/" in name:
        ls = name.split("/")
        if len(ls) > 0:
            last_file = ls[len(ls) - 1]


def get_file():
    """
    this method is for retrieving the stored file name
    """
    return last_file

# list for maintaining  the ftp data sessions
ftpdatasessions = []


def is_created_session(Src, Dst, SPort):
    """
    this method returns true if the ftp data session is exist
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    """
    i = 0
    while i < len(ftpdatasessions):
        if  str(Src) and str(Dst) and str(SPort) in ftpdatasessions[i]:
            return True
        i = i + 1
    return False


def create_session(Src, Dst, SPort):
    """
    this method for creating the ftp data sessions
    @param Src: source ip address
    @param Dst: destination ip address
    @param SPort: source port number
    """
    if not is_created_session(Src, Dst, SPort):
        ftpdatasessions.append([Src, Dst, SPort])
        return True
    return False


def bind(Port):
    """
    ftp data sessions which get establish after do an agreement
    on a specific port number at the server, this port number need
    to be bounded by using bind_layers() method
    @param Port: source port number at the server side
    """
    bind_layers(TCP, FTPData, sport=int(Port))

'''
# 原来的FTPData字段解析
class FTPDataField(XByteField):
    """
    this is a field class for handling the ftp data
    @attention: this class inherets XByteField
    """
    holds_packets = 1
    name = "FtpDataField"
    myresult = ""

    def __init__(self, name, default):
        """
        FTPDataField constructor, for initializing instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        """
        self.name = name
        self.fmt = "!B"
        Field.__init__(self, name, default, "!B")

    def getfield(self, pkt, s):
        cstream = -1
        if pkt.underlayer.name == "TCP":
            cstream = dissector.check_stream(\
            pkt.underlayer.underlayer.fields["src"],\
             pkt.underlayer.underlayer.fields["dst"],\
              pkt.underlayer.fields["sport"],\
               pkt.underlayer.fields["dport"],\
                pkt.underlayer.fields["seq"], s)
        if not cstream == -1:
            s = cstream
        if pkt.underlayer.name == "TCP" and cstream == -1:
            return "", ""
        name = get_file()
        if not dissector.Dissector.default_download_folder_changed:
            cwd = os.getcwd() + "/downloaded/"
            try:
                os.mkdir("downloaded")
            except:
                None
            f = open(cwd + clean_file_name(name, cwd), "wb")
        else:
            f = open(dissector.Dissector.path +\
             clean_file_name(name, dissector.Dissector.path), "wb")
        f.write(s)
        f.close()
        self.myresult = ""
        firstb = struct.unpack(self.fmt, s[0])[0]
        self.myresult = ""
        for c in s:
            ustruct = struct.unpack(self.fmt, c)
            byte = base64.standard_b64encode(str(ustruct[0]))
            self.myresult = self.myresult + byte
        if not is_created_session(pkt.underlayer.underlayer.fields["src"],
                                pkt.underlayer.underlayer.fields["dst"],
                                pkt.underlayer.fields["sport"]):
            return self.myresult, ""
        return "", self.myresult
'''



class FTPResArgField(StrField):
    """
    class field to handle the ftp responses' arguments
    @attention: it inherets StrField which is imported from Scapy
    """
    holds_packets = 1
    name = "FTPResArgField"

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        value = ""
        if "Entering Passive Mode (" in s: # 被动模式参数格式：Entering Passive Mode (h1,h2,h3,h4,p1,p2)
            value = []
            res = s.split("Entering Passive Mode (")
            res.remove(res[0])
            res = res[0].split(")")
            del(res[len(res)-1])
            res = res[0].split(",")
            IP = res[0] + "." + res[1] + "." + res[2] + "." + res[3]
            Port = str(int(res[4]) * 256 + int(res[5]))
            str01 = "Passive IP Address: " + IP
            str02 = "Passive Port Number: " + Port
            value.append(str01)
            value.append(str02)
            # if(create_session(IP, pkt.underlayer.underlayer.fields["dst"],
            #                   Port)):
            #     bind(Port)
            return "", value
        else:
            value = s
            return "", value

    def __init__(self, name, default, fmt, remain=0):
        """
        FTPResArgField constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class FTPResField(StrField):
    """
    class field to handle the ftp responses
    @attention: it inherets StrField which is imported from Scapy
    """
    holds_packets = 1
    name = "FTPReField"

    def get_code_msg(self, cn):
        """
        method which returns message for a ftp code number
        @param cn: code number
        """
        codes = {
    "110": "Restart marker reply",
    "120": "Service ready in nnn minutes",
    "125": "Data connection already open; transfer starting",
    "150": "File status okay; about to open data connection",
    "200": "Command okay",
    "202": "Command not implemented, superfluous at this site",
    "211": "System status, or system help reply",
    "212": "Directory status",
    "213": "File status",
    "214": "Help message",
    "215": "NAME system type",
    "220": "Service ready for new user",
    "221": "Service closing control connection",
    "225": "Data connection open; no transfer in progress",
    "226": "Closing data connection",
    "227": "Entering Passive Mode",
    "229": "Entering Extended Passive Mode",
    "230": "User logged in, proceed",
    "232": "User logged in, authorized by security data exchange",
    "234": "Security data exchange complete",
    "235": "Security data exchange completed successfully",
    "250": "Requested file action okay, completed",
    "257": "PATHNAME created",
    "331": "User name okay, need password",
    "332": "Need account for login",
    "334": "Requested security mechanism is ok",
    "335": "Security data is acceptable, more is required",
    "336": "Username okay, need password. Challenge is ...",
    "350": "Requested file action pending further information",
    "421": "Service not available, closing control connection",
    "425": "Can't open data connection",
    "426": "Connection closed; transfer aborted",
    "431": "Need some unavailable resource to process security",
    "450": "Requested file action not taken",
    "451": "Requested action aborted: local error in processing",
    "452": "Requested action not taken. Insufficient storage space in system",
    "500": "Syntax error, command unrecognized",
    "501": "Syntax error in parameters or arguments",
    "502": "Command not implemented",
    "503": "Bad sequence of commands",
    "504": "Command not implemented for that parameter",
    "522": "Network protocol not supported",
    "530": "Not logged in",
    "532": "Need account for storing files",
    "533": "Command protection level denied for policy reasons",
    "534": "Request denied for policy reasons",
    "535": "Failed security check (hash, sequence, etc)",
    "536": "Requested PROT level not supported by mechanism",
    "537": "Command protection level not supported by security mechanism",
    "550": "Requested action not taken: File unavailable",
    "551": "Requested action aborted: page type unknown",
    "552": "Requested file action aborted: Exceeded storage allocation",
    "553": "Requested action not taken: File name not allowed",
    "631": "Integrity protected reply",
    "632": "Confidentiality and integrity protected reply",
    "633": "Confidentiality protected reply"
 }
        if cn in codes:
            return codes[cn]
        return ""

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        remain = ""
        value = ""
        ls = s.split()
        length_ls = len(ls)
        # python3区分str与bytes，这里将bytes转换成str, 注意到command中存在后缀‘-’，理应除去
        # ls01 = [str(ls[i], encoding="utf-8") for i in range(length)]
        ls01 = []
        for i in range(length_ls):
            str01 = str(ls[i], encoding="utf-8")
            if i == 0 and len(str01) > 3:
                str_list = str01.split('-')
                for j in range(len(str_list)):
                    if str_list[j] == '':
                        continue
                    else:
                        ls01.append(str_list[j])
            else:
                ls01.append(str01)
        length = len(ls01)
        if length > 1:
            # value = self.get_code_msg(ls[0]) + " (" + ls[0] + ")"
            value = self.get_code_msg(ls01[0]) + " (" + ls01[0] + ")"
            if length == 2:
                # remain = ls[1]
                remain = ls01[1]
                return remain, value
            else:
                i = 1
                remain = ""
                while i < length:
                    if i != 1:
                        # remain = remain + " " + ls[i]
                        remain = remain + " " + ls01[i]
                    elif i == 1:
                        # remain = remain + ls[i]
                        remain = remain + ls01[i]
                    i = i + 1
                return remain, value
        else:
            # return "", self.get_code_msg(ls[0]) + " (" + ls[0] + ")"
            return "", self.get_code_msg(ls01[0]) + " (" + ls01[0] + ")"

    def __init__(self, name, default, fmt, remain=0):
        """
        class constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class FTPReqField(StrField):
    holds_packets = 1
    name = "FTPReqField"

    def getfield(self, pkt, s):
        """
        this method will get the packet, takes what does need to be
        taken and let the remaining go, so it returns two values.
        first value which belongs to this field and the second is
        the remaining which does need to be dissected with
        other "field classes".
        @param pkt: holds the whole packet
        @param s: holds only the remaining data which is not dissected yet.
        """
        remain = ""
        value = ""
        ls = s.split()
        length_ls = len(ls)
        # python3区分str与bytes，这里将bytes转换成str
        ls01 = [str(ls[i], encoding="utf-8") for i in range(length_ls)]
        length = len(ls01)
        # if ls[0].lower() == "retr":
        if ls01[0].lower() == "retr":
            c = 1
            file = ""
            # while c < len(ls):
            while c < len(ls01):
                # file = file + ls[c]
                file = file + ls01[c]
                c = c + 1
            if len(file) > 0:
                add_file(file)
        length = len(ls01)
        if length > 1:
            # value = ls[0]
            value = ls01[0]
            if length == 2:
                # remain = ls[1]
                remain = ls01[1]
                return remain, value
            else:
                i = 1
                remain = ""
                while i < length:
                    # remain = remain + ls[i] + " "
                    remain = remain + ls01[i] + " "
                    i = i + 1
                return remain, value
        else:
            return "", ls01[0]

    def __init__(self, name, default, fmt, remain=0):
        """
        class constructor for initializing the instance variables
        @param name: name of the field
        @param default: Scapy has many formats to represent the data
        internal, human and machine. anyways you may sit this param to None.
        @param fmt: specifying the format, this has been set to "H"
        @param remain: this parameter specifies the size of the remaining
        data so make it 0 to handle all of the data.
        """
        self.name = name
        StrField.__init__(self, name, default, fmt, remain)


class FTPData(Packet):
    """
    class for dissecting the ftp data
    @attention: it inherets Packet class from Scapy library
    """
    name = "ftp"
    # fields_desc = [FTPDataField("data", "")]
    fields_desc = [StrField("data", "")]


class FTPResponse(Packet):
    """
    class for dissecting the ftp responses
    @attention: it inherets Packet class from Scapy library
    """
    name = "ftp"
    fields_desc = [FTPResField("code", "", "H"),
                    FTPResArgField("argument", "", "H")]


class FTPRequest(Packet):
    """
    class for dissecting the ftp requests
    @attention: it inherets Packet class from Scapy library
    """
    name = "ftp"
    fields_desc = [FTPReqField("command", "", "H"),
                    StrField("argument", "", "H")]

def FTP(hex_data):
    """
    根据请求命令和响应命令来进行报文类型判断，然后使用相应的解析方法对字段进行解析
    """
    request_list = ["ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CCC", "CDUP", "CONF", "CSID", "CWD", "CLNT", "DELE", "DSIZ", "ENC", "EPRT", 
                    "EPSV", "FEAT", "HELP", "HOST", "LANG", "LIST", "LPRT", "LPSV", "MDTM", "MFCT", "MFF", "MFMT", "MIC", "MKD", "MLSD", "MLST", 
                    "MODE", "NLST", "NOOP", "OPTS", "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT", "REIN", "REST", "RETR", "RMD", "RMDA",
                    "RNFR", "RNTO", "SITE", "SIZE", "SMNT", "SPSV", "STAT", "STOR", "STOU", "STRU", "SYST", "THMB", "TYPE", "USER", "XCUP", "XMKD",
                    "XPWD", "XRCP", "XRMD", "XRSQ", "XSEM", "XSEN"]
    respone_list = ["110", "120", "125", "150", "200", "202", "211", "212", "213", "214", "215", "220", "221", "225", "226", "227", "229", "230", 
                    "232", "234", "235", "250", "257", "331", "332", "334", "335", "336", "350", "421", "425", "426", "431", "450", "451", "452", 
                    "500", "501", "502", "503", "504", "522", "530", "532", "533", "534", "535", "536", "537", "550", "551", "552", "553", "631",
                    "632", "633"]
    
    str_data = str(hex_data, encoding="utf-8")
    
    if str_data[:3] in respone_list:
        # 解析的报文属于响应报文
        ftp_result = FTPResponse(hex_data)
    elif str_data[:3].upper() in request_list or str_data[:4].upper() in request_list:
        # 解析的报文属于请求报文
        ftp_result = FTPRequest(hex_data)
    else:
        # 解析的报文属于数据报文
        ftp_result = FTPData(hex_data)
    return ftp_result

    


bind_layers(TCP, FTPResponse, sport=21)
bind_layers(TCP, FTPRequest, dport=21)
bind_layers(TCP, FTPData, dport=20)
bind_layers(TCP, FTPData, dport=20)
