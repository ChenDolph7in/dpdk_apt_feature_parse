# encoding=UTF-8
import OpenSSL
import time, os, sys, json
import numpy as np
import pandas as pd
import difflib
import datetime
import math

from dateutil import parser

LOCAL_IP_ADDRESS = '10.0.2.15'  # local host ip address

def call_test(lines):
    
    line = lines[0]
    print(line)
    key_str = str(line[0],encoding="utf-8")
    print(key_str)
    timestamp = line[1]
    print(timestamp)
    proto = line[2]
    print(proto)
    ip_src = str(line[3],encoding='utf-8')
    print(ip_src)
    ip_dst = str(line[4],encoding='utf-8')
    print(ip_dst)
    ip_len = line[9]
    print(ip_len)

    # new
    ip_hdr_len = line[10]
    print(ip_hdr_len)
    tcp_flags = line[11]
    print(tcp_flags)
    tcp_hdr_len = line[12]
    print(tcp_hdr_len)
    tls_version = line[13]
    print(tls_version)
    more_seg_flag = line[14]
    print(more_seg_flag)
    tcp_ack = line[15]
    print(tcp_ack)
    tls_content_type = line[16]
    print(tls_content_type)
    # print("certs and sni:")
    certs = str(line[17],encoding='utf-8')
    print(certs)
    sni = str(line[18],encoding='utf-8')
    print(sni)
    return 0

def parse_x509(x509_data):
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes.fromhex(x509_data))
    certIssue = cert.get_issuer()
    certSubject = cert.get_subject()
    notAfter = parser.parse(cert.get_notAfter().decode("utf-8"))
    notBefore = parser.parse(cert.get_notBefore().decode("utf-8"))

    SAN = ""
    ex_num = cert.get_extension_count()
    for i in range(ex_num):
        ex = cert.get_extension(i)
        ex_name = ex.get_short_name().decode("utf-8")
        if ex_name == 'subjectAltName':
            SAN = str(ex)
    return certIssue.commonName, certSubject.commonName, notBefore, notAfter, cert.has_expired(), SAN


def parse_tcp(flags_str):
    flags = []
    num = int(flags_str, 16)
    num = bin(num)[2:]
    # print(num)
    for i in range(len(num)):
        flags.append(num[len(num) - 1 - i])
    if len(num) < 8:
        for i in range(8 - len(num)):
            flags.append("0")
    return flags


def gen_conn_state(flag_list, ack_list):
    # flags: FIN,SYN,RST,PSH,ACK,URG,ECE,CWR
    flag_list = np.array(flag_list)
    ack_list = np.array(ack_list)

    flag_ack_list = np.c_[flag_list, ack_list]
    # print(flag_ack_list)
    client2server = flag_ack_list[np.where(flag_ack_list[:, 0] == "->")][:, 1:]
    server2client = flag_ack_list[np.where(flag_ack_list[:, 0] == "<-")][:, 1:]

    # The string of conn_state is on the perspective of client (originator)
    # reference from http://www.takakura.com/Kyoto_data/BenchmarkData-Description-v5.pdf
    conn_state = []
    for i in client2server:
        if (i[:-1] == ['0', '1', '0', '0', '0', '0', '0', '0']).all():
            conn_state.append("SYN sent")
            break

    for i in server2client:
        if (i[:-1] == ['0', '1', '0', '0', '1', '0', '0', '0']).all():
            conn_state.append("SYN-ACK received")
            break

    for i in client2server:
        if (i[:-1] == ['0', '0', '0', '0', '1', '0', '0', '0']).all():
            conn_state.append("ACK sent")
            break

    for i in client2server:
        if (i[:-1] == ['0', '0', '1', '0', '1', '0', '0', '0']).all() or (
                i[:-1] == ['0', '0', '1', '0', '0', '0', '0', '0']).all():
            conn_state.append("RST sent")
            break

    for i in server2client:
        if (i[:-1] == ['0', '0', '1', '0', '1', '0', '0', '0']).all() or (
                i[:-1] == ['0', '0', '1', '0', '0', '0', '0', '0']).all():
            conn_state.append("RST received")
            break

    FIN_sent = ""
    FIN_receive = ""
    for i in flag_ack_list:
        if FIN_sent == "" and i[1] == '1':
            FIN_sent = i[0]
        if FIN_sent != "" and i[1] == '1':
            FIN_receive = i[0]
            break
    # print(conn_state)
    # print("FIN senter : ",FIN_sent)
    # print("FIN receiver : ",FIN_receive)

    # generate connection state
    if "SYN sent" not in conn_state and "SYN-ACK received" not in conn_state:
        # No SYN seen, just midstream traffic (a “partial connection” that was not later closed)
        return "OTH"
    elif "SYN sent" in conn_state and len(conn_state) == 1:
        # Connection attempt seen, no reply
        return "S0"
    elif "SYN sent" in conn_state and "RST received" in conn_state:
        # Connection attempt rejected
        return "REJ"
    elif "SYN sent" in conn_state and "SYN-ACK received" not in conn_state and "RST sent" in conn_state:
        # Originator sent a SYN followed by a RST, we never saw a SYN ACK from the responder
        return "RSTOS0"
    elif "SYN sent" in conn_state and "SYN-ACK received" not in conn_state and FIN_sent == "->":
        #  Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open)
        return "SH"
    elif "SYN sent" not in conn_state and "SYN-ACK received" in conn_state and "RST received" in conn_state:
        #  Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator
        return "RSTRH"
    elif "SYN sent" not in conn_state and "SYN-ACK received" in conn_state and FIN_sent == "<-":
        # Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator
        return "SHR"
    elif "SYN sent" in conn_state and "SYN-ACK received" in conn_state and "ACK sent" in conn_state:
        # Connection established
        if "RST sent" not in conn_state and "RST received" not in conn_state and FIN_sent == "" and FIN_receive == "":
            # Connection established, not terminated
            return "S1"
        elif "RST sent" not in conn_state and "RST received" not in conn_state and (
                FIN_sent != "" and FIN_receive != ""):
            # Normal establishment and termination
            return "SF"
        elif "RST sent" not in conn_state and "RST received" not in conn_state and (
                FIN_sent == "->" and FIN_receive == ""):
            # Connection established and close attempt by originator seen (but no reply from responder)
            return "S2"
        elif "RST sent" not in conn_state and "RST received" not in conn_state and (
                FIN_sent == "<-" and FIN_receive == ""):
            # Connection established and close attempt by responder seen (but no reply from originator)
            return "S3"
        elif "RST sent" in conn_state:
            # Connection established, originator aborted (sent a RST)
            return "RSTO"
        elif "RST received" in conn_state:
            # Established, responder aborted
            return "RSTR"
    return "Error"


def gen_five_tuple_flow(lines):
    f_dic = {}
    f_dic['tcp'] = {}
    f_dic['udp'] = {}
    f_dic['more_seg_flag'] = {}
    f_dic['ip_hdr_len'] = {}

    for line in lines:
        # try:
        #     timestamp = float(line[1])
        # except Exception as e:
        #     print("timestamp error")
        timestamp = line[1]
        proto = str(line[2])
        ip_src = str(line[3],encoding='utf-8')
        ip_dst = str(line[4],encoding='utf-8')
        ip_len = line[9]

        # new
        ip_hdr_len = int(line[10])
        tcp_flags = str(hex(line[11]).upper())
        tcp_hdr_len = str(line[12])
        tls_version = str(line[13])
        more_seg_flag = str(hex(line[14]).upper())
        tcp_ack = str(line[15])
        tls_content_type = str(line[16])
        certs = str(line[17],encoding='utf-8')
        sni = str(line[18],encoding='utf-8')
        # new end
        # print("timestamp",type(timestamp))
        # print("proto",type(proto))
        # print("ip_src",type(ip_src))
        # print("ip_dst",type(ip_dst))
        # print("ip_len",type(ip_len))
        # print("ip_hdr_len",type(ip_hdr_len))
        # print("tcp_flags",type(tcp_flags))
        # print("tcp_hdr_len",type(tcp_hdr_len))
        # print("tls_version",type(tls_version))
        # print("more_seg_flag",type(more_seg_flag))
        # print("tcp_ack",type(tcp_ack))
        # print("tls_content_type",type(tls_content_type))
        # print("certs",type(certs))
        # print("sni",type(sni))
        direction = '->'
        # try:
        if proto == '6':
            if int(line[5]) > int(line[6]):
                port_client = str(line[5])
                port_server = str(line[6])
                direction = '->'
            else:
                port_client = str(line[6])
                port_server = str(line[5])
                direction = '<-'
            key = port_client + '<->' + port_server
            if key not in f_dic['more_seg_flag'].keys():
                # if more_seg_flag == '1':
                f_dic['more_seg_flag'][key] = {}
                f_dic['more_seg_flag'][key]['->'] = []
                f_dic['more_seg_flag'][key]['<-'] = []
                f_dic['more_seg_flag'][key][direction].append(more_seg_flag)
            else:
                # if more_seg_flag == '1':
                f_dic['more_seg_flag'][key][direction].append(more_seg_flag)

            if key not in f_dic['ip_hdr_len'].keys():
                f_dic['ip_hdr_len'][key] = {}
                f_dic['ip_hdr_len'][key]['->'] = 0
                f_dic['ip_hdr_len'][key]['<-'] = 0
                f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
            else:
                f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
    
            if key not in f_dic['tcp'].keys():
                f_dic['tcp'][key] = {}
                f_dic['tcp'][key]['->'] = []
                f_dic['tcp'][key]['<-'] = []
                f_dic['tcp'][key]['<->'] = []
                f_dic['tcp'][key][direction].append(ip_len)
                f_dic['tcp'][key]['time'] = {}
                f_dic['tcp'][key]['time'][direction] = [timestamp]
                f_dic['tcp'][key]['time']['<->'] = [timestamp]
                # new
                f_dic['tcp'][key]['tcp_flag'] = [direction + ":" + tcp_flags]
                f_dic['tcp'][key]['tcp_ack'] = [tcp_ack]
                if tls_content_type != '':
                    f_dic['tcp'][key]['tls_content_type'] = [tls_content_type]
                else:
                    f_dic['tcp'][key]['tls_content_type'] = []
                if tls_version != '':
                    f_dic['tcp'][key]['tls_version'] = [tls_version]
                else:
                    f_dic['tcp'][key]['tls_version'] = []
                if certs != '':
                    f_dic['tcp'][key]['certs'] = [certs]
                else:
                    f_dic['tcp'][key]['certs'] = []
                if sni != '':
                    f_dic['tcp'][key]['sni'] = [sni]
                else:
                    f_dic['tcp'][key]['sni'] = []
                # new end
            else:
                if direction not in f_dic['tcp'][key]['time'].keys():
                    f_dic['tcp'][key]['time'][direction] = [timestamp]
                f_dic['tcp'][key][direction].append(ip_len)
                f_dic['tcp'][key]['time'][direction].append(timestamp)
            f_dic['tcp'][key]['<->'].append(ip_len)
            f_dic['tcp'][key]['time']['<->'].append(timestamp)
            # new
        
            f_dic['tcp'][key]['tcp_flag'].append(direction + ":" + tcp_flags)
            f_dic['tcp'][key]['tcp_ack'].append(tcp_ack)
            if tls_content_type != '': f_dic['tcp'][key]['tls_content_type'].append(tls_content_type)

            if tls_version != '': f_dic['tcp'][key]['tls_version'].append(tls_version)
            if certs != '': f_dic['tcp'][key]['certs'].append(certs)
            if sni != '' and sni not in f_dic['tcp'][key]['sni']: f_dic['tcp'][key]['sni'].append(sni)
            # new end
            
        else:
            if int(line[7]) > int(line[8]):
                port_client = str(line[7])
                port_server = str(line[8])
                direction = '->'
            else:
                port_client = line[8]
                port_server = line[7]
                direction = '<-'
            key = port_client + '<->' + port_server
            if key not in f_dic['more_seg_flag'].keys():
                if more_seg_flag == '0X1':
                    f_dic['more_seg_flag'][key] = {}
                    f_dic['more_seg_flag'][key]['->'] = []
                    f_dic['more_seg_flag'][key]['<-'] = []
                    f_dic['more_seg_flag'][key][direction].append(more_seg_flag)
            else:
                if more_seg_flag == '0X1':
                    f_dic['more_seg_flag'][key][direction].append(more_seg_flag)

            if key not in f_dic['ip_hdr_len'].keys():
                f_dic['ip_hdr_len'][key] = {}
                f_dic['ip_hdr_len'][key]['->'] = 0
                f_dic['ip_hdr_len'][key]['<-'] = 0
                f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
            else:
                f_dic['ip_hdr_len'][key][direction] += ip_hdr_len

            if key not in f_dic['udp'].keys():
                f_dic['udp'][key] = {}
                f_dic['udp'][key]['->'] = []
                f_dic['udp'][key]['<-'] = []
                f_dic['udp'][key]['<->'] = []
                f_dic['udp'][key][direction].append(ip_len)
                f_dic['udp'][key]['time'] = {}
                f_dic['udp'][key]['time'][direction] = [timestamp]
                f_dic['udp'][key]['time']['<->'] = [timestamp]
            else:
                if direction not in f_dic['udp'][key]['time'].keys():
                    f_dic['udp'][key]['time'][direction] = [timestamp]
                f_dic['udp'][key][direction].append(ip_len)
                f_dic['udp'][key]['time'][direction].append(timestamp)
            f_dic['udp'][key]['<->'].append(ip_len)
            f_dic['udp'][key]['time']['<->'].append(timestamp)
        # except Exception as e:
        #     print(e)
    return f_dic


def gen_flow(filename):
    f_dic = {}
    f_dic['tcp'] = {}
    f_dic['udp'] = {}
    f_dic['more_seg_flag'] = {}
    f_dic['ip_hdr_len'] = {}
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line[0:-1].split(",")
            try:
                timestamp = float(line[1])
            except Exception as e:
                break
            proto = line[2]
            ip_src = line[3]
            ip_dst = line[4]
            ip_len = int(line[9])

            # new
            ip_hdr_len = int(line[10])
            tcp_flags = line[11]
            tcp_hdr_len = line[12]
            tls_version = line[13]
            more_seg_flag = line[14]
            tcp_ack = line[15]
            tls_content_type = line[16]
            certs = line[17]
            sni = line[18]
            # new end

            direction = '->'
            if proto == '6':
                if int(line[5]) > int(line[6]):
                    port_client = line[5]
                    port_server = line[6]
                    direction = '->'
                else:
                    port_client = line[6]
                    port_server = line[5]
                    direction = '<-'
                key = port_client + '<->' + port_server
                if key not in f_dic['more_seg_flag'].keys():
                    if more_seg_flag == '1':
                        f_dic['more_seg_flag'][key] = {}
                        f_dic['more_seg_flag'][key]['->'] = []
                        f_dic['more_seg_flag'][key]['<-'] = []
                        f_dic['more_seg_flag'][key][direction].append(ip_len)
                else:
                    if more_seg_flag == '1':
                        f_dic['more_seg_flag'][key][direction].append(ip_len)

                if key not in f_dic['ip_hdr_len'].keys():
                    f_dic['ip_hdr_len'][key] = {}
                    f_dic['ip_hdr_len'][key]['->'] = 0
                    f_dic['ip_hdr_len'][key]['<-'] = 0
                    f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
                else:
                    f_dic['ip_hdr_len'][key][direction] += ip_hdr_len

                if key not in f_dic['tcp'].keys():
                    f_dic['tcp'][key] = {}
                    f_dic['tcp'][key]['->'] = []
                    f_dic['tcp'][key]['<-'] = []
                    f_dic['tcp'][key]['<->'] = []
                    f_dic['tcp'][key][direction].append(ip_len)
                    f_dic['tcp'][key]['time'] = {}
                    f_dic['tcp'][key]['time'][direction] = [timestamp]
                    f_dic['tcp'][key]['time']['<->'] = [timestamp]
                    # new
                    f_dic['tcp'][key]['tcp_flag'] = [direction + ":" + tcp_flags]
                    f_dic['tcp'][key]['tcp_ack'] = [tcp_ack]
                    if tls_content_type != '':
                        f_dic['tcp'][key]['tls_content_type'] = [tls_content_type]
                    else:
                        f_dic['tcp'][key]['tls_content_type'] = []
                    if tls_version != '':
                        f_dic['tcp'][key]['tls_version'] = [tls_version]
                    else:
                        f_dic['tcp'][key]['tls_version'] = []
                    if certs != '':
                        f_dic['tcp'][key]['certs'] = [certs]
                    else:
                        f_dic['tcp'][key]['certs'] = []
                    if sni != '':
                        f_dic['tcp'][key]['sni'] = [sni]
                    else:
                        f_dic['tcp'][key]['sni'] = []
                    # new end
                else:
                    if direction not in f_dic['tcp'][key]['time'].keys():
                        f_dic['tcp'][key]['time'][direction] = [timestamp]
                    f_dic['tcp'][key][direction].append(ip_len)
                    f_dic['tcp'][key]['time'][direction].append(timestamp)
                f_dic['tcp'][key]['<->'].append(ip_len)
                f_dic['tcp'][key]['time']['<->'].append(timestamp)
                # new
                f_dic['tcp'][key]['tcp_flag'].append(direction + ":" + tcp_flags)
                f_dic['tcp'][key]['tcp_ack'].append(tcp_ack)
                if tls_content_type != '': f_dic['tcp'][key]['tls_content_type'].append(tls_content_type)

                if tls_version != '': f_dic['tcp'][key]['tls_version'].append(tls_version)
                if certs != '': f_dic['tcp'][key]['certs'].append(certs)
                if sni != '' and sni not in f_dic['tcp'][key]['sni']: f_dic['tcp'][key]['sni'].append(sni)
                # new end
            else:
                if int(line[7]) > int(line[8]):
                    port_client = line[7]
                    port_server = line[8]
                    direction = '->'
                else:
                    port_client = line[8]
                    port_server = line[7]
                    direction = '<-'
                key = port_client + '<->' + port_server
                if key not in f_dic['more_seg_flag'].keys():
                    if more_seg_flag == '1':
                        f_dic['more_seg_flag'][key] = {}
                        f_dic['more_seg_flag'][key]['->'] = []
                        f_dic['more_seg_flag'][key]['<-'] = []
                        f_dic['more_seg_flag'][key][direction].append(ip_len)
                else:
                    if more_seg_flag == '1':
                        f_dic['more_seg_flag'][key][direction].append(ip_len)

                if key not in f_dic['ip_hdr_len'].keys():
                    f_dic['ip_hdr_len'][key] = {}
                    f_dic['ip_hdr_len'][key]['->'] = 0
                    f_dic['ip_hdr_len'][key]['<-'] = 0
                    f_dic['ip_hdr_len'][key][direction] += ip_hdr_len
                else:
                    f_dic['ip_hdr_len'][key][direction] += ip_hdr_len

                if key not in f_dic['udp'].keys():
                    f_dic['udp'][key] = {}
                    f_dic['udp'][key]['->'] = []
                    f_dic['udp'][key]['<-'] = []
                    f_dic['udp'][key]['<->'] = []
                    f_dic['udp'][key][direction].append(ip_len)
                    f_dic['udp'][key]['time'] = {}
                    f_dic['udp'][key]['time'][direction] = [timestamp]
                    f_dic['udp'][key]['time']['<->'] = [timestamp]
                else:
                    if direction not in f_dic['udp'][key]['time'].keys():
                        f_dic['udp'][key]['time'][direction] = [timestamp]
                    f_dic['udp'][key][direction].append(ip_len)
                    f_dic['udp'][key]['time'][direction].append(timestamp)
                f_dic['udp'][key]['<->'].append(ip_len)
                f_dic['udp'][key]['time']['<->'].append(timestamp)
        return f_dic


def get_statistical_fraturs(list, timestamp_list):
    duration = timestamp_list[-1] - timestamp_list[0] if len(timestamp_list) > 0 else 0
    
    if len(list) > 0:
        f_max = max(list)
        f_min = min(list)
        f_mean = np.mean(list)
        f_var = np.var(list)
        f_std = np.std(list, ddof=1)
        f_sum = sum(list)
        f_pkts_num = len(list)
        if duration < 0.1:
            f_speed = 0
        else:
            f_speed = f_sum / duration
        f_10_p = np.percentile(list, 10)
        f_20_p = np.percentile(list, 20)
        f_30_p = np.percentile(list, 30)
        f_40_p = np.percentile(list, 40)
        f_50_p = np.percentile(list, 50)
        f_60_p = np.percentile(list, 60)
        f_70_p = np.percentile(list, 70)
        f_80_p = np.percentile(list, 80)
        f_90_p = np.percentile(list, 90)
    else:
        f_max, f_min, f_mean, f_var, f_std, f_sum, f_pkts_num, f_speed = 0, 0, 0, 0, 0, 0, 0, 0
        f_10_p, f_20_p, f_30_p, f_40_p, f_50_p, f_60_p, f_70_p, f_80_p, f_90_p = 0, 0, 0, 0, 0, 0, 0, 0, 0

    flow_IAT_list = []
    for i in range(len(timestamp_list) - 1):
        flow_IAT_list.append(timestamp_list[i + 1] - timestamp_list[i])
    if len(flow_IAT_list) > 0:
        IAT_min = min(flow_IAT_list)
        IAT_max = max(flow_IAT_list)
        IAT_avg = np.mean(flow_IAT_list)
        IAT_std = np.std(flow_IAT_list, ddof=1)
        IAT_total = np.sum(flow_IAT_list)
    else:
        IAT_min, IAT_max, IAT_avg, IAT_std, IAT_total = 0, 0, 0, 0, 0
    return f_sum, f_pkts_num, duration, f_speed, f_max, f_min, f_mean, f_var, f_std, f_10_p, f_20_p, f_30_p, f_40_p, f_50_p, f_60_p, f_70_p, f_80_p, f_90_p, IAT_min, IAT_max, IAT_avg, IAT_std, IAT_total


def get_sample_features_(hash_key_string, f_dic):
    f_list = []
    tag = 4
    for key in f_dic['tcp'].keys():
        proto = 'tcp'
        if '->' in f_dic[proto][key]['time'].keys():
            send = get_statistical_fraturs(f_dic[proto][key]['->'], f_dic[proto][key]['time']['->'])
        else:
            send = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<-' in f_dic[proto][key]['time'].keys():
            receive = get_statistical_fraturs(f_dic[proto][key]['<-'], f_dic[proto][key]['time']['<-'])
        else:
            receive = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<->' in f_dic[proto][key]['time'].keys():
            total = get_statistical_fraturs(f_dic[proto][key]['<->'], f_dic[proto][key]['time']['<->'])
        else:
            total = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        records = []
        records.append(hash_key_string)
        records.append(tag)
        records.append(1)  # proto=='tcp'
        records.append(f_dic[proto][key]['time']['<->'][0])
        records.append(f_dic['ip_hdr_len'][key]['->'])
        records.append(f_dic['ip_hdr_len'][key]['<-'])
        for i in send:
            records.append(i)
        for i in receive:
            records.append(i)
        for i in total:
            records.append(i)

        records.append(";".join(f_dic['tcp'][key]['tcp_flag']))

        flags_list = []
        for i in f_dic['tcp'][key]['tcp_flag']:
            line = i.split(":")
            flags = parse_tcp(line[1])
            flags_list.append([line[0]] + flags)
        t_flags_list = np.array(flags_list)
        c_flags_list = t_flags_list[np.where(t_flags_list[:, 0] == "->")]
        s_flags_list = t_flags_list[np.where(t_flags_list[:, 0] == "<-")]
        c_FIN_cnt = np.sum(c_flags_list[:, 1] == '1')
        c_SYN_cnt = np.sum(c_flags_list[:, 2] == '1')
        c_RST_cnt = np.sum(c_flags_list[:, 3] == '1')
        c_PSH_cnt = np.sum(c_flags_list[:, 4] == '1')
        c_ACK_cnt = np.sum(c_flags_list[:, 5] == '1')
        c_URG_cnt = np.sum(c_flags_list[:, 6] == '1')
        c_ECE_cnt = np.sum(c_flags_list[:, 7] == '1')
        c_CWR_cnt = np.sum(c_flags_list[:, 8] == '1')
        records.append(c_FIN_cnt)
        records.append(c_SYN_cnt)
        records.append(c_RST_cnt)
        records.append(c_PSH_cnt)
        records.append(c_ACK_cnt)
        records.append(c_URG_cnt)
        records.append(c_ECE_cnt)
        records.append(c_CWR_cnt)
        s_FIN_cnt = np.sum(s_flags_list[:, 1] == '1')
        s_SYN_cnt = np.sum(s_flags_list[:, 2] == '1')
        s_RST_cnt = np.sum(s_flags_list[:, 3] == '1')
        s_PSH_cnt = np.sum(s_flags_list[:, 4] == '1')
        s_ACK_cnt = np.sum(s_flags_list[:, 5] == '1')
        s_URG_cnt = np.sum(s_flags_list[:, 6] == '1')
        s_ECE_cnt = np.sum(s_flags_list[:, 7] == '1')
        s_CWR_cnt = np.sum(s_flags_list[:, 8] == '1')
        records.append(s_FIN_cnt)
        records.append(s_SYN_cnt)
        records.append(s_RST_cnt)
        records.append(s_PSH_cnt)
        records.append(s_ACK_cnt)
        records.append(s_URG_cnt)
        records.append(s_ECE_cnt)
        records.append(s_CWR_cnt)
        t_FIN_cnt = np.sum(t_flags_list[:, 1] == '1')
        t_SYN_cnt = np.sum(t_flags_list[:, 2] == '1')
        t_RST_cnt = np.sum(t_flags_list[:, 3] == '1')
        t_PSH_cnt = np.sum(t_flags_list[:, 4] == '1')
        t_ACK_cnt = np.sum(t_flags_list[:, 5] == '1')
        t_URG_cnt = np.sum(t_flags_list[:, 6] == '1')
        t_ECE_cnt = np.sum(t_flags_list[:, 7] == '1')
        t_CWR_cnt = np.sum(t_flags_list[:, 8] == '1')
        records.append(t_FIN_cnt)
        records.append(t_SYN_cnt)
        records.append(t_RST_cnt)
        records.append(t_PSH_cnt)
        records.append(t_ACK_cnt)
        records.append(t_URG_cnt)
        records.append(t_ECE_cnt)
        records.append(t_CWR_cnt)

        records.append(";".join(f_dic['tcp'][key]['tcp_ack']))
        conn_state = gen_conn_state(flags_list, f_dic['tcp'][key]['tcp_ack'])
        records.append(conn_state)
        if key in f_dic['more_seg_flag']:
            records.append(";".join(f_dic['more_seg_flag'][key]['->']))
            records.append(";".join(f_dic['more_seg_flag'][key]['<-']))

        else:
            records.append("")
            records.append("")
        records.append(";".join(f_dic['tcp'][key]['tls_version']))
        records.append(";".join(f_dic['tcp'][key]['tls_content_type']))
        CCS_cnt = f_dic['tcp'][key]['tls_content_type'].count('22')
        records.append(CCS_cnt)

        records.append(";".join(f_dic['tcp'][key]['certs']))
        records.append(";".join(f_dic['tcp'][key]['sni']))

        f_list.append(records)
    return f_list[0]


def get_sample_features(file, f_dic):
    f_list = []
    tag = 4
    for key in f_dic['tcp'].keys():
        proto = 'tcp'
        if '->' in f_dic[proto][key]['time'].keys():
            send = get_statistical_fraturs(f_dic[proto][key]['->'], f_dic[proto][key]['time']['->'])
        else:
            send = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<-' in f_dic[proto][key]['time'].keys():
            receive = get_statistical_fraturs(f_dic[proto][key]['<-'], f_dic[proto][key]['time']['<-'])
        else:
            receive = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        if '<->' in f_dic[proto][key]['time'].keys():
            total = get_statistical_fraturs(f_dic[proto][key]['<->'], f_dic[proto][key]['time']['<->'])
        else:
            total = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        records = []
        records.append(file[:-4])
        records.append(tag)
        records.append(1)  # proto=='tcp'
        records.append(f_dic[proto][key]['time']['<->'][0])
        records.append(f_dic['ip_hdr_len'][key]['->'])
        records.append(f_dic['ip_hdr_len'][key]['<-'])
        for i in send:
            records.append(i)
        for i in receive:
            records.append(i)
        for i in total:
            records.append(i)

        records.append(";".join(f_dic['tcp'][key]['tcp_flag']))

        flags_list = []
        for i in f_dic['tcp'][key]['tcp_flag']:
            line = i.split(":")
            flags = parse_tcp(line[1])
            flags_list.append([line[0]] + flags)
        t_flags_list = np.array(flags_list)
        c_flags_list = t_flags_list[np.where(t_flags_list[:, 0] == "->")]
        s_flags_list = t_flags_list[np.where(t_flags_list[:, 0] == "<-")]
        c_FIN_cnt = np.sum(c_flags_list[:, 1] == '1')
        c_SYN_cnt = np.sum(c_flags_list[:, 2] == '1')
        c_RST_cnt = np.sum(c_flags_list[:, 3] == '1')
        c_PSH_cnt = np.sum(c_flags_list[:, 4] == '1')
        c_ACK_cnt = np.sum(c_flags_list[:, 5] == '1')
        c_URG_cnt = np.sum(c_flags_list[:, 6] == '1')
        c_ECE_cnt = np.sum(c_flags_list[:, 7] == '1')
        c_CWR_cnt = np.sum(c_flags_list[:, 8] == '1')
        records.append(c_FIN_cnt)
        records.append(c_SYN_cnt)
        records.append(c_RST_cnt)
        records.append(c_PSH_cnt)
        records.append(c_ACK_cnt)
        records.append(c_URG_cnt)
        records.append(c_ECE_cnt)
        records.append(c_CWR_cnt)
        s_FIN_cnt = np.sum(s_flags_list[:, 1] == '1')
        s_SYN_cnt = np.sum(s_flags_list[:, 2] == '1')
        s_RST_cnt = np.sum(s_flags_list[:, 3] == '1')
        s_PSH_cnt = np.sum(s_flags_list[:, 4] == '1')
        s_ACK_cnt = np.sum(s_flags_list[:, 5] == '1')
        s_URG_cnt = np.sum(s_flags_list[:, 6] == '1')
        s_ECE_cnt = np.sum(s_flags_list[:, 7] == '1')
        s_CWR_cnt = np.sum(s_flags_list[:, 8] == '1')
        records.append(s_FIN_cnt)
        records.append(s_SYN_cnt)
        records.append(s_RST_cnt)
        records.append(s_PSH_cnt)
        records.append(s_ACK_cnt)
        records.append(s_URG_cnt)
        records.append(s_ECE_cnt)
        records.append(s_CWR_cnt)
        t_FIN_cnt = np.sum(t_flags_list[:, 1] == '1')
        t_SYN_cnt = np.sum(t_flags_list[:, 2] == '1')
        t_RST_cnt = np.sum(t_flags_list[:, 3] == '1')
        t_PSH_cnt = np.sum(t_flags_list[:, 4] == '1')
        t_ACK_cnt = np.sum(t_flags_list[:, 5] == '1')
        t_URG_cnt = np.sum(t_flags_list[:, 6] == '1')
        t_ECE_cnt = np.sum(t_flags_list[:, 7] == '1')
        t_CWR_cnt = np.sum(t_flags_list[:, 8] == '1')
        records.append(t_FIN_cnt)
        records.append(t_SYN_cnt)
        records.append(t_RST_cnt)
        records.append(t_PSH_cnt)
        records.append(t_ACK_cnt)
        records.append(t_URG_cnt)
        records.append(t_ECE_cnt)
        records.append(t_CWR_cnt)

        records.append(";".join(f_dic['tcp'][key]['tcp_ack']))
        conn_state = gen_conn_state(flags_list, f_dic['tcp'][key]['tcp_ack'])
        records.append(conn_state)
        if key in f_dic['more_seg_flag']:
            records.append(";".join(f_dic['more_seg_flag'][key]['->']))
            records.append(";".join(f_dic['more_seg_flag'][key]['<-']))

        else:
            records.append("")
            records.append("")
        records.append(";".join(f_dic['tcp'][key]['tls_version']))
        records.append(";".join(f_dic['tcp'][key]['tls_content_type']))
        CCS_cnt = f_dic['tcp'][key]['tls_content_type'].count('22')
        records.append(CCS_cnt)

        records.append(";".join(f_dic['tcp'][key]['certs']))
        records.append(";".join(f_dic['tcp'][key]['sni']))

        f_list.append(records)

    # for key in f_dic['udp'].keys():
    #     proto = 'udp'
    #     if '->' in f_dic[proto][key]['time'].keys():
    #         send = get_statistical_fraturs(f_dic[proto][key]['->'], f_dic[proto][key]['time']['->'])
    #     else:
    #         send = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    #     if '<-' in f_dic[proto][key]['time'].keys():
    #         receive = get_statistical_fraturs(f_dic[proto][key]['<-'], f_dic[proto][key]['time']['<-'])
    #     else:
    #         receive = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    #     if '<->' in f_dic[proto][key]['time'].keys():
    #         total = get_statistical_fraturs(f_dic[proto][key]['<->'], f_dic[proto][key]['time']['<->'])
    #     else:
    #         total = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    #     records = []
    #     records.append(file[:-4])
    #     records.append(tag)
    #     records.append(0)  # proto=='udp'
    #     records.append(f_dic[proto][key]['time']['<->'][0])
    #     records.append(f_dic['ip_hdr_len'][key]['->'])
    #     records.append(f_dic['ip_hdr_len'][key]['<-'])
    #     for i in send:
    #         records.append(i)
    #     for i in receive:
    #         records.append(i)
    #     for i in total:
    #         records.append(i)
        # f_list.append(records)
    return records


def is_nan(input):
    return input != input


def cal_similarity(str1, str2):
    return difflib.SequenceMatcher(None, str1, str2).ratio()


def parse_tls_version(tls_version):
    version_list = tls_version.split(";")

    version = int(version_list[0], 16)
    if version == 769:  # 0x0301
        return 1  # tls 1.0
    elif version == 770:  # 0x0302
        return 2  # tls 1.1
    elif version == 771:  # 0x0303
        return 3  # tls 1.2
    else:
        return 4


def self_cert_detect(cert_list):
    for x509_data in cert_list:
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes.fromhex(x509_data))
            certIssue = cert.get_issuer()
            certSubject = cert.get_subject()
        # issue = {}
        # subject = {}
        # for item in certIssue.get_components():
        #     key = item[0].decode("utf-8")
        #     if key not in issue.keys():
        #         issue[key] = [item[1].decode("utf-8")]
        #     else:
        #         issue[key].append(item[1].decode("utf-8"))
        # for item in certSubject.get_components():
        #     key = item[0].decode("utf-8")
        #     if key not in subject.keys():
        #         subject[key] = [item[1].decode("utf-8")]
        #     else:
        #         subject[key].append(item[1].decode("utf-8"))
            issue = []
            subject = []
            for item in certIssue.get_components():
                issue.append(item[1].decode("utf-8"))
            for item in certSubject.get_components():
                subject.append(item[1].decode("utf-8"))

        # issue = certIssue.commonName
        # subject = certSubject.commonName

            similarity = cal_similarity(issue, subject)

            if similarity > 0.9:
                return 1
            
        except Exception as e:
            pass

def parse_x509_cert(cert_list, sni_list):
    # valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag
    valid_list = []
    expire_flag = 0
    age_list = []
    san_dns_total_list = []
    consistent_flag = 0
    now_time = datetime.datetime.now()
    for x509_data in cert_list:
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, bytes.fromhex(x509_data))
            notBefore = parser.parse(cert.get_notBefore().decode("utf-8")).replace(tzinfo=None)
            notAfter = parser.parse(cert.get_notAfter().decode("utf-8")).replace(tzinfo=None)

            valid_seconds = (notAfter - notBefore).total_seconds()
            valid_list.append(valid_seconds)
            life_seconds = (now_time - notBefore).total_seconds()
            if cert.has_expired():
                expire_flag = 1
            age = life_seconds / valid_seconds
            age_list.append(age)
            san_dns_list = []
            for i in range(cert.get_extension_count()):
                extension = cert.get_extension(i)
                short_name = extension.get_short_name()
                if short_name == 'subjectAltName':
                    san_dns = str(extension)
                    san_dns_list = [i.split(":")[1] for i in san_dns.split(",")]
            if len(san_dns_list) > 0:
                san_dns_total_list += san_dns_list
            if len(san_dns_list) != 0 and len(sni_list) != 0 and consistent_flag == 0:

                if cal_similarity(san_dns_list, sni_list) > 0.9:
                    consistent_flag = 1
            # for i in san_dns_list:
            #     for j in sni_list:
            #         if cal_similarity(i, j) > 0.9:
            #             consistent_flag = 1
        except Exception as e:
            pass

    valid_avg = np.mean(valid_list) if len(valid_list) > 0 else 0
    valid_std = np.std(valid_list) if len(valid_list) > 0 else 0
    age_avg = np.mean(age_list) if len(age_list) > 0 else 0

    san_dns_num_avg = len(san_dns_total_list) / len(cert_list) if len(cert_list) != 0 else 0
    return valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag


def parse_features_2(line):

    ip_src, port_src, ip_dst, port_dst, proto, label = line[2], line[3], line[4], line[5], line[8], line[7]

    SSL_flag = 0 if is_nan(line[110]) else 1
    TLS_version = parse_tls_version(line[110]) if not is_nan(line[110]) else 0
    sni_flag = 1 if not is_nan(line[114]) else 0
    cert_list = line[113].split(";") if not is_nan(line[113]) else []
    cert_chain_len = len(cert_list)
    self_cert_flag = self_cert_detect(cert_list)
    # dga_flag

    sni_list = line[114].split(";") if not is_nan(line[114]) else []
    valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag = parse_x509_cert(cert_list,
                                                                                                   sni_list)
    cert_num = len(cert_list)

    fw_pkt_l_max, fw_pkt_l_min, fw_pkt_l_avg, fw_pkt_l_var, fw_pkt_l_std = line[16], line[17], line[18], line[19], \
        line[20]

    bw_pkt_l_max, bw_pkt_l_min, bw_pkt_l_avg, bw_pkt_l_var, bw_pkt_l_std = line[39], line[40], line[41], line[42], \
        line[43]

    fl_pkt_l_max, fl_pkt_l_min, fl_pkt_l_avg, fl_pkt_l_var, fl_pkt_l_std = line[62], line[63], line[64], line[65], \
        line[66]

    fw_byt_s, bw_byt_s, fl_byt_s = line[15], line[38], line[61]

    fw_duration, bw_duration, fl_duration = line[14], line[37], line[60]

    fw_pkt_s = line[13] / fw_duration if not is_nan(fw_duration) and fw_duration > 0.1 else 0
    bw_pkt_s = line[36] / bw_duration if not is_nan(bw_duration) and bw_duration > 0.1 else 0
    fl_pkt_s = line[59] / fl_duration if not is_nan(fl_duration) and fl_duration > 0.1 else 0

    fw_iat_min, fw_iat_max, fw_iat_avg, fw_iat_std, fw_iat_tot = line[30], line[31], line[32], line[33], line[34]

    bw_iat_min, bw_iat_max, bw_iat_avg, bw_iat_std, bw_iat_tot = line[53], line[54], line[55], line[56], line[57]

    fl_iat_min, fl_iat_max, fl_iat_avg, fl_iat_std, fl_iat_tot = line[76], line[77], line[78], line[79], line[80]

    fw_fin_cnt, fw_syn_cnt, fw_rst_cnt, fw_psh_cnt, fw_ack_cnt, fw_urg_cnt, fw_ece_cnt, fw_cwr_cnt = line[82], line[
        83], line[84], line[85], line[86], line[87], line[88], line[89]

    bw_fin_cnt, bw_syn_cnt, bw_rst_cnt, bw_psh_cnt, bw_ack_cnt, bw_urg_cnt, bw_ece_cnt, bw_cwr_cnt = line[90], line[
        91], line[92], line[93], line[94], line[95], line[96], line[97]

    fl_fin_cnt, fl_syn_cnt, fl_rst_cnt, fl_psh_cnt, fl_ack_cnt, fl_urg_cnt, fl_ece_cnt, fl_cwr_cnt = line[98], line[
        99], line[100], line[101], line[102], line[103], line[104], line[105]

    fw_10_p, fw_20_p, fw_30_p, fw_40_p, fw_50_p, fw_60_p, fw_70_p, fw_80_p, fw_90_p = line[21], line[22], line[23], \
        line[24], line[25], line[26], line[27], line[28], line[29]

    bw_10_p, bw_20_p, bw_30_p, bw_40_p, bw_50_p, bw_60_p, bw_70_p, bw_80_p, bw_90_p = line[44], line[45], line[46], \
        line[47], line[48], line[49], line[50], line[51], line[52]

    fl_10_p, fl_20_p, fl_30_p, fl_40_p, fl_50_p, fl_60_p, fl_70_p, fl_80_p, fl_90_p = line[67], line[68], line[69], \
        line[70], line[71], line[72], line[73], line[74], line[75]

    fw_hdr_len, bw_hdr_len = line[10], line[11]

    down_up_ratio = line[35] / line[12] if not is_nan(line[12]) else 0
    # pkt_size_avg =

    fw_seg_avg = np.mean([int(i,16) for i in line[108].split(";")]) if not is_nan(line[108]) else 0
    bw_seg_avg = np.mean([int(i,16) for i in line[109].split(";")]) if not is_nan(line[109]) else 0
    fw_seg_cnt = len([int(i,16) for i in line[108].split(";")]) if not is_nan(line[108]) else 0
    bw_seg_cnt = len([int(i,16) for i in line[109].split(";")]) if not is_nan(line[109]) else 0
    fl_seg_cnt = fw_seg_cnt + bw_seg_cnt
    conn_state = line[107]
    timestamp = line[9]

    # 基于时间的网络流量统计特征
    # last_2_s_list = data[np.where((data[:, 9] <= timestamp) & (data[:, 9] > timestamp - 2))]
    #
    # last_2_same_host_list = last_2_s_list[np.where(last_2_s_list[:, 4] == ip_dst)]
    # count = len(last_2_same_host_list)
    # serror_list = last_2_same_host_list[np.where(
    #     (last_2_same_host_list[:, 107] == 'S0') & (last_2_same_host_list[:, 107] == 'S1') & (
    #             last_2_same_host_list[:, 107] == 'S2') & (
    #             last_2_same_host_list[:, 107] == 'S3'))]
    # serror_rate = len(serror_list) / count if count > 0 else 0
    # rerror_list = last_2_same_host_list[np.where(last_2_same_host_list[:, 107] == 'REJ')]
    # rerror_rate = len(rerror_list) / count if count > 0 else 0
    # last_2_host_srv_list = last_2_same_host_list[np.where(last_2_same_host_list[:, 8] == proto)]
    # host_srv_cnt = len(last_2_host_srv_list)
    # same_srv_rate = host_srv_cnt / count if count > 0 else 0
    # diff_srv_rate = 1 - same_srv_rate
    #
    # last_2_same_src_list = last_2_s_list[np.where(last_2_s_list[:, 8] == proto)]
    # srv_count = len(last_2_same_src_list)
    # srv_serror_list = last_2_s_list[np.where(
    #     (last_2_same_src_list[:, 107] == 'S0') & (last_2_same_src_list[:, 107] == 'S1') & (
    #             last_2_same_src_list[:, 107] == 'S2') & (
    #             last_2_same_src_list[:, 107] == 'S3'))]
    # srv_rerror_list = last_2_same_src_list[np.where(last_2_same_src_list[:, 107] == 'REJ')]
    # srv_serror_rate = len(srv_serror_list) / srv_count if srv_count > 0 else 0
    # srv_rerror_rate = len(srv_rerror_list) / srv_count if srv_count > 0 else 0
    # srv_same_host_rate = host_srv_cnt / srv_count if srv_count > 0 else 0
    # srv_diff_host_rate = 1 - srv_same_host_rate

    # 基于主机的网络流量统计特征
    # first = i - 100 if (i - 100) > 0 else 1
    # last_100_list = data[0:first, :]
    # last_100_cnt = len(last_100_list)
    # same_host_list = last_100_list[np.where(last_100_list[:, 4] == ip_dst)]
    # same_host_srv_list = last_100_list[np.where((last_100_list[:, 4] == ip_dst) & (last_100_list[:, 8] == proto))]
    # dst_host_count = len(same_host_list)
    # dst_host_srv_count = len(same_host_srv_list)
    # dst_host_same_srv_rate = dst_host_count / last_100_cnt if last_100_cnt > 0 else 0
    # dst_host_diff_srv_rate = 1 - dst_host_same_srv_rate
    # same_host_sport_list = last_100_list[
    #     np.where((last_100_list[:, 4] == ip_dst) & (last_100_list[:, 3] == port_src))]
    # dst_host_same_src_port_rate = len(same_host_sport_list) / last_100_cnt if last_100_cnt > 0 else 0
    # diff_sip_list = same_host_srv_list[np.where(same_host_srv_list[:, 2] != ip_src)]
    # dst_host_srv_diff_host_rate = len(diff_sip_list) / dst_host_srv_count if dst_host_srv_count > 0 else 0
    #
    # dst_host_serror_list = same_host_list[np.where(
    #     (same_host_list[:, 107] == 'S0') & (same_host_list[:, 107] == 'S1') & (
    #             same_host_list[:, 107] == 'S2') & (
    #             same_host_list[:, 107] == 'S3'))]
    # dst_host_serror_rate = len(dst_host_serror_list) / dst_host_count if dst_host_count > 0 else 0
    # dst_host_rerror_list = same_host_list[np.where(same_host_list[:, 107] == 'REJ')]
    # dst_host_rerror_rate = len(dst_host_rerror_list) / dst_host_count if dst_host_count > 0 else 0
    #
    # dst_host_srv_serror_list = same_host_srv_list[np.where(
    #     (same_host_srv_list[:, 107] == 'S0') & (same_host_srv_list[:, 107] == 'S1') & (
    #             same_host_srv_list[:, 107] == 'S2') & (
    #             same_host_srv_list[:, 107] == 'S3'))]
    # dst_host_srv_serror_rate = len(dst_host_srv_serror_list) / dst_host_srv_count if dst_host_srv_count > 0 else 0
    # dst_host_srv_rerror_list = same_host_srv_list[np.where(same_host_srv_list[:, 107] == 'REJ')]
    # dst_host_srv_rerror_rate = len(dst_host_srv_rerror_list) / dst_host_srv_count if dst_host_srv_count > 0 else 0

    new_line = [ip_src, port_src, ip_dst, port_dst, proto, label, timestamp, SSL_flag, TLS_version, sni_flag,
                cert_chain_len, self_cert_flag,
                valid_avg, valid_std, expire_flag, age_avg, san_dns_num_avg, consistent_flag, cert_num,
                fw_pkt_l_max, fw_pkt_l_min, fw_pkt_l_avg, fw_pkt_l_var, fw_pkt_l_std, fw_byt_s,
                fw_pkt_s, fw_iat_min, fw_iat_max, fw_iat_avg, fw_iat_std, fw_iat_tot,
                fw_fin_cnt, fw_syn_cnt, fw_rst_cnt, fw_psh_cnt, fw_ack_cnt, fw_urg_cnt, fw_ece_cnt,
                fw_cwr_cnt, fw_10_p, fw_20_p, fw_30_p, fw_40_p, fw_50_p, fw_60_p, fw_70_p, fw_80_p, fw_90_p,
                fw_duration,
                bw_pkt_l_max, bw_pkt_l_min, bw_pkt_l_avg, bw_pkt_l_var, bw_pkt_l_std, bw_byt_s,
                bw_pkt_s, bw_iat_min, bw_iat_max, bw_iat_avg, bw_iat_std, bw_iat_tot,
                bw_fin_cnt, bw_syn_cnt, bw_rst_cnt, bw_psh_cnt, bw_ack_cnt, bw_urg_cnt, bw_ece_cnt,
                bw_cwr_cnt, bw_10_p, bw_20_p, bw_30_p, bw_40_p, bw_50_p, bw_60_p, bw_70_p, bw_80_p, bw_90_p,
                bw_duration,
                fl_pkt_l_max, fl_pkt_l_min, fl_pkt_l_avg, fl_pkt_l_var, fl_pkt_l_std, fl_byt_s,
                fl_pkt_s, fl_iat_min, fl_iat_max, fl_iat_avg, fl_iat_std, fl_iat_tot,
                fl_fin_cnt, fl_syn_cnt, fl_rst_cnt, fl_psh_cnt, fl_ack_cnt, fl_urg_cnt, fl_ece_cnt,
                fl_cwr_cnt, fl_10_p, fl_20_p, fl_30_p, fl_40_p, fl_50_p, fl_60_p, fl_70_p, fl_80_p, fl_90_p,
                fl_duration,
                fw_hdr_len, bw_hdr_len, down_up_ratio, fw_seg_avg, bw_seg_avg, fl_seg_cnt, conn_state]
                # count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate,
                # diff_srv_rate, srv_diff_host_rate, srv_same_host_rate,
                # dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
                # dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
                # dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate

    return new_line

def gen_new_fields_list(fields_list):
    host_list = fields_list[0].split(" ")
    host0 = host_list[0].split(":")
    host1 = host_list[1].split(":")
    ip_src = host0[0]
    port_src = host0[1]
    ip_dst = host1[0]
    port_dst = host1[1]
    fields_list_new = ["NULL","NULL",ip_src,port_src,ip_dst,port_dst] + fields_list
    return fields_list_new

def gen_five_tuple(lines):
    f_dic = gen_five_tuple_flow(lines)
    # print(f_dic)
    # f_dic = {'tcp': {'49262<->80': {'->': [52, 40, 409, 40, 40, 40], '<-': [44, 40, 243, 40, 40], '<->': [52, 44, 40, 409, 40, 243, 40, 40, 40, 40, 40], 'time': {'->': [57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829], '<->': [57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829], '<-': [57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829, 57924963557829]}, 'tcp_flag': ['->:0X2', '->:0X2', '<-:0X12', '->:0X10', '->:0X18', '<-:0X10', '<-:0X18', '->:0X10', '<-:0X19', '->:0X10', '->:0X11', '<-:0X10'], 'tcp_ack': ['0', '0', '546486945', '733044992', '733044992', '-1852589407', '-1852589407', '-156147456', '-1852589407', '-139370240', '-139370240', '-1835812191'], 'tls_content_type': ['4', '4', '4', '4', '4', '4', '4', '4', '4', '4', '4', '4'], 'tls_version': ['3', '3', '3', '3', '3', '3', '3', '3', '3', '3', '3', '3'], 'certs': ['cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test', 'cert_test'], 'sni': ['sni_test']}}, 'udp': {}, 'more_seg_flag': {'49262<->80': {'->': [52, 40, 409, 40, 40, 40], '<-': [44, 40, 243, 40, 40]}}, 'ip_hdr_len': {'49262<->80': {'->': 30, '<-': 25}}}
    
    fields_list = get_sample_features_(str(lines[0][0],encoding='utf-8'),f_dic)
    # print(fields_list)
    # fields_list = ['10.12.19.102:49442 193.3.23.123:233', 4, 1, 65137393149423, 30, 25, 621, 6, 0, 0, 409, 40, 103.5, 18685.25, 149.74077600974292, 40.0, 40.0, 40.0, 40.0, 40.0, 40.0, 46.0, 52.0, 230.5, 0, 0, 0.0, 0.0, 0, 407, 5, 0, 0, 243, 40, 81.4, 6531.039999999999, 90.35374923045529, 40.0, 40.0, 40.0, 40.0, 40.0, 41.6, 43.2, 83.80000000000004, 163.40000000000003, 0, 0, 0.0, 0.0, 0, 1028, 11, 0, 0, 409, 40, 93.45454545454545, 13281.702479338843, 120.87130646796504, 40.0, 40.0, 40.0, 40.0, 40.0, 40.0, 44.0, 52.0, 243.0, 0, 0, 0.0, 0.0, 0, '->:0X2;->:0X2;<-:0X12;->:0X10;->:0X18;<-:0X10;<-:0X18;->:0X10;<-:0X19;->:0X10;->:0X11;<-:0X10', 1, 2, 0, 1, 5, 0, 0, 0, 1, 1, 0, 2, 5, 0, 0, 0, 2, 3, 0, 3, 10, 0, 0, 0, '0;0;546486945;733044992;733044992;-1852589407;-1852589407;-156147456;-1852589407;-139370240;-139370240;-1835812191', 'SF', '0X1;0X1;0X1;0X1;0X1;0X1', '0X1;0X1;0X1;0X1;0X1', '3;3;3;3;3;3;3;3;3;3;3;3', '4;4;4;4;4;4;4;4;4;4;4;4', 0, 'cert_test;cert_test;cert_test;cert_test;cert_test;cert_test;cert_test;cert_test;cert_test;cert_test;cert_test;cert_test', 'sni_test']
    
    
    features_list = parse_features_2(gen_new_fields_list(fields_list))
    print(features_list)
    # write to file or print lists
    return 0

if __name__ == '__main__':
    gen_five_tuple("example")