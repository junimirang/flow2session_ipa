import os

import pandas as pd
import math
import statistics as stat
import datetime
from multiprocessing import Pool

# import numpy as np

def assemble(df_syn, df, file_name):
    except_rows = []
    n = 0
    df_length = len(df)
    df_syn_length = len(df_syn)
    while n < df_syn_length:
        # if n == 2:
        #     print("hello")
        print("This Counts:", n, "/", df_syn_length)
        stop_bit = 0
        # fin_point = 0
        num_packet = 0
        # interval = 0.0
        interval_avg = 0.0
        # interval_variance = 0.0
        interval_total = []
        send_byte = df_syn["Send Byte"][n]
        receive_byte = df_syn["Receive Byte"][n]
        start_point = df_syn["Packet_num"][n]
        start_time = df_syn["Time"][n]
        end_time = start_time

        ## asseble for문 시작
        for i in range(start_point, df_length):
            check_time = df["Time"][i]

            ## 비정상 통신 종료 확인 ##
            if ((stop_bit == 1) and (check_time > (end_time + 60))): ## FIN에 대한 ACK이 없을 경우 종료
                break
            if ((check_time > (start_point + 60)) and (num_packet == 0)):  ## SYN 이후 SYN, ACK  없는 경우 종료
                break
            if (check_time > (end_time + 150)): ## end time 이후 300초 이상 추가 패킷이 없는 경우 종료
                print("No response for", n)
                break

            if ((df_syn["Destination_ip_port"][n] == df["Destination_ip_port"][i]) and (
                    df_syn["Source_ip_port"][n] == df["Source_ip_port"][i])):
                send_byte += df["Length"][i]
                if (num_packet != 0):
                    interval = df["Time"][i] - end_time
                    interval_avg = (interval_avg*num_packet + interval)/num_packet
                    interval_total.append(interval)
                end_time = df["Time"][i]
                num_packet += 1
                if (stop_bit == 1): # FIN 후에 ACK 이 날라오면 종료
                    break
                if ("FIN") in df["Info"][i]:
                    stop_bit = 1

            elif ((df_syn["Destination_ip_port"][n] == df["Source_ip_port"][i]) and (
                    df_syn["Source_ip_port"][n] == df["Destination_ip_port"][i])):
                receive_byte += df["Length"][i]
                if (num_packet != 0):
                    interval = df["Time"][i]-end_time
                    interval_avg = (interval_avg*num_packet + interval)/num_packet
                    interval_total.append(interval)
                end_time = df["Time"][i]
                num_packet += 1
                if stop_bit == 1: # FIN 후에 ACK 이 날라오면 종료
                    break
                if ("FIN") in df["Info"][i]:
                    stop_bit = 1
                    # fin_point = i

        ## asseble for문 종료


        duration = end_time - start_time
        df_syn["Send Byte"][n] = send_byte
        df_syn["Receive Byte"][n] = receive_byte
        df_syn["Duration"][n] = duration
        df_syn["Packet Interval"][n] = interval_avg
        if (len(interval_total) > 0):
            df_syn["Interval Variance"][n] = stat.pvariance(interval_total)
        df_syn["Packet Counts"][n] = num_packet
        n+=1

    df_syn.to_csv(file_name+"_after_assemble.csv")

    return df_syn


def dns_check(df_syn, df_dns):
    syn_length = len(df_syn)
    dns_length = len(df_dns)
    for n in range(syn_length):
        # print(day," of", week," : ", n,"/",syn_length)
        for i in range(dns_length):
            if (df_syn["Time"][n] < df_dns["Time"][i] + 300):
                if (df_syn["Source"][n] == df_dns["Destination"][i]) and (df_syn["Destination"][n] in df_dns["Info"][i]):
                    df_syn["no_url"][n] = 0
                    break
                if (df_syn["Time"][n] < df_dns["Time"][i]):
                    break
    return df_syn

def data_read(file_name):
    # Original Column information : "No.","Time","Source","Destination","Protocol","Length","Source Port","Destination Port","Info"
    df = pd.read_csv(file_name)
    idx_not_tcp = df[df["Protocol"] != "TCP"].index
    df = df.drop(idx_not_tcp)
    df = df.dropna(axis=0)  ## 결측행 삭제

    ## DNS 데이터 필터링 ##
    df_dns = df[(df["Protocol"] == "DNS")]
    df_dns = df_dns.reset_index()  ## 인덱스 초기
    del df_dns["index"]

    ## TCP Filtering ##
    df = df[(df["Protocol"] == "TCP") | (df["Protocol"] == "SMTP") | (df["Protocol"] == "SMTP/IMF") | (
                df["Protocol"] == "HTTP") | (df["Protocol"] == "FTP") | (df["Protocol"] == "FTP-DATA") | (
                        df["Protocol"] == "TELNET") | (df["Protocol"] == "POP") | (df["Protocol"] == "SSHv1")]
    df = df.reset_index()  ## 인덱스 초기
    del df["index"], df["No."]

    ## Addtional feautres ##
    df["Source Port"] = df["Source Port"].astype('int')
    df["Destination Port"] = df["Destination Port"].astype('int')
    df["Source_ip_port"] = df["Source"] + ":" + df["Source Port"].map(str)
    df["Destination_ip_port"] = df["Destination"] + ":" + df["Destination Port"].map(str)
    df["Start Packet"] = 0
    df["no_url"] = 1
    df["Send Byte"] = 0
    df["Receive Byte"] = 0
    df["Duration"] = 0.0
    df["Packet Interval"] = 0.0
    df["Interval Variance"] = 0.0
    df["Packet_num"] = df.index
    df["Packet Counts"] = 0
    total_length = len(df)
    print("Total Length of",file_name, " : ", total_length)

    tcp_length = len(df)
    print("TCP Length of",file_name, " : ", tcp_length)

    ## Start(SYN) Packet Filtering ##
    syn_packet = df["Info"].str.contains("Seq=0 Win=")
    df["Start Packet"] = syn_packet
    not_syn_index = df[df["Start Packet"] == False].index
    df_syn = df.drop(not_syn_index)
    df_syn = df_syn.reset_index()
    del df_syn["index"]
    not_syn_packet = df_syn["Info"].str.contains("TCP") ## TCP Retransmission or TCP Out Of Order 삭제
    df_syn["Start Packet"] = not_syn_packet
    not_syn_index = df_syn[df_syn["Start Packet"] == True].index
    df_syn = df_syn.drop(not_syn_index)
    df_syn = df_syn.reset_index()
    del df_syn["index"]
    syn_length = len(df_syn)
    print("SYN Length ",file_name, " : ", syn_length)


    ## Session Assembling ##
    df_syn = assemble(df_syn, df, file_name)

    ## DNS Query Check ##
    df_syn = dns_check(df_syn, df_dns)

    df_syn["log_time_interval_mean"] = 0.0
    df_syn["log_time_interval_var"] = 0.0
    df_syn["log_time_taken"] = 0.0
    df_syn["log_cs_byte"] = 0.0
    df_syn["log_ratio_trans_receive"] = 0.0
    df_syn["log_count_connect_IP"] = 0.0
    df_syn["log_count_total_connect"] = 0.0
    idx_miss_receive = df_syn[df_syn["Receive Byte"] == 0.0].index
    df_syn = df_syn.drop(idx_miss_receive)
    df_syn = df_syn.reset_index()
    del df_syn["index"]
    df_syn["ratio_trans_receive"] = df_syn["Send Byte"] / df_syn["Receive Byte"]
    df_syn["log_avg_count_connect"] = 0.0
    df_syn["log_transmit_speed_BPS"] = 0.0
    df_syn["Business.time"] = 0
    df_syn["Business.time"] = df_syn["Business.time"].astype(int)
    df_syn["ratio_trans_receive"] = df_syn["Send Byte"] / df_syn["Receive Byte"]
    df_syn["LABEL"] = "non-ssh"
    df_syn["LABEL_original"] = "UNKNOWN"
    df_syn["count_total_connect"] = 0
    df_syn["count_connect_IP"] = 0

    idx_ftp = df_syn[df_syn["Destination Port"] == 21].index
    df_syn["LABEL_original"][idx_ftp] = "ftp"
    df_syn["LABEL"][idx_ftp] = "non-ssh"
    idx_ssh = df_syn[df_syn["Destination Port"] == 22].index
    df_syn["LABEL_original"][idx_ssh] = "ssh"
    df_syn["LABEL"][idx_ssh] = "ssh"
    idx_telnet = df_syn[df_syn["Destination Port"] == 23].index
    df_syn["LABEL_original"][idx_telnet] = "telnet"
    df_syn["LABEL"][idx_telnet] = "ssh"
    idx_smtp = df_syn[df_syn["Destination Port"] == 25].index
    df_syn["LABEL_original"][idx_smtp] = "smtp"
    df_syn["LABEL"][idx_smtp] = "non-ssh"
    idx_dns = df_syn[df_syn["Destination Port"] == 53].index
    df_syn["LABEL_original"][idx_dns] = "dns"
    df_syn["LABEL"][idx_dns] = "non-ssh"
    idx_HTTP = df_syn[df_syn["Destination Port"] == 80].index
    df_syn["LABEL_original"][idx_HTTP] = "web"
    df_syn["LABEL"][idx_HTTP] = "non-ssh"
    idx_ntp = df_syn[df_syn["Destination Port"] == 123].index
    df_syn["LABEL_original"][idx_ntp] = "ntp"
    df_syn["LABEL"][idx_ntp] = "non-ssh"
    idx_https = df_syn[df_syn["Destination Port"] == 443].index
    df_syn["LABEL_original"][idx_https] = "web"
    df_syn["LABEL"][idx_https] = "non-ssh"
    idx_rdp = df_syn[df_syn["Destination Port"] == 3389].index
    df_syn["LABEL_original"][idx_rdp] = "rdp"
    df_syn["LABEL"][idx_rdp] = "non-ssh"

    #df.to_csv("week2/session_output_without_ip_count.csv")
    df_syn = df_syn.dropna(axis=0)  ## 결측행 삭제
    return df_syn

def src_ip_count(df):
    ### 목적지,출발지 접속 카운트 ###
    # https://nittaku.tistory.com/131
    # https://rfriend.tistory.com/456
    count_ip = df.groupby([df["Destination"], df["Source"]]).count()
    count_ip = count_ip.reset_index().rename(columns={"Time": "Count"})
    count_ip = count_ip[["Destination", "Source", "Count"]]

    count_total_connect = count_ip.groupby("Destination")["Count"].sum()
    count_total_connect = count_total_connect.reset_index().rename(columns={"index": "Destination"})
    count_connect_ip = count_ip.groupby("Destination")["Source"].count()
    count_connect_ip = count_connect_ip.reset_index().rename(columns={"Source": "Count"})

    total_length = len(df["Info"])
    count_connect_ip_length = len(count_connect_ip["Count"])
    #count_total_connect_length = len(count_total_connect["Count"])

    for i in range(total_length):
        for j in range(count_connect_ip_length):
            if count_connect_ip["Destination"][j] == df["Destination"][i]:
                df["count_connect_IP"][i] = count_connect_ip["Count"][j]
                df["count_total_connect"][i] = count_total_connect["Count"][j]
                break

    df["avg_count_connect"] = df["count_total_connect"] / df["count_connect_IP"]
    df["transmit_speed_BPS"] = df["Send Byte"] / df["Duration"]

    df = df.dropna(axis=0)  ## 결측행 삭제

    df.to_csv("session_output_without_log_calculation.csv")

    idx_miss = df[df["Duration"] == 0.0].index
    df = df.drop(idx_miss)
    df = df.reset_index()  ## 행번호 추가
    total_length = len(df["Info"])

    for i in range(total_length):
        k1 = df["Duration"][i]
        k2 = df["Send Byte"][i]
        k3 = df["ratio_trans_receive"][i]
        k4 = df["count_connect_IP"][i]
        k5 = df["count_total_connect"][i]
        k6 = df["avg_count_connect"][i]
        k7 = df["transmit_speed_BPS"][i]
        k8 = df["Packet Interval"][i]
        k9 = df["Interval Variance"][i]

        df["log_time_taken"][i] = math.log10(k1 * 1000)  ## sec to msec
        df["log_cs_byte"][i] = math.log10(k2)
        df["log_ratio_trans_receive"][i] = math.log2(k3)
        df["log_count_connect_IP"][i] = math.log2(k4)
        df["log_count_total_connect"][i] = math.log2(k5)
        df["log_avg_count_connect"][i] = math.log10(k6)
        df["log_transmit_speed_BPS"][i] = math.log2(k7+1)
        df["log_time_interval_mean"][i] = math.log2(k8+1)
        df["log_time_interval_var"][i] = math.log2(k9+1)

        if (df["Time"][i] <= 11 * 3600):  ## 08:00 ~ 19:00
            df["Business.time"][i] = 1
    return df


def normalization(df): ## min, max cal
    df["log_time_taken"] = 100 * (df["log_time_taken"] - min(df["log_time_taken"])) / (
                max(df["log_time_taken"]) - min(df["log_time_taken"]))
    df["log_cs_byte"] = 100 * (df["log_cs_byte"] - min(df["log_cs_byte"])) / (
                max(df["log_cs_byte"]) - min(df["log_cs_byte"]))
    df["log_ratio_trans_receive"] = 100 * (df["log_ratio_trans_receive"] - min(df["log_ratio_trans_receive"])) / (
                max(df["log_ratio_trans_receive"]) - min(df["log_ratio_trans_receive"]))
    df["log_count_connect_IP"] = 100 * (df["log_count_connect_IP"] - min(df["log_count_connect_IP"])) / (
                max(df["log_count_connect_IP"]) - min(df["log_count_connect_IP"]))
    df["log_count_total_connect"] = 100 * (df["log_count_total_connect"] - min(df["log_count_total_connect"])) / (
                max(df["log_count_total_connect"]) - min(df["log_count_total_connect"]))
    df["log_avg_count_connect"] = 100 * (df["log_avg_count_connect"] - min(df["log_avg_count_connect"])) / (
                max(df["log_avg_count_connect"]) - min(df["log_avg_count_connect"]))
    df["log_transmit_speed_BPS"] = 100 * (df["log_transmit_speed_BPS"] - min(df["log_transmit_speed_BPS"])) / (
                max(df["log_transmit_speed_BPS"]) - min(df["log_transmit_speed_BPS"]))
    df["log_time_interval_mean"] = 100 * (df["log_time_interval_mean"] - min(df["log_time_interval_mean"])) / (
            max(df["log_time_interval_mean"]) - min(df["log_time_interval_mean"]))
    df["log_time_interval_var"] = 100 * (df["log_time_interval_var"] - min(df["log_time_interval_var"])) / (
            max(df["log_time_interval_var"]) - min(df["log_time_interval_var"]))

    return df


if __name__ == '__main__':
    # sys.stdout = open('flow2session_output.csv', 'w')       # Print as file #
    os.makedirs("output session", exist_ok=True)
    now = datetime.datetime.now()

    print("Start Time : ", now)

    with Pool(6) as p:
        directory1 = "week5/"  ## folder of meta data ##
        # filename1 = directory1+"mon.csv"
        # filename2 = directory1+"tue.csv"
        # filename3 = directory1+"wed.csv"
        # filename4 = directory1+"thu.csv"
        # filename5 = directory1+"fri.csv"
        #
        directory2 = directory1+"session output/" ## folder of session output ##
        # df1, df2, df3, df4, df5 = p.map(data_read, [filename1,filename2,filename3,filename4,filename5])
        #
        # df1.to_csv(directory2+"session_output_mon.csv")
        # df2.to_csv(directory2+"session_output_tue.csv")
        # df3.to_csv(directory2+"session_output_wed.csv")
        # df4.to_csv(directory2+"session_output_thu.csv")
        # df5.to_csv(directory2+"session_output_fri.csv")

        # data concate
        df1 = pd.read_csv(directory2+"session_output_mon.csv")
        df2 = pd.read_csv(directory2+"session_output_tue.csv")
        df3 = pd.read_csv(directory2+"session_output_wed.csv")
        df4 = pd.read_csv(directory2+"session_output_thu.csv")
        df5 = pd.read_csv(directory2+"session_output_fri.csv")
        df = pd.concat([df1, df2, df3, df4, df5], ignore_index=True)
        idx_not_valid = df[(df["Interval Variance"] == 0) | (df["Destination"] == "172.16.114.50")].index
        df = df.drop(idx_not_valid)
        df = df.reset_index()
        del df["index"]
        df = src_ip_count(df)
        df = normalization(df)
        df.to_csv(directory2+"session_output_concat_normalized.csv")
    #
    # with Pool(6) as p:
    #     directory1 = "week3/"  ## folder of meta data ##
    #     filename1 = directory1 + "mon.csv"
    #     filename2 = directory1 + "tue.csv"
    #     filename3 = directory1 + "wed.csv"
    #     filename4 = directory1 + "thu.csv"
    #     filename5 = directory1 + "fri.csv"
    #
        # directory2 = directory1 + "session output/"  ## folder of session output ##
    #     df1, df2, df3, df4, df5 = p.map(data_read, [filename1, filename2, filename3, filename4, filename5])
    #
    #     df1.to_csv(directory2 + "session_output_mon.csv")
    #     df2.to_csv(directory2 + "session_output_tue.csv")
    #     df3.to_csv(directory2 + "session_output_wed.csv")
    #     df4.to_csv(directory2 + "session_output_thu.csv")
    #     df5.to_csv(directory2 + "session_output_fri.csv")
    #
    #     # data concate
    #     df1 = pd.read_csv(directory2 + "session_output_mon.csv")
    #     df2 = pd.read_csv(directory2 + "session_output_tue.csv")
    #     df3 = pd.read_csv(directory2 + "session_output_wed.csv")
    #     df4 = pd.read_csv(directory2 + "session_output_thu.csv")
    #     df5 = pd.read_csv(directory2 + "session_output_fri.csv")
    #     df = pd.concat([df1, df2, df3, df4, df5], ignore_index=True)
    #     df = src_ip_count(df)
    #     df = normalization(df)
    #     df.to_csv(directory2 + "session_output_concat_normalized.csv")
    #
    # with Pool(6) as p:
    #     directory1 = "packet meta data/"  ## folder of meta data ##
    #     filename1 = directory1 + "mon.csv"
    #     filename2 = directory1 + "tue_filtered.csv"
    #     filename3 = directory1 + "wed.csv"
    #     filename4 = directory1 + "thu.csv"
    #     filename5 = directory1 + "fri.csv"
    #
        # directory2 = directory1 + "session output/"  ## folder of session output ##
    #     df1, df2, df3, df4, df5 = p.map(data_read, [filename1, filename2, filename3, filename4, filename5])




        # df1.to_csv(directory2 + "session_output_mon.csv")
        # df2.to_csv(directory2 + "session_output_tue.csv")
        # df3.to_csv(directory2 + "session_output_wed.csv")
        # df4.to_csv(directory2 + "session_output_thu.csv")
        # df5.to_csv(directory2 + "session_output_fri.csv")

        # # data concate
        # df1 = pd.read_csv(directory2 + "session_output_mon.csv")
        # df2 = pd.read_csv(directory2 + "session_output_tue.csv")
        # df3 = pd.read_csv(directory2 + "session_output_wed.csv")
        # df4 = pd.read_csv(directory2 + "session_output_thu.csv")
        # df5 = pd.read_csv(directory2 + "session_output_fri.csv")
        # df = pd.concat([df1, df2, df3, df4, df5], ignore_index=True)
        # df = src_ip_count(df)
        # df = normalization(df)
        # df.to_csv(directory2 + "session_output_concat_normalized.csv")


    print("End Time : ", now)
    # sys.stdout = sys.__stdout__  # End of stdout\
